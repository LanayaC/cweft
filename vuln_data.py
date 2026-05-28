"""
Vul4J integration layer (alldeps-compatible).

For each VUL4J-N in our subset, this module:
  1. Looks up CWE metadata from the Vul4J dataset CSV (inside the container)
  2. Ensures the vulnerability is checked out inside the alldeps container
  3. Reads vulnerability_info.json (failing tests, human_patch info, etc.)
  4. Reads the vulnerable Java file content from the project tree
  5. Returns a dict with everything `prompts.build_prompt` needs

We talk to the container via `docker exec` — no Python-side reimplementation
of vul4j logic.

NOTE: The vul4j CLI version baked into `bqcuongas/vul4j:alldeps` is older
than the modern repo version. It does NOT create VUL4J/vulnerable/ or
VUL4J/human_patch/ subdirectories. Instead, vulnerability_info.json
contains a `human_patch` array with file_path + content for each patched
file. The vulnerable version of those files lives at its natural project
path in the checkout tree.
"""

import csv
import json
import subprocess
from typing import Dict, List, Optional

from config import CONTAINER_NAME, CONTAINER_WORK_DIR, DOCKER_EXEC_TIMEOUT


# ──────────────────────────────────────────────────────────────────────
# CWE id → human-readable name
# Sourced from MITRE CWE definitions. Used only by L2/L3a/L3b prompts.
# Add more entries here if your subset adds new CWEs.
# ──────────────────────────────────────────────────────────────────────

CWE_NAMES: Dict[str, str] = {
    "CWE-19":  "Data Processing Errors",
    "CWE-20":  "Improper Input Validation",
    "CWE-22":  "Path Traversal",
    "CWE-74":  "Improper Neutralization of Special Elements in Output (Injection)",
    "CWE-77":  "Improper Neutralization of Special Elements Used in a Command (Command Injection)",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-254": "7PK - Security Features",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-310": "Cryptographic Issues",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    "CWE-835": "Loop with Unreachable Exit Condition (Infinite Loop)",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


# ──────────────────────────────────────────────────────────────────────
# Docker exec helpers
# ──────────────────────────────────────────────────────────────────────

def _docker_exec(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    full = ["docker", "exec", CONTAINER_NAME] + cmd
    return subprocess.run(
        full,
        check=check,
        capture_output=True,
        text=True,
        timeout=DOCKER_EXEC_TIMEOUT,
    )


def _docker_cat(path: str) -> str:
    return _docker_exec(["cat", path]).stdout


def _docker_path_exists(path: str) -> bool:
    return _docker_exec(["test", "-e", path], check=False).returncode == 0


# ──────────────────────────────────────────────────────────────────────
# Dataset CSV (cached after first read)
# ──────────────────────────────────────────────────────────────────────

_CSV_PATH_IN_CONTAINER = "/vul4j/dataset/vul4j_dataset.csv"
_csv_cache: Optional[Dict[str, Dict[str, str]]] = None


def _load_csv() -> Dict[str, Dict[str, str]]:
    global _csv_cache
    if _csv_cache is not None:
        return _csv_cache
    raw = _docker_cat(_CSV_PATH_IN_CONTAINER)
    reader = csv.DictReader(raw.splitlines())
    _csv_cache = {row["vul_id"]: row for row in reader}
    return _csv_cache


# ──────────────────────────────────────────────────────────────────────
# Checkout management
# ──────────────────────────────────────────────────────────────────────

def checkout_dir(vul_id: str) -> str:
    return f"{CONTAINER_WORK_DIR}/{vul_id}"


def ensure_checkout(vul_id: str, force: bool = False) -> str:
    """
    Make sure vul_id is checked out at /tmp/cweft/vul_id inside the container.
    Returns the in-container path. Use force=True to wipe and re-checkout.
    """
    target = checkout_dir(vul_id)

    if force and _docker_path_exists(target):
        _docker_exec(["rm", "-rf", target])

    if not _docker_path_exists(target):
        _docker_exec(["mkdir", "-p", CONTAINER_WORK_DIR])
        _docker_exec(["vul4j", "checkout", "--id", vul_id, "-d", target])

    return target


# ──────────────────────────────────────────────────────────────────────
# Vulnerability metadata (the JSON the checkout produces)
# ──────────────────────────────────────────────────────────────────────

def read_vulnerability_info(vul_id: str) -> Dict:
    """Parse VUL4J/vulnerability_info.json from inside the checkout."""
    ensure_checkout(vul_id)
    info_path = f"{checkout_dir(vul_id)}/VUL4J/vulnerability_info.json"
    return json.loads(_docker_cat(info_path))


def read_patched_file_paths(vul_id: str) -> List[str]:
    """
    Files the human patch modifies, relative to the project root.
    Sourced from vulnerability_info.json's `human_patch` array.
    """
    info = read_vulnerability_info(vul_id)
    return [entry["file_path"] for entry in info.get("human_patch", [])]


def read_vulnerable_file(vul_id: str, relative_path: str) -> str:
    """
    Read the *vulnerable* version of a Java file as a string.
    This reads from the natural project path, not a snapshot directory —
    the alldeps `vul4j checkout` leaves the project at the vulnerable revision.
    """
    ensure_checkout(vul_id)
    full = f"{checkout_dir(vul_id)}/{relative_path}"
    return _docker_cat(full)


def read_human_patched_content(vul_id: str, relative_path: str) -> str:
    """
    The human-written patched version of a file, from the JSON.
    Used for comparison / sanity checking, not for prompting the LLM.
    """
    info = read_vulnerability_info(vul_id)
    for entry in info.get("human_patch", []):
        if entry["file_path"] == relative_path:
            return entry["content"]
    raise KeyError(f"{relative_path} not found in {vul_id}'s human_patch")

def _extract_failing_tests(info: Dict) -> List[str]:
    """
    Get the PoV test names from vulnerability_info.json.

    The modern vul4j JSON has a top-level "failing_tests" array.
    The alldeps (older) JSON does not — instead, the test names are
    inside the `test_cmd` field as a comma-separated value to the
    `-Dtest=` Maven argument:

        "mvn test -Dtest=org.foo.Bar#m1,org.foo.Bar#m2"

    We accept either form so this layer remains forward-compatible.
    """
    # Modern form
    if "failing_tests" in info and info["failing_tests"]:
        return list(info["failing_tests"])

    # alldeps form: parse "-Dtest=..." out of test_cmd
    test_cmd = info.get("test_cmd", "")
    marker = "-Dtest="
    idx = test_cmd.find(marker)
    if idx == -1:
        return []
    after = test_cmd[idx + len(marker):]
    # The test list ends at the next whitespace (next Maven arg) or EOL
    test_list = after.split()[0] if after.split() else ""
    return [t.strip() for t in test_list.split(",") if t.strip()]
# ──────────────────────────────────────────────────────────────────────
# Convenience: bundle everything a prompt needs
# ──────────────────────────────────────────────────────────────────────

def get_vuln_payload(vul_id: str) -> Dict:
    """
    Bundle everything `prompts.build_prompt` could need for this vuln.

    Returns a dict with:
        vul_id, cve_id, cwe_id, cwe_name,
        failing_tests, file_paths, primary_file, primary_content

    Raises RuntimeError if:
      - the vuln has no CWE label (cwe_id == "Not Mapping" or empty), or
      - the vuln touches more than one file (single-file subset enforcement).
    """
    csv_row = _load_csv()[vul_id]

    cwe_id = csv_row["cwe_id"].strip()
    if cwe_id in ("", "Not Mapping"):
        raise RuntimeError(f"{vul_id} has no usable CWE label (csv value: {cwe_id!r})")

    cwe_name = CWE_NAMES.get(cwe_id)
    if cwe_name is None:
        raise RuntimeError(
            f"{vul_id} has CWE {cwe_id!r}, which is not in CWE_NAMES. "
            f"Add it to vuln_data.CWE_NAMES."
        )

    info = read_vulnerability_info(vul_id)

    paths = [entry["file_path"] for entry in info.get("human_patch", [])]
    if len(paths) != 1:
        raise RuntimeError(
            f"{vul_id} touches {len(paths)} files; single-file subset only. Paths: {paths}"
        )

    primary_file = paths[0]
    primary_content = read_vulnerable_file(vul_id, primary_file)

    return {
        "vul_id":          vul_id,
        "cve_id":          csv_row.get("cve_id", ""),
        "cwe_id":          cwe_id,
        "cwe_name":        cwe_name,
        "failing_tests":   _extract_failing_tests(info),
        "file_paths":      paths,
        "primary_file":    primary_file,
        "primary_content": primary_content,
    }


# ──────────────────────────────────────────────────────────────────────
# Smoke test
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_id = "VUL4J-10"
    print(f"Fetching payload for {test_id}...\n")

    payload = get_vuln_payload(test_id)

    print(f"vul_id:         {payload['vul_id']}")
    print(f"cve_id:         {payload['cve_id']}")
    print(f"cwe_id:         {payload['cwe_id']}")
    print(f"cwe_name:       {payload['cwe_name']!r}")
    print(f"failing_tests:  {payload['failing_tests']}")
    print(f"file_paths:     {payload['file_paths']}")
    print(f"primary_file:   {payload['primary_file']}")
    print(f"file length:    {len(payload['primary_content'])} chars")
    print()
    print("First 400 chars of the vulnerable file:")
    print("-" * 60)
    print(payload["primary_content"][:400])