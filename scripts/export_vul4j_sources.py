"""
Export the 42 Vul4J vulnerable source files, and the metadata a prompt needs,
from the vul4j-alldeps container into data/vul4j/, so prompts can be built on
a machine without that container.

For each vulnerability this writes the primary file's bytes, exactly as they
sit in the container checkout, to data/vul4j/sources/<VUL4J-N>/<file name>, and
records in data/vul4j/manifest.json what vuln_data would otherwise read from
the container: CVE, CWE and the PoV tests (the dataset CSV's failing_tests
column), the patched file path (vulnerability_info.json), plus the byte count
and SHA-256.

Before writing anything it checks, per file, that:
  * the bytes on disk equal the copy `vul4j checkout` staged (git show :path),
    so a patch left behind by evaluate.py cannot be exported; and
  * decoding those bytes the way vuln_data does gives exactly what the
    container path returns today, so prompts built from the export match.

    python scripts/export_vul4j_sources.py
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import vuln_data  # noqa: E402
from config import CONTAINER_NAME, SUBSET  # noqa: E402

OUT = PROJECT_ROOT / "data" / "vul4j"


def _docker_bytes(cmd):
    return subprocess.run(["docker", "exec", CONTAINER_NAME] + cmd,
                          check=True, capture_output=True).stdout


def main() -> int:
    image = subprocess.run(["docker", "inspect", "-f", "{{.Image}}", CONTAINER_NAME],
                           check=True, capture_output=True, text=True).stdout.strip()
    csv_rows = vuln_data._load_csv()
    entries, problems = [], []

    for vul_id in SUBSET:
        info = vuln_data.read_vulnerability_info(vul_id)
        paths = [e["file_path"] for e in info.get("human_patch", [])]
        if len(paths) != 1:
            problems.append(f"{vul_id}: {len(paths)} patched files")
            continue
        rel = paths[0]
        workdir = vuln_data.checkout_dir(vul_id)
        on_disk = _docker_bytes(["cat", f"{workdir}/{rel}"])
        staged = _docker_bytes(["git", "-C", workdir, "show", f":{rel}"])
        if on_disk != staged:
            problems.append(f"{vul_id}: {rel} differs from the staged copy")
            continue
        if vuln_data.decode_source(on_disk) != vuln_data.read_vulnerable_file(vul_id, rel):
            problems.append(f"{vul_id}: decoded export differs from the container read")
            continue

        source = f"sources/{vul_id}/{Path(rel).name}"
        row = csv_rows[vul_id]
        pov, pov_source = vuln_data.pov_tests(vul_id, row, info)
        entries.append({
            "vul_id":        vul_id,
            "cve_id":        row.get("cve_id", ""),
            "cwe_id":        row["cwe_id"].strip(),
            "primary_file":  rel,
            "file_paths":    paths,
            # The PoV tests: Vul4J's failing_tests column (see vuln_data.pov_tests).
            "failing_tests": pov,
            "failing_tests_source": pov_source,
            # What the test_cmd parser gave, which the published 504 were graded
            # with; kept so scripts/regrade_published_vul4j.py can tell what
            # the old grader treated as the PoV.
            "failing_tests_from_test_cmd": vuln_data._extract_failing_tests(info),
            "source":        source,
            "bytes":         len(on_disk),
            "sha256":        hashlib.sha256(on_disk).hexdigest(),
        })
        dest = OUT / source
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(on_disk)
        print(f"{vul_id:10s} {len(on_disk):8d} bytes  {rel}")

    if problems:
        print("\nNot exported:\n  " + "\n  ".join(problems))
        return 1
    manifest = {"container": CONTAINER_NAME, "image": image, "entries": entries}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                       encoding="utf-8", newline="\n")
    print(f"\n{len(entries)} files -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
