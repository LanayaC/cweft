"""
PatchEval payloads and prompts build from local files alone.

For all 109 entries in data/patcheval/manifest.json: the payload builds with
Docker made unreachable, the file text matches the frozen file, and all four
prompt levels build in the entry's language with no Java wording.

    python tests/test_patcheval_payloads.py
    python -m pytest tests/test_patcheval_payloads.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import vuln_data  # noqa: E402
from config import PROMPT_LEVELS  # noqa: E402
from prompts import build_prompt  # noqa: E402
from schemas import get_prose, get_schema  # noqa: E402

EXPECTED_ENTRIES = 109


def _no_docker(*args, **kwargs):
    raise AssertionError("PatchEval payloads must not touch Docker")


def check() -> list:
    failures = []
    ids = vuln_data.patcheval_ids()
    if len(ids) != EXPECTED_ENTRIES:
        failures.append(f"expected {EXPECTED_ENTRIES} PatchEval entries, found {len(ids)}")

    saved = vuln_data._docker_exec
    vuln_data._docker_exec = _no_docker
    try:
        for vul_id in ids:
            try:
                p = vuln_data.get_vuln_payload(vul_id)
                p["repair_prose"] = get_prose(p["cwe_id"])
                p["repair_schema"] = get_schema(p["cwe_id"])
                for level in PROMPT_LEVELS:
                    prompt = build_prompt(level, p, p["primary_file"], p["primary_content"],
                                          language=p["language"])
                    if not prompt.startswith(f"The following {p['language']} source file"):
                        failures.append(f"{vul_id} {level}: preamble is not {p['language']}")
                    if "Java file" in prompt or "Java source" in prompt:
                        failures.append(f"{vul_id} {level}: Java wording in prompt")
                    if p["primary_content"] not in prompt:
                        failures.append(f"{vul_id} {level}: file text missing from prompt")
            except Exception as e:
                failures.append(f"{vul_id}: {type(e).__name__}: {e}")
    finally:
        vuln_data._docker_exec = saved
    return failures


def check_tamper_detected() -> list:
    """A file whose bytes no longer match the manifest must be refused."""
    vul_id = vuln_data.patcheval_ids()[0]
    entry = vuln_data._patcheval_manifest()[vul_id]
    original = entry["sha256"]
    entry["sha256"] = "0" * 64
    try:
        vuln_data.read_patcheval_file(vul_id)
        return [f"{vul_id}: sha256 mismatch was not detected"]
    except RuntimeError:
        return []
    finally:
        entry["sha256"] = original


def test_patcheval_payloads_and_prompts_build_without_docker():
    failures = check()
    assert not failures, "\n".join(failures[:20])


def test_patcheval_tampered_file_refused():
    failures = check_tamper_detected()
    assert not failures, "\n".join(failures)


if __name__ == "__main__":
    failures = check() + check_tamper_detected()
    if failures:
        print(f"FAIL: {len(failures)} problem(s)")
        for f in failures[:20]:
            print("  " + f)
        sys.exit(1)
    print(f"OK: {EXPECTED_ENTRIES} PatchEval payloads and "
          f"{EXPECTED_ENTRIES * len(PROMPT_LEVELS)} prompts built without Docker.")
