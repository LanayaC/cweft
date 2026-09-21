"""
Prompt regression test: the published Vul4J prompts must not change.

Rebuilds every prompt in the published generation logs (42 vulns x 4 levels
x 3 cloud models = 504) with the current code and asserts each is identical,
character for character, to the prompt that was actually sent.

What comes from the log and what comes from the code:
  - the vulnerable file text and its path are read back out of the logged
    prompt (no Docker needed);
  - the CWE name comes from vuln_data.CWE_NAMES, and the L3a/L3b guidance
    from schemas.py, so a change to either is caught too.

It also pins the Java system prompt and markdown-fence regex in models.py,
which go out with every call but are not part of the logged prompt.

The logs live outside the repo (they go to Zenodo). Point at them with
CWEFT_GOLDEN_LOGS; the default is the sibling cweft_dataset checkout.

    python tests/test_prompt_regression.py
    python -m pytest tests/test_prompt_regression.py
"""

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import models  # noqa: E402
from prompts import build_prompt  # noqa: E402
from schemas import get_prose, get_schema  # noqa: E402
from vuln_data import CWE_NAMES  # noqa: E402


GOLDEN_LOGS = Path(os.environ.get(
    "CWEFT_GOLDEN_LOGS", PROJECT_ROOT.parent / "cweft_dataset" / "vul4j_logs"
))
EXPECTED_LOG_COUNT = 504

_BEGIN = "--- BEGIN FILE ---\n"
_END = "\n--- END FILE ---"

# Verbatim copies of what the 504 published cells were generated with.
JAVA_SYSTEM_PROMPT = (
    "You are a deterministic Java automated program repair tool. "
    "Return ONLY the complete modified Java source file with the security "
    "repair applied. Do NOT wrap the code in markdown fences such as "
    "```java. Do NOT add explanations, comments about your changes, or "
    "any text before or after the file. Your entire response must be "
    "valid Java source code that can be saved directly to a .java file "
    "and compiled."
)
JAVA_FENCE_PATTERN = r"^```(?:java|json|xml)?\s*\n?|\n?```\s*$"


def _file_from_prompt(prompt: str) -> str:
    start = prompt.index(_BEGIN) + len(_BEGIN)
    end = prompt.rindex(_END)
    return prompt[start:end]


def _rebuild(log: dict) -> str:
    cwe_id = log["cwe_id"]
    vuln_info = {
        "cwe_id":        cwe_id,
        "cwe_name":      CWE_NAMES[cwe_id],
        "repair_prose":  get_prose(cwe_id),
        "repair_schema": get_schema(cwe_id),
    }
    return build_prompt(
        level=log["level"],
        vuln_info=vuln_info,
        file_path=log["primary_file"],
        file_content=_file_from_prompt(log["prompt"]),
    )


def check_prompts() -> list:
    """Return a list of failure messages (empty means every prompt matches)."""
    if not GOLDEN_LOGS.is_dir():
        return [f"golden log directory not found: {GOLDEN_LOGS} (set CWEFT_GOLDEN_LOGS)"]

    paths = sorted(GOLDEN_LOGS.glob("*.json"))
    failures = []
    if len(paths) != EXPECTED_LOG_COUNT:
        failures.append(f"expected {EXPECTED_LOG_COUNT} logs in {GOLDEN_LOGS}, found {len(paths)}")

    for p in paths:
        log = json.loads(p.read_text(encoding="utf-8"))
        try:
            rebuilt = _rebuild(log)
        except Exception as e:
            failures.append(f"{p.name}: rebuild raised {type(e).__name__}: {e}")
            continue
        if rebuilt != log["prompt"]:
            i = next((k for k, (a, b) in enumerate(zip(rebuilt, log["prompt"])) if a != b),
                     min(len(rebuilt), len(log["prompt"])))
            failures.append(
                f"{p.name}: prompt differs at char {i}: "
                f"logged {log['prompt'][i:i + 60]!r} vs rebuilt {rebuilt[i:i + 60]!r}"
            )
    return failures


def check_models() -> list:
    failures = []
    if models.SYSTEM_PROMPT != JAVA_SYSTEM_PROMPT:
        failures.append("models.SYSTEM_PROMPT differs from the published Java system prompt")
    if models._FENCE_RE.pattern != JAVA_FENCE_PATTERN:
        failures.append("models._FENCE_RE differs from the published Java fence regex")

    # call_model's Java path, default and explicit, with a fake provider:
    # it must send the published system prompt and clean with _FENCE_RE.
    raw = "```java\npackage a;\nclass B {}\n```\n"
    seen = []

    def fake(prompt, system):
        seen.append(system)
        return raw, {"input_tokens": 0, "output_tokens": 0}

    original = models._DISPATCH["claude"]
    models._DISPATCH["claude"] = fake
    try:
        outs = [models.call_model("claude", "p")[0],
                models.call_model("claude", "p", language="Java")[0]]
    finally:
        models._DISPATCH["claude"] = original
    if any(s != JAVA_SYSTEM_PROMPT for s in seen):
        failures.append("call_model sends a different system prompt on the Java path")
    if any(o != models._FENCE_RE.sub("", raw).strip() for o in outs):
        failures.append("call_model cleans Java output differently from _FENCE_RE")
    return failures


def test_published_vul4j_prompts_unchanged():
    failures = check_prompts()
    assert not failures, "\n".join(failures[:20])


def test_java_system_prompt_and_fences_unchanged():
    failures = check_models()
    assert not failures, "\n".join(failures)


if __name__ == "__main__":
    failures = check_prompts() + check_models()
    if failures:
        print(f"FAIL: {len(failures)} problem(s)")
        for f in failures[:20]:
            print("  " + f)
        sys.exit(1)
    print(f"OK: all {EXPECTED_LOG_COUNT} published Vul4J prompts rebuild identically; "
          f"Java system prompt and fence regex unchanged.")
