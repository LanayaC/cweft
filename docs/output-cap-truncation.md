# Output-cap truncation in the published 504 Vul4J cells

**Finding:** 70 of the 504 published cells were cut off by the output token cap, and
every one of them scored L0. That is 61% of the 115 published L0s. They are not failed
repairs — the model was stopped mid-file, and a half-written Java file cannot compile,
which is exactly what L0 records.

Analysis date: 2026-10-14. Nothing in the pipeline has been changed on the strength of
it; the cap decision is still open. This note is the evidence for that decision.

## The caps the published run used

The three cloud models did **not** share a cap:

| model | cap at publication | where |
|---|---|---|
| `claude-sonnet-4-5-20250929` | `max_tokens=8192` | `models.py` `_call_claude` |
| `gpt-5` | `max_completion_tokens=8192` | `models.py` `_call_gpt` |
| `gemini-2.5-pro` | `max_output_tokens=32768` | `models.py` `_call_gemini` |
| Ollama locals | no output cap; `num_ctx=40960` shared by prompt and output | `config.py` |

Gemini ran with four times the budget of the other two. That asymmetry is what makes the
truncation measurable: Gemini is an uncapped control for the same 42 files.

## Evidence

Every cell whose `usage.output_tokens` equals its cap was truncated, because a model
cannot emit more than its cap. Joining those cells to `results/published/results.csv`:

- **claude: 29 cells at 8192**, across 8 vulnerabilities —
  VUL4J-7, 14, 22, 36, 52, 59, 78, 79.
  All four prompt levels truncated for VUL4J-7, 14, 36, 52, 59, 78, 79.
- **gpt: 41 cells at 8192**, across 14 vulnerabilities —
  VUL4J-2, 6, 7, 14, 22, 33, 36, 47, 52, 55, 59, 62, 78, 79.
  All four levels truncated for VUL4J-2, 7, 14, 36, 52, 59, 78, 79.
- **All 70 of those cells have `trust_level == L0`.**
- Published distribution for context: L0 115, L1 275, L2 31, L3 83 (504 total).

GPT-5 fares worst because `max_completion_tokens` covers reasoning tokens as well as
visible output, so the whole 8192 could be consumed before any file text was emitted.

## Gemini as the control: how much output the files really need

Gemini, at 32,768, was never truncated — its maximum was **28,283** output tokens
(VUL4J-78 / L3a), and **24 of its 168 cells exceeded 8192**. Those 24 cells are direct
evidence that a 8192 cap could not have held the file, whichever model was asked.

Largest observed outputs: VUL4J-78/L3a 28,283, VUL4J-78/L2 28,212, VUL4J-79/L3b 27,827,
VUL4J-79/L2 27,777.

## File sizes behind this

The task asks the model to return the complete patched file, so required output scales
with file size.

| | largest file | size |
|---|---|---|
| Vul4J (42) | VUL4J-78 | 111,641 chars — 30,685 Claude prompt tokens at L1 |
| Vul4J (42) | VUL4J-79 | 97,689 chars — 29,825 Claude prompt tokens at L1 |
| PatchEval (109) | CVE-2020-7613 `index.js` | 16,707 tokens (cl100k, from the manifest) |

The Java files are roughly twice the size of the largest PatchEval file. 11 of the 109
PatchEval files exceed 8192 tokens, so the same truncation would affect them under the
published cap — but the larger problem is already in the Java results.

## Consequences

1. **The published L0 rate overstates repair failure.** 70 of 115 L0s are a harness
   limit. Any per-model comparison is also skewed: Claude and GPT were capped at 8192
   while Gemini had 32,768, so part of Gemini's advantage on large files is budget, not
   capability.
2. **A cap change makes re-runs incomparable cell-for-cell** with the published numbers.
   `generate.py` skips cells whose log records `status == "ok"`, so raising the cap
   regenerates nothing by itself; the published logs and results stay as they are until
   those cells are deliberately re-run.
3. **Prompts are unaffected** either way: no cap value appears in any prompt, and
   `tests/test_prompt_regression.py` pins the prompt text, the Java system prompt and the
   fence regex, none of which involve `max_tokens`.
4. **Model ceilings, if the cap is raised** (vendor docs, 2026-10-14): Sonnet 4.5 64K
   (deprecated, retires 2026-11-30), GPT-5 128,000, Gemini 2.5 Pro 65,536. The largest
   value common to all three is 64K. The local models cannot take part in a large output
   cap at all: their 40,960 window holds prompt and output together, and VUL4J-79 alone
   needs about 55,000 tokens for both.

## Reproducing this

```python
# counts the truncated cells and joins them to the published trust levels
import csv, json, collections
from pathlib import Path

logs = Path("logs/published")   # the 504 published per-call logs
truncated = set()
for p in logs.glob("*.json"):
    log = json.loads(p.read_text(encoding="utf-8"))
    if log.get("status") == "ok" and log["model_key"] in ("claude", "gpt") \
            and log["usage"]["output_tokens"] >= 8192:
        truncated.add((log["vul_id"], log["level"], log["model_key"]))

rows = list(csv.DictReader(Path("results/published/results.csv").open()))
print(len(truncated), collections.Counter(
    r["trust_level"] for r in rows
    if (r["vul_id"], r["level"], r["model_key"]) in truncated))
```

`logs/published/` holds the 504 published per-call logs and
`results/published/results.csv` the 504 published outcomes.
