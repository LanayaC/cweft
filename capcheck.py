"""
Pre-flight check: which cells are likely to be truncated at the output cap.

The task asks for the whole patched file back, so required output scales with
the file. A cell whose file needs more tokens than its model's cap is a cell
whose L0 is decided before the model sees it. This estimates that need from the
source file and compares it with the configured cap, without calling any API.

How the estimate is made, and why it leans high:

  * When the file's token count is already known it is used directly. The
    PatchEval manifest carries one per file (cl100k), scaled by TOKENIZER_RATIO
    because a provider's own tokenizer counts the same code differently: over
    the 42 Vul4J files, Claude counted 1.21x what GPT did and Gemini 1.12x.
  * Otherwise tokens are estimated from characters at the *median* ratio each
    provider produced over those 42 files (claude 3.29, gpt 4.10, gemini 3.57),
    divided by CHAR_SAFETY because density varies by file: the densest Java file
    observed ran at 2.36 chars per token against a median of 3.29.
  * The patched file is usually a little longer than the original, so the
    estimate is multiplied by PATCH_GROWTH. On Gemini, whose 32,768 cap never
    truncated, output ran between 0.63x and 1.17x the prompt tokens.
  * GPT's max_completion_tokens covers reasoning tokens as well as the visible
    file, so GPT_REASONING_RESERVE of its budget is treated as unavailable.
    This is an assumption, not a measurement: reasoning_tokens only started
    being recorded with the truncation work, so there is no history to fit yet.
  * The local models have no output cap. Their OLLAMA_NUM_CTX window holds the
    prompt and the generated file together, so both are counted against it.

An estimate is not a promise: it says which cells to look at, and the recorded
stop_reason says what actually happened.
"""

import math
from typing import Dict, List, NamedTuple, Optional

from config import LOCAL_MODELS, OLLAMA_NUM_CTX
from models import OUTPUT_CAPS

# Median chars-per-token per provider over the 42 published Vul4J files.
# "ollama" covers every local model; no local run is published, so it borrows
# Gemini's, the middle of the three.
CHARS_PER_TOKEN: Dict[str, float] = {
    "claude": 3.29,
    "gpt":    4.10,
    "gemini": 3.57,
    "ollama": 3.57,
}

# What each provider's tokenizer counts, relative to a cl100k count of the same
# file. Derived from the per-file prompt tokens of the published run.
TOKENIZER_RATIO: Dict[str, float] = {
    "claude": 1.21,
    "gpt":    1.00,          # cl100k is GPT's own family
    "gemini": 1.12,
    "ollama": 1.12,
}

CHAR_SAFETY = 1.30          # per-file density varies: 2.36 against a 3.29 median.
                            # At 1.30 the estimate clears the actual token count of
                            # every one of the 42 published files, on all three
                            # providers (tests/test_capcheck.py pins this).
PATCH_GROWTH = 1.10          # a patch adds lines; Gemini's output reached 1.17x
GPT_REASONING_RESERVE = 2048  # assumed, see the module docstring
TIGHT_FRACTION = 0.80        # "tight" once the estimate passes this much of the budget
LOCAL_TIGHT_FRACTION = 0.90

OVER, TIGHT, OK = "over", "tight", "ok"


class CellRisk(NamedTuple):
    vul_id: str
    level: str
    model_key: str
    verdict: str              # OVER | TIGHT | OK
    output_estimate: int      # tokens the file is expected to need
    budget: int               # tokens actually available for the file
    detail: str               # how the budget was arrived at

    @property
    def at_risk(self) -> bool:
        return self.verdict in (OVER, TIGHT)


def provider_of(model_key: str) -> str:
    return "ollama" if model_key in LOCAL_MODELS else model_key


def estimate_tokens(model_key: str, chars: int = 0, known_tokens: int = 0) -> int:
    """
    Tokens this model is expected to count for a file.

    A known count (the PatchEval manifest's cl100k figure) is scaled to the
    provider's own tokenizer; otherwise characters are converted at the
    provider's median ratio with CHAR_SAFETY applied.
    """
    provider = provider_of(model_key)
    if known_tokens:
        return math.ceil(known_tokens * TOKENIZER_RATIO.get(provider, 1.12))
    ratio = CHARS_PER_TOKEN.get(provider, 3.57) / CHAR_SAFETY
    return math.ceil(chars / ratio)


def estimate_output_tokens(model_key: str, file_chars: int = 0,
                           known_tokens: int = 0) -> int:
    """Tokens the model must emit to return the whole patched file."""
    return math.ceil(estimate_tokens(model_key, file_chars, known_tokens) * PATCH_GROWTH)


def budget_for(model_key: str, prompt_chars: int = 0,
               reasoning_reserve: int = GPT_REASONING_RESERVE) -> tuple:
    """
    (tokens available for the file, how that was arrived at).

    Cloud models get their configured cap, less any reserve. Local models get
    whatever their shared window has left once the prompt is in it.
    """
    if model_key in LOCAL_MODELS:
        prompt_tokens = estimate_tokens(model_key, prompt_chars)
        return (OLLAMA_NUM_CTX - prompt_tokens,
                f"num_ctx {OLLAMA_NUM_CTX} shared, prompt ~{prompt_tokens}")
    cap = OUTPUT_CAPS[model_key]
    if model_key == "gpt":
        return cap - reasoning_reserve, f"cap {cap} less {reasoning_reserve} for reasoning"
    return cap, f"cap {cap}"


def check_cell(vul_id: str, level: str, model_key: str, file_chars: int = 0,
               prompt_chars: int = 0,
               reasoning_reserve: int = GPT_REASONING_RESERVE,
               known_tokens: int = 0) -> CellRisk:
    need = estimate_output_tokens(model_key, file_chars, known_tokens)
    budget, detail = budget_for(model_key, prompt_chars, reasoning_reserve)
    tight = LOCAL_TIGHT_FRACTION if model_key in LOCAL_MODELS else TIGHT_FRACTION
    if budget <= 0 or need > budget:
        verdict = OVER
    elif need > budget * tight:
        verdict = TIGHT
    else:
        verdict = OK
    return CellRisk(vul_id, level, model_key, verdict, need, budget, detail)


def check_cells(cells, file_chars: Dict[str, int] = None,
                prompt_chars: Dict[tuple, int] = None,
                reasoning_reserve: int = GPT_REASONING_RESERVE,
                file_tokens: Dict[str, int] = None) -> List[CellRisk]:
    """
    Check an iterable of (vul_id, level, model_key).

    `file_chars` maps vul_id -> source file length and `file_tokens` maps
    vul_id -> a known token count, which is preferred where present. A vul_id in
    neither is skipped: its size is unknown, and guessing would defeat the point.
    """
    file_chars = file_chars or {}
    prompt_chars, file_tokens = prompt_chars or {}, file_tokens or {}
    out = []
    for vul_id, level, model_key in cells:
        if vul_id not in file_chars and vul_id not in file_tokens:
            continue
        chars = file_chars.get(vul_id, 0)
        out.append(check_cell(
            vul_id, level, model_key, chars,
            prompt_chars.get((vul_id, level, model_key), chars),
            reasoning_reserve, file_tokens.get(vul_id, 0)))
    return out


def summary_line(risks: List[CellRisk], total_cells: int, unknown: int = 0) -> str:
    """The one line a normal run prints before it starts."""
    over = [r for r in risks if r.verdict == OVER]
    tight = [r for r in risks if r.verdict == TIGHT]
    if not over and not tight:
        checked = len(risks)
        tail = f", {unknown} unknown" if unknown else ""
        return f"Cap check: no truncation risk in {checked} of {total_cells} cells{tail}."
    def by_model(rows):
        counts: Dict[str, int] = {}
        for r in rows:
            counts[r.model_key] = counts.get(r.model_key, 0) + 1
        return ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
    parts = []
    if over:
        parts.append(f"{len(over)} over cap ({by_model(over)})")
    if tight:
        parts.append(f"{len(tight)} tight ({by_model(tight)})")
    tail = f"; {unknown} of unknown size" if unknown else ""
    return (f"Cap check: {'; '.join(parts)} of {total_cells} cells{tail}. "
            f"Those will score L0 for truncation. Run --check-caps for the list.")


def report(risks: List[CellRisk], total_cells: int, unknown: Optional[list] = None) -> str:
    """The detailed report --check-caps prints."""
    lines = [summary_line(risks, total_cells, len(unknown or []))]
    flagged = [r for r in risks if r.at_risk]
    if flagged:
        lines.append("")
        lines.append(f"{'vuln':<18}{'level':<6}{'model':<12}{'verdict':<8}"
                     f"{'needs':>8}{'budget':>8}  how the budget was set")
        for r in sorted(flagged, key=lambda r: (-r.output_estimate, r.vul_id,
                                                r.model_key, r.level)):
            lines.append(f"{r.vul_id:<18}{r.level:<6}{r.model_key:<12}{r.verdict:<8}"
                         f"{r.output_estimate:>8}{r.budget:>8}  {r.detail}")
        worst = max(flagged, key=lambda r: r.output_estimate)
        lines.append("")
        lines.append(f"Largest need: {worst.vul_id} at ~{worst.output_estimate} tokens "
                     f"on {worst.model_key}.")
    if unknown:
        lines.append("")
        lines.append(f"Size unknown, not checked ({len(unknown)}): "
                     f"{', '.join(sorted(set(unknown))[:12])}"
                     f"{' ...' if len(set(unknown)) > 12 else ''}")
    return "\n".join(lines)
