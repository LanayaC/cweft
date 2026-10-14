"""
Pre-flight check: which cells are likely to be truncated at the output cap.

The task asks for the whole patched file back, so required output scales with
the file. A cell whose file needs more tokens than its model's cap is a cell
whose L0 is decided before the model sees it. This estimates that need from the
source file and compares it with the configured cap, without calling any API.

How the estimate is made, and why it leans high:

The estimate is a bracket, not a number, because token density varies by file:
over the 42 published Vul4J files one Java file ran at 2.36 characters per token
and another at 3.86. A single ratio is therefore either too loose to be safe or
too tight to be useful - a median ratio called VUL4J-78 "over cap" on Gemini,
which in the published run emitted 28,283 tokens against a 32,768 cap and did
not truncate.

  * From characters: the optimistic bound uses the *highest* chars-per-token
    ratio the provider was observed to produce (fewest tokens) and the
    pessimistic bound the *lowest* (most tokens).
  * From a known token count - the PatchEval manifest's cl100k figure - the
    bracket is the range by which a provider's own tokenizer differs from
    cl100k over those same files.
  * Both bounds are multiplied by PATCH_GROWTH, since a patch adds lines. On
    Gemini output ran between 0.63x and 1.17x the prompt tokens.

The verdict says which bound decided it: `over` when even the optimistic bound
does not fit, `tight` when only the pessimistic one does not. `tight` means it
might truncate, and the recorded stop_reason is what settles it.
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

# (densest, sparsest) chars-per-token observed per provider over the 42
# published Vul4J files. The sparsest gives the optimistic token count, the
# densest the pessimistic one. "ollama" covers every local model; no local run
# is published, so it borrows Gemini's, the middle of the three.
CHARS_PER_TOKEN_RANGE: Dict[str, tuple] = {
    "claude": (2.36, 3.86),
    "gpt":    (2.95, 5.67),
    "gemini": (2.54, 4.60),
    "ollama": (2.54, 4.60),
}

# (low, high) multiple of a cl100k count that a provider's own tokenizer
# produces for the same file, from the per-file prompt tokens of the published
# run (Claude counted about 1.21x what GPT did on average, Gemini 1.12x).
TOKENIZER_RATIO_RANGE: Dict[str, tuple] = {
    "claude": (1.15, 1.30),
    "gpt":    (1.00, 1.05),  # cl100k is GPT's own family
    "gemini": (1.08, 1.20),
    "ollama": (1.08, 1.20),
}

PATCH_GROWTH = 1.10          # a patch adds lines; Gemini's output reached 1.17x
GPT_REASONING_RESERVE = 2048  # assumed, see the module docstring
OVER, TIGHT, OK = "over", "tight", "ok"


class CellRisk(NamedTuple):
    vul_id: str
    level: str
    model_key: str
    verdict: str              # OVER | TIGHT | OK
    output_low: int           # optimistic tokens the file needs
    output_high: int          # pessimistic tokens the file needs
    budget: int               # tokens actually available for the file
    detail: str               # how the budget was arrived at

    @property
    def at_risk(self) -> bool:
        return self.verdict in (OVER, TIGHT)

    @property
    def needs(self) -> str:
        return f"{self.output_low}-{self.output_high}"


def provider_of(model_key: str) -> str:
    return "ollama" if model_key in LOCAL_MODELS else model_key


def estimate_tokens(model_key: str, chars: int = 0, known_tokens: int = 0) -> tuple:
    """
    (optimistic, pessimistic) tokens this model is expected to count for a file.

    A known count (the PatchEval manifest's cl100k figure) is scaled by the
    range its tokenizer differs by; otherwise characters are converted at the
    sparsest and densest ratios the provider was observed to produce.
    """
    provider = provider_of(model_key)
    if known_tokens:
        low, high = TOKENIZER_RATIO_RANGE.get(provider, (1.08, 1.20))
        return math.ceil(known_tokens * low), math.ceil(known_tokens * high)
    densest, sparsest = CHARS_PER_TOKEN_RANGE.get(provider, (2.54, 4.60))
    return math.ceil(chars / sparsest), math.ceil(chars / densest)


def estimate_output_tokens(model_key: str, file_chars: int = 0,
                           known_tokens: int = 0) -> tuple:
    """(optimistic, pessimistic) tokens needed to return the whole patched file."""
    low, high = estimate_tokens(model_key, file_chars, known_tokens)
    return math.ceil(low * PATCH_GROWTH), math.ceil(high * PATCH_GROWTH)


def budget_for(model_key: str, prompt_chars: int = 0,
               reasoning_reserve: int = GPT_REASONING_RESERVE) -> tuple:
    """
    (tokens available for the file, how that was arrived at).

    Cloud models get their configured cap, less any reserve. Local models get
    whatever their shared window has left once the prompt is in it.
    """
    if model_key in LOCAL_MODELS:
        # The pessimistic prompt count: a bigger prompt leaves less room, so
        # assuming the smaller one would overstate what is left for the file.
        _, prompt_tokens = estimate_tokens(model_key, prompt_chars)
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
    low, high = estimate_output_tokens(model_key, file_chars, known_tokens)
    budget, detail = budget_for(model_key, prompt_chars, reasoning_reserve)
    if budget <= 0 or low > budget:
        verdict = OVER          # it does not fit even optimistically
    elif high > budget:
        verdict = TIGHT         # it might not fit
    else:
        verdict = OK
    return CellRisk(vul_id, level, model_key, verdict, low, high, budget, detail)


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
            f"Truncation there would score L0 for the cap, not the patch. "
            f"Run --check-caps for the list.")


def report(risks: List[CellRisk], total_cells: int, unknown: Optional[list] = None) -> str:
    """The detailed report --check-caps prints."""
    lines = [summary_line(risks, total_cells, len(unknown or []))]
    flagged = [r for r in risks if r.at_risk]
    if flagged:
        lines.append("")
        lines.append(f"{'vuln':<18}{'level':<6}{'model':<12}{'verdict':<8}"
                     f"{'needs':>16}{'budget':>8}  how the budget was set")
        for r in sorted(flagged, key=lambda r: (-r.output_low, r.vul_id,
                                                r.model_key, r.level)):
            lines.append(f"{r.vul_id:<18}{r.level:<6}{r.model_key:<12}{r.verdict:<8}"
                         f"{r.needs:>16}{r.budget:>8}  {r.detail}")
        worst = max(flagged, key=lambda r: r.output_low)
        lines.append("")
        lines.append(f"Largest need: {worst.vul_id} at ~{worst.needs} tokens "
                     f"on {worst.model_key}.")
        lines.append("`over` does not fit even optimistically; `tight` might not fit. "
                     "The recorded stop_reason settles it.")
    if unknown:
        lines.append("")
        lines.append(f"Size unknown, not checked ({len(unknown)}): "
                     f"{', '.join(sorted(set(unknown))[:12])}"
                     f"{' ...' if len(set(unknown)) > 12 else ''}")
    return "\n".join(lines)
