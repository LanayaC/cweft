"""
The pre-flight output-cap check.

Two things matter. The estimate must not fall short — an estimate below the real
token count would clear a cell that then truncates — and the budget must be the
one the request will actually have: GPT's reasoning shares its cap, and a local
model's window holds the prompt and the file together.

The calibration test measures the estimator against the 42 published Vul4J
files, whose real token counts the archived logs record for all three providers.
It skips when that archive is not present (see DATA_AVAILABILITY.md).
"""

import json
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import capcheck  # noqa: E402
import generate  # noqa: E402
from config import OLLAMA_NUM_CTX  # noqa: E402
from models import OUTPUT_CAPS  # noqa: E402

GOLDEN_LOGS = Path(os.environ.get(
    "CWEFT_GOLDEN_LOGS", PROJECT_ROOT.parent / "cweft_dataset" / "vul4j_logs"))
BEGIN, END = "--- BEGIN FILE ---\n", "\n--- END FILE ---"


# ── the estimate ─────────────────────────────────────────────────────────

def test_a_known_token_count_is_preferred_and_scaled_per_provider():
    # cl100k is GPT's own family, so GPT scales by 1.0 and Claude by more.
    gpt = capcheck.estimate_output_tokens("gpt", known_tokens=10_000)
    claude = capcheck.estimate_output_tokens("claude", known_tokens=10_000)
    gemini = capcheck.estimate_output_tokens("gemini", known_tokens=10_000)
    assert gpt == 11_000                      # 10k x 1.00 x 1.10 growth
    assert claude > gemini > gpt


def test_the_character_path_is_used_when_no_count_is_known():
    assert capcheck.estimate_output_tokens("claude", file_chars=40_000) > 0
    # More characters can never mean fewer tokens.
    smaller = capcheck.estimate_output_tokens("claude", file_chars=10_000)
    bigger = capcheck.estimate_output_tokens("claude", file_chars=20_000)
    assert bigger > smaller


def test_the_estimate_includes_room_for_the_patch_to_grow():
    bare = capcheck.estimate_tokens("gpt", known_tokens=10_000)
    with_growth = capcheck.estimate_output_tokens("gpt", known_tokens=10_000)
    assert with_growth > bare


@pytest.mark.skipif(not GOLDEN_LOGS.is_dir(), reason="archived logs not available")
def test_the_estimate_never_falls_short_on_the_published_files():
    """
    For every published file and provider, the estimated output need must be at
    least the provider's own count of that file. Under-estimating is the one
    failure mode that matters: it clears a cell that then truncates.
    """
    short = []
    for path in sorted(GOLDEN_LOGS.glob("*__L1__*.json")):
        log = json.loads(path.read_text(encoding="utf-8"))
        if log.get("status") != "ok":
            continue
        prompt = log["prompt"]
        chars = len(prompt[prompt.index(BEGIN) + len(BEGIN):prompt.rindex(END)])
        estimate = capcheck.estimate_output_tokens(log["model_key"], file_chars=chars)
        actual = log["usage"]["input_tokens"]
        if estimate < actual:
            short.append(f"{log['vul_id']}/{log['model_key']}: {estimate} < {actual}")
    assert not short, short


# ── the budget ───────────────────────────────────────────────────────────

def test_cloud_budget_is_the_configured_cap():
    budget, detail = capcheck.budget_for("claude")
    assert budget == OUTPUT_CAPS["claude"] and str(OUTPUT_CAPS["claude"]) in detail


def test_gpt_budget_reserves_room_for_reasoning():
    budget, detail = capcheck.budget_for("gpt")
    assert budget == OUTPUT_CAPS["gpt"] - capcheck.GPT_REASONING_RESERVE
    assert "reasoning" in detail


def test_the_reasoning_reserve_is_adjustable():
    budget, _ = capcheck.budget_for("gpt", reasoning_reserve=0)
    assert budget == OUTPUT_CAPS["gpt"]


def test_a_local_budget_is_what_the_shared_window_has_left():
    small, _ = capcheck.budget_for("granite-8b", prompt_chars=1_000)
    large, detail = capcheck.budget_for("granite-8b", prompt_chars=100_000)
    assert small < OLLAMA_NUM_CTX          # the prompt is already in the window
    assert large < small
    assert "shared" in detail


def test_a_prompt_that_fills_a_local_window_leaves_no_room():
    risk = capcheck.check_cell("V", "L1", "granite-8b", file_chars=5_000,
                               prompt_chars=10_000_000)
    assert risk.verdict == capcheck.OVER and risk.budget <= 0


# ── classification ───────────────────────────────────────────────────────

def test_a_file_that_cannot_fit_is_over():
    risk = capcheck.check_cell("V", "L1", "claude", known_tokens=50_000)
    assert risk.verdict == capcheck.OVER and risk.at_risk


def test_a_small_file_is_ok_and_not_at_risk():
    risk = capcheck.check_cell("V", "L1", "claude", known_tokens=200)
    assert risk.verdict == capcheck.OK and not risk.at_risk


def test_a_file_near_the_cap_is_tight():
    # just inside the cap, but past the tight fraction of it
    cap = OUTPUT_CAPS["claude"]
    tokens = int(cap * 0.95 / (capcheck.TOKENIZER_RATIO["claude"] * capcheck.PATCH_GROWTH))
    risk = capcheck.check_cell("V", "L1", "claude", known_tokens=tokens)
    assert risk.verdict == capcheck.TIGHT and risk.at_risk


def test_gemini_clears_what_claude_cannot_at_the_same_size():
    tokens = 9_000
    assert capcheck.check_cell("V", "L1", "claude", known_tokens=tokens).verdict == capcheck.OVER
    assert capcheck.check_cell("V", "L1", "gemini", known_tokens=tokens).verdict == capcheck.OK


# ── whole plans ──────────────────────────────────────────────────────────

CELLS = [("V-big", "L1", "claude"), ("V-small", "L1", "claude"),
         ("V-unknown", "L1", "claude")]


def test_cells_of_unknown_size_are_skipped_not_guessed():
    risks = capcheck.check_cells(CELLS, file_chars={"V-big": 200_000, "V-small": 500})
    assert {r.vul_id for r in risks} == {"V-big", "V-small"}


def test_a_known_count_wins_over_the_character_estimate():
    # 200k dense characters would estimate far above this count
    risks = capcheck.check_cells([("V", "L1", "claude")], file_chars={"V": 200_000},
                                 file_tokens={"V": 1_000})
    assert risks[0].output_estimate < 2_000


def test_summary_line_reports_nothing_to_worry_about():
    risks = capcheck.check_cells([("V", "L1", "claude")], file_chars={"V": 500})
    line = capcheck.summary_line(risks, 1)
    assert "no truncation risk" in line


def test_summary_line_counts_by_model_and_names_the_consequence():
    risks = capcheck.check_cells([("V", "L1", "claude"), ("V", "L1", "gpt")],
                                 file_tokens={"V": 50_000})
    line = capcheck.summary_line(risks, 2)
    assert "over cap" in line and "claude 1" in line and "gpt 1" in line
    assert "L0" in line


def test_report_lists_the_flagged_cells_and_the_unknown_ones():
    risks = capcheck.check_cells([("V-big", "L1", "claude")], file_tokens={"V-big": 50_000})
    text = capcheck.report(risks, 2, unknown=["V-gone"])
    assert "V-big" in text and "Largest need" in text
    assert "V-gone" in text and "Size unknown" in text


# ── the generate.py wiring ───────────────────────────────────────────────

FAKE_PAYLOAD = {
    "vul_id": "VUL4J-78", "cve_id": "CVE-x", "cwe_id": "CWE-22",
    "cwe_name": "Path Traversal", "primary_file": "A.java",
    "primary_content": "class A {}" * 9000,          # big enough to be over cap
    "repair_prose": "p",
    "repair_schema": {"root_cause": "r", "canonical_repair": "c",
                      "constraints": "k", "what_to_avoid": "a"},
}


@pytest.fixture
def no_api(monkeypatch):
    """Any API call during a cap check is a bug."""
    def boom(*a, **kw):
        raise AssertionError("--check-caps must not call a model")
    monkeypatch.setattr(generate, "call_model", boom)
    monkeypatch.setattr(generate, "payload_for", lambda vul_id: dict(FAKE_PAYLOAD))


def test_check_caps_reports_and_calls_no_api(no_api, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["generate.py", "--check-caps",
                                      "--vulns", "VUL4J-78", "--models", "claude",
                                      "--levels", "L1"])
    generate.main()
    out = capsys.readouterr().out
    assert "Cap check:" in out and "over cap" in out
    assert "VUL4J-78" in out


def test_a_normal_run_prints_the_summary_before_starting(no_api, monkeypatch, capsys):
    # --dry-run stops before any API call, after the plan and the cap summary
    monkeypatch.setattr(sys, "argv", ["generate.py", "--dry-run",
                                      "--vulns", "VUL4J-78", "--models", "claude",
                                      "--levels", "L1"])
    generate.main()
    out = capsys.readouterr().out
    assert "Cap check:" in out
    assert out.index("Cap check:") < out.index("Dry run")


def test_cap_risks_reports_a_payload_it_cannot_build(monkeypatch):
    monkeypatch.setattr(generate, "payload_for", lambda vul_id: None)
    risks, unknown = generate.cap_risks([("VUL4J-1", "L1", "claude")])
    assert risks == [] and unknown == ["VUL4J-1"]
