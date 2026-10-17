"""
Stop-reason recording: a response that stops at the output cap must be recorded
as such, at every stage, for every provider.

Each provider reports stopping differently, so each gets a positive case (it hit
the cap) and a negative control (it finished normally) against a fake client.
Then: the flag reaches the generation log and prints a warning, the results
writers carry it as a column and refuse to append to an older header.
"""

import csv
import json
import sys
import types as pytypes
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import evaluate  # noqa: E402
import generate  # noqa: E402
import models  # noqa: E402
import patcheval_eval  # noqa: E402


# ── the mapping itself ───────────────────────────────────────────────────

@pytest.mark.parametrize("provider,reason,expected", [
    ("claude", "max_tokens", True),
    ("claude", "end_turn", False),
    ("claude", "refusal", False),
    ("gpt", "length", True),
    ("gpt", "stop", False),
    ("gpt", "content_filter", False),
    ("gemini", "MAX_TOKENS", True),
    ("gemini", "FinishReason.MAX_TOKENS", True),   # the enum's str()
    ("gemini", "STOP", False),
    ("gemini", "SAFETY", False),
    ("ollama", "length", True),
    ("ollama", "stop", False),
    ("claude", "", False),
    ("claude", None, False),
])
def test_is_truncated_per_provider(provider, reason, expected):
    assert models.is_truncated(provider, reason or "") is expected


def test_unknown_provider_never_reports_truncation():
    assert models.is_truncated("nobody", "length") is False


# ── per-provider capture, against fake clients ───────────────────────────

class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _fake_anthropic(stop_reason):
    message = _Obj(content=[_Obj(text="class A {}")],
                   usage=_Obj(input_tokens=11, output_tokens=22),
                   stop_reason=stop_reason)
    return _Obj(messages=_Obj(create=lambda **kw: message))


def _fake_openai(finish_reason, text="class A {}", reasoning=None):
    details = _Obj(reasoning_tokens=reasoning) if reasoning is not None else None
    completion = _Obj(
        choices=[_Obj(message=_Obj(content=text), finish_reason=finish_reason)],
        usage=_Obj(prompt_tokens=11, completion_tokens=22,
                   completion_tokens_details=details))
    return _Obj(chat=_Obj(completions=_Obj(create=lambda **kw: completion)))


def _fake_gemini(finish_reason, text="class A {}"):
    response = _Obj(text=text,
                    candidates=[_Obj(finish_reason=_Obj(name=finish_reason))],
                    usage_metadata=_Obj(prompt_token_count=11, candidates_token_count=22))
    return _Obj(models=_Obj(generate_content=lambda **kw: response))


@pytest.fixture
def stub_genai_types(monkeypatch):
    """_call_gemini imports google.genai.types at call time; stub the two it uses."""
    mod = pytypes.ModuleType("google.genai.types")
    mod.GenerateContentConfig = lambda **kw: kw
    mod.ThinkingConfig = lambda **kw: kw
    genai = pytypes.ModuleType("google.genai")
    genai.types = mod
    monkeypatch.setitem(sys.modules, "google.genai", genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", mod)


@pytest.mark.parametrize("reason,truncated", [("max_tokens", True), ("end_turn", False)])
def test_claude_records_stop_reason(monkeypatch, reason, truncated):
    monkeypatch.setattr(models, "_get_anthropic", lambda: _fake_anthropic(reason))
    text, usage = models._call_claude("p", "sys")
    assert text == "class A {}"
    assert usage["stop_reason"] == reason
    assert usage["truncated"] is truncated
    assert usage["output_tokens"] == 22


@pytest.mark.parametrize("reason,truncated", [("length", True), ("stop", False)])
def test_gpt_records_finish_reason_and_reasoning_tokens(monkeypatch, reason, truncated):
    monkeypatch.setattr(models, "_get_openai", lambda: _fake_openai(reason, reasoning=7))
    text, usage = models._call_gpt("p", "sys")
    assert usage["stop_reason"] == reason
    assert usage["truncated"] is truncated
    assert usage["reasoning_tokens"] == 7


def test_gpt_empty_response_still_raises(monkeypatch):
    """The existing guard must survive: an empty file is not a patch."""
    monkeypatch.setattr(models, "_get_openai", lambda: _fake_openai("length", text=""))
    with pytest.raises(RuntimeError, match="empty response"):
        models._call_gpt("p", "sys")


@pytest.mark.parametrize("reason,truncated", [("MAX_TOKENS", True), ("STOP", False)])
def test_gemini_records_finish_reason(monkeypatch, stub_genai_types, reason, truncated):
    monkeypatch.setattr(models, "_get_gemini", lambda: _fake_gemini(reason))
    text, usage = models._call_gemini("p", "sys")
    assert usage["stop_reason"] == reason
    assert usage["truncated"] is truncated


def test_gemini_no_text_names_the_reason(monkeypatch, stub_genai_types):
    monkeypatch.setattr(models, "_get_gemini", lambda: _fake_gemini("SAFETY", text=None))
    with pytest.raises(RuntimeError, match="SAFETY"):
        models._call_gemini("p", "sys")


def _ollama_payload(done_reason, eval_count=22):
    return {"response": "class A {}", "prompt_eval_count": 11,
            "eval_count": eval_count, "done_reason": done_reason}


def test_ollama_records_done_reason(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "post",
                        lambda *a, **kw: _Obj(status_code=200,
                                              json=lambda: _ollama_payload("stop")))
    text, usage = models._call_ollama("p", "sys", model_key="granite-8b")
    assert usage["stop_reason"] == "stop"
    assert usage["truncated"] is False


def test_ollama_truncation_raises_loudly(monkeypatch):
    """
    Locals fail rather than flag: their window holds prompt and output together,
    so a cut-off generation is an error, not a result to score.
    """
    import httpx
    monkeypatch.setattr(httpx, "post",
                        lambda *a, **kw: _Obj(status_code=200,
                                              json=lambda: _ollama_payload("length")))
    with pytest.raises(RuntimeError, match="truncated"):
        models._call_ollama("p", "sys", model_key="granite-8b")


# ── normalisation ────────────────────────────────────────────────────────

def test_call_model_always_sets_the_keys(monkeypatch):
    def bare(prompt, system):
        return "x", {"input_tokens": 1, "output_tokens": 2}   # provider told us nothing
    monkeypatch.setitem(models._DISPATCH, "claude", bare)
    _, usage = models.call_model("claude", "p")
    assert usage["stop_reason"] == "" and usage["truncated"] is False


# ── the generation log ───────────────────────────────────────────────────

PAYLOAD = {
    "vul_id": "VUL4J-1", "cve_id": "CVE-x", "cwe_id": "CWE-22",
    "cwe_name": "Path Traversal", "primary_file": "A.java",
    "primary_content": "class A {}", "repair_prose": "p", "repair_schema": {
        "root_cause": "r", "canonical_repair": "c", "constraints": "k", "what_to_avoid": "a"},
}


def test_run_cell_records_truncation_and_warns(monkeypatch, capsys):
    usage = {"input_tokens": 1, "output_tokens": 4000, "latency_s": 1.0,
             "stop_reason": "max_tokens", "truncated": True}
    monkeypatch.setattr(generate, "call_model", lambda *a, **kw: ("partial file", usage))
    record = generate.run_cell(PAYLOAD, "L1", "claude")
    assert record["status"] == "ok"
    assert record["truncated"] is True
    assert record["stop_reason"] == "max_tokens"
    assert record["usage"]["output_tokens"] == 4000
    out = capsys.readouterr().out
    assert "TRUNCATED" in out and "VUL4J-1" in out


def test_console_that_cannot_print_the_warning_still_yields_the_result(monkeypatch):
    """
    The warning sits inside the retry block. If printing it could raise, a paid
    successful call would become three retries and an error row.
    """
    usage = {"input_tokens": 1, "output_tokens": 4000, "latency_s": 1.0,
             "stop_reason": "max_tokens", "truncated": True}
    monkeypatch.setattr(generate, "call_model", lambda *a, **kw: ("partial", usage))

    def exploding_print(*a, **kw):
        raise UnicodeEncodeError("charmap", "x", 0, 1, "cp1252 cannot encode this")
    monkeypatch.setattr("builtins.print", exploding_print)
    record = generate.run_cell(PAYLOAD, "L1", "claude")
    assert record["status"] == "ok" and record["truncated"] is True
    assert record["attempts"] == 1, "it must not have retried"


def test_warning_text_is_ascii_only():
    """Console output must survive a cp1252 terminal, warnings included."""
    source = (PROJECT_ROOT / "generate.py").read_text(encoding="utf-8")
    offenders = [line.strip() for line in source.splitlines()
                 if "print(" in line and any(ord(ch) > 127 for ch in line)]
    assert not offenders, offenders


def test_run_cell_clean_response_is_not_flagged(monkeypatch, capsys):
    usage = {"input_tokens": 1, "output_tokens": 50, "latency_s": 1.0,
             "stop_reason": "end_turn", "truncated": False}
    monkeypatch.setattr(generate, "call_model", lambda *a, **kw: ("whole file", usage))
    record = generate.run_cell(PAYLOAD, "L1", "claude")
    assert record["truncated"] is False
    assert "TRUNCATED" not in capsys.readouterr().out


# ── the results writers ──────────────────────────────────────────────────

def test_both_results_writers_have_the_columns():
    for fields in (evaluate.CSV_FIELDS, patcheval_eval.CSV_FIELDS):
        assert "truncated" in fields and "stop_reason" in fields


def test_patcheval_row_defaults_carry_the_keys():
    row = patcheval_eval._row("CVE-2022-2900", {}, "L1", "claude", "m")
    assert row["truncated"] is False and row["stop_reason"] == ""


def test_evaluate_refuses_an_older_header(tmp_path, monkeypatch):
    old = tmp_path / "results.csv"
    old.write_text(",".join(c for c in evaluate.CSV_FIELDS
                            if c not in ("truncated", "stop_reason")) + "\n",
                   encoding="utf-8")
    monkeypatch.setattr(evaluate, "RESULTS_CSV", old)
    with pytest.raises(RuntimeError, match="older header"):
        evaluate.append_row({})
    assert old.read_text(encoding="utf-8").count("\n") == 1, "the old file must be untouched"


def test_patcheval_refuses_an_older_header(tmp_path):
    old = tmp_path / "results_patcheval.csv"
    old.write_text(",".join(c for c in patcheval_eval.CSV_FIELDS
                            if c not in ("truncated", "stop_reason")) + "\n",
                   encoding="utf-8")
    with pytest.raises(RuntimeError, match="older header"):
        patcheval_eval.append_row({}, old)


def test_evaluate_writes_the_flag_to_a_fresh_file(tmp_path, monkeypatch):
    fresh = tmp_path / "results.csv"
    monkeypatch.setattr(evaluate, "RESULTS_CSV", fresh)
    row = {k: "" for k in evaluate.CSV_FIELDS}
    row.update({"vul_id": "VUL4J-1", "level": "L1", "model_key": "claude",
                "trust_level": "L0", "truncated": True, "stop_reason": "max_tokens"})
    evaluate.append_row(row)
    back = list(csv.DictReader(fresh.open(newline="")))
    assert back[0]["truncated"] == "True" and back[0]["stop_reason"] == "max_tokens"
