"""
The vLLM path: OpenAI-compatible generation against a server whose window is
VLLM_MAX_MODEL_LEN.

Mirrors the Ollama tests (stop reason recorded, the request reaches the right
endpoint), then covers what is new here: max_tokens is what the window has left,
a prompt that leaves nothing is skipped without being sent, a cut-off answer is
flagged rather than raised, and a placeholder model id fails before any call.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import capcheck  # noqa: E402
import config  # noqa: E402
import generate  # noqa: E402
import models  # noqa: E402

KEY = "granite-8b-bf16"
HF_ID = "test-org/granite-8b-test"


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _fake_vllm(finish_reason, text="class A {}", calls=None):
    """An OpenAI client stand-in that records the kwargs of each request."""
    completion = _Obj(
        choices=[_Obj(message=_Obj(content=text), finish_reason=finish_reason)],
        usage=_Obj(prompt_tokens=11, completion_tokens=22))

    def create(**kw):
        if calls is not None:
            calls.append(kw)
        return completion
    return _Obj(chat=_Obj(completions=_Obj(create=create)))


@pytest.fixture
def filled(monkeypatch):
    """Give KEY a real-looking id, as config.py will once it is filled in."""
    monkeypatch.setitem(models.MODELS, KEY, HF_ID)
    monkeypatch.setitem(models.VLLM_MODELS, KEY, HF_ID)


def _tokenize_returns(monkeypatch, count, max_model_len=config.VLLM_MAX_MODEL_LEN):
    monkeypatch.setattr(models, "_vllm_prompt_tokens",
                        lambda model_id, messages: (count, max_model_len))


# ── the model list ───────────────────────────────────────────────────────

def test_every_vllm_model_is_dispatched_and_colon_free():
    for key in config.VLLM_MODELS:
        assert key in models._DISPATCH
        assert ":" not in key, "the key goes into a log filename"


def test_the_ollama_entries_are_unchanged():
    assert config.LOCAL_MODELS == {
        "granite-8b":  "granite4.1:8b-q8_0",
        "granite-30b": "granite4.1:30b-q8_0",
        "gemma-12b":   "gemma4:12b-it-q8_0",
        "gemma-31b":   "gemma4:31b-it-q8_0",
    }


@pytest.mark.parametrize("reason,expected", [("length", True), ("stop", False)])
def test_is_truncated_vllm(reason, expected):
    assert models.is_truncated("vllm", reason) is expected


# ── a call, mirroring the Ollama tests ───────────────────────────────────

def test_vllm_records_finish_reason(monkeypatch, filled):
    calls = []
    _tokenize_returns(monkeypatch, 1_000)
    monkeypatch.setattr(models, "_get_vllm", lambda: _fake_vllm("stop", calls=calls))
    text, usage = models._call_vllm("p", "sys", model_key=KEY)
    assert text == "class A {}"
    assert usage["stop_reason"] == "stop"
    assert usage["truncated"] is False
    assert calls[0]["model"] == HF_ID
    assert calls[0]["max_tokens"] == usage["max_tokens"]
    assert "temperature" not in calls[0], "no model sets one; all run at server default"


def test_vllm_truncation_is_flagged_not_raised(monkeypatch, filled):
    """
    Unlike Ollama, a cut-off answer is a result to flag, as for the cloud
    models, so it reaches the log and the truncated column.
    """
    _tokenize_returns(monkeypatch, 1_000)
    monkeypatch.setattr(models, "_get_vllm", lambda: _fake_vllm("length"))
    _, usage = models._call_vllm("p", "sys", model_key=KEY)
    assert usage["stop_reason"] == "length"
    assert usage["truncated"] is True


def test_vllm_empty_response_raises(monkeypatch, filled):
    _tokenize_returns(monkeypatch, 1_000)
    monkeypatch.setattr(models, "_get_vllm", lambda: _fake_vllm("stop", text=""))
    with pytest.raises(RuntimeError, match="empty response"):
        models._call_vllm("p", "sys", model_key=KEY)


def test_tokenize_goes_to_the_server_root_with_the_same_messages(monkeypatch):
    import httpx
    seen = {}

    def post(url, json, timeout):
        seen["url"], seen["json"] = url, json
        return _Obj(status_code=200, json=lambda: {"count": 123, "max_model_len": 65536})
    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(models, "VLLM_BASE_URL", "http://gpu5:8000/v1")
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    assert models._vllm_prompt_tokens(HF_ID, messages) == (123, 65536)
    assert seen["url"] == "http://gpu5:8000/tokenize"
    assert seen["json"]["messages"] == messages
    assert seen["json"]["add_generation_prompt"] is True


def test_vllm_unreachable_says_where(monkeypatch):
    import httpx

    def post(*a, **kw):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(httpx, "post", post)
    with pytest.raises(RuntimeError, match="vLLM unreachable"):
        models._vllm_prompt_tokens(HF_ID, [])


def test_a_server_window_that_differs_from_config_refuses(monkeypatch, filled):
    _tokenize_returns(monkeypatch, 1_000, max_model_len=32768)
    monkeypatch.setattr(models, "_get_vllm",
                        lambda: pytest.fail("must not generate on a mismatched window"))
    with pytest.raises(RuntimeError, match="max_model_len=32768"):
        models._call_vllm("p", "sys", model_key=KEY)


# ── the output budget ────────────────────────────────────────────────────

def test_max_tokens_is_what_the_window_has_left(monkeypatch):
    monkeypatch.setattr(models, "VLLM_TOKEN_MARGIN", 64)
    monkeypatch.setattr(models, "VLLM_MAX_OUTPUT_TOKENS", 64_000)
    # Room left after the prompt and margin, below the cap: use all of it.
    assert models.vllm_max_tokens(10_000, max_model_len=65_536) == 65_536 - 10_000 - 64
    # More room than the cap: the cap wins.
    assert models.vllm_max_tokens(1_000, max_model_len=65_536) == 64_000
    # One token of room is still room.
    assert models.vllm_max_tokens(65_536 - 64 - 1, max_model_len=65_536) == 1
    # None is not.
    with pytest.raises(models.PromptExceedsWindow):
        models.vllm_max_tokens(65_536 - 64, max_model_len=65_536)


# ── a prompt too long for the window ─────────────────────────────────────

def test_a_prompt_that_does_not_fit_is_never_sent(monkeypatch, filled):
    _tokenize_returns(monkeypatch, config.VLLM_MAX_MODEL_LEN + 5_000)
    monkeypatch.setattr(models, "_get_vllm",
                        lambda: pytest.fail("the request must not be sent"))
    with pytest.raises(models.PromptExceedsWindow, match="no room"):
        models._call_vllm("p", "sys", model_key=KEY)


def test_run_cell_records_the_skip_and_does_not_retry(monkeypatch):
    def too_long(*a, **kw):
        raise models.PromptExceedsWindow("prompt is 70000 tokens")
    monkeypatch.setattr(generate, "call_model", too_long)
    monkeypatch.setattr(generate.time, "sleep", lambda s: pytest.fail("must not back off"))
    payload = {
        "vul_id": "VUL4J-1", "cve_id": "CVE-x", "cwe_id": "CWE-22",
        "cwe_name": "Path Traversal", "primary_file": "A.java",
        "primary_content": "class A {}", "repair_prose": "p", "repair_schema": {
            "root_cause": "r", "canonical_repair": "c", "constraints": "k",
            "what_to_avoid": "a"},
    }
    record = generate.run_cell(payload, "L1", KEY)
    assert record["status"] == "skipped"
    assert record["error"].startswith("prompt exceeds window")
    assert record["attempts"] == 1
    assert "response" not in record


# ── placeholders ─────────────────────────────────────────────────────────

def test_placeholder_ids_are_reported():
    assert models.vllm_placeholders(["claude", "granite-8b", KEY]) == [KEY]


def test_a_placeholder_id_fails_before_any_call(monkeypatch):
    monkeypatch.setattr(models, "_vllm_prompt_tokens",
                        lambda *a: pytest.fail("must not reach the server"))
    with pytest.raises(ValueError, match="VLLM_MODELS in config.py"):
        models._call_vllm("p", "sys", model_key=KEY)


# ── the pre-flight cap check ─────────────────────────────────────────────

def test_capcheck_budget_for_a_vllm_model():
    small, detail = capcheck.budget_for(KEY, prompt_chars=1_000)
    large, _ = capcheck.budget_for(KEY, prompt_chars=200_000)
    assert small == config.VLLM_MAX_OUTPUT_TOKENS      # capped
    assert large < small                               # the prompt shares the window
    assert "max_model_len" in detail
