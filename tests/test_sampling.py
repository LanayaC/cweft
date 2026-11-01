"""
Temperature and repetition: what each provider is sent, what the log records,
where the logs and results go, and that a rejected temperature stops the run.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import config  # noqa: E402
import evaluate  # noqa: E402
import generate  # noqa: E402
import models  # noqa: E402
import patcheval_eval  # noqa: E402

VLLM_KEY = "granite-8b-bf16"
PAYLOAD = {
    "vul_id": "VUL4J-1", "cve_id": "CVE-x", "cwe_id": "CWE-22",
    "cwe_name": "Path Traversal", "primary_file": "A.java",
    "primary_content": "class A {}", "repair_prose": "p", "repair_schema": {
        "root_cause": "r", "canonical_repair": "c", "constraints": "k",
        "what_to_avoid": "a"},
}


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _openai_client(calls):
    done = _Obj(choices=[_Obj(message=_Obj(content="class A {}"), finish_reason="stop")],
                usage=_Obj(prompt_tokens=1, completion_tokens=2))

    def create(**kw):
        calls.append(kw)
        return done
    return _Obj(chat=_Obj(completions=_Obj(create=create)))


# ── what is sent ─────────────────────────────────────────────────────────

def test_vllm_sends_and_reports_every_sampling_parameter(monkeypatch):
    calls = []
    monkeypatch.setattr(models, "_vllm_prompt_tokens",
                        lambda m, msgs: (1_000, config.VLLM_MAX_MODEL_LEN))
    monkeypatch.setattr(models, "_get_vllm", lambda: _openai_client(calls))
    _, usage = models.call_model(VLLM_KEY, "p", temperature=0.5, seed=99)
    sent = calls[0]
    assert (sent["temperature"], sent["top_p"], sent["seed"]) == (0.5, config.VLLM_TOP_P, 99)
    assert sent["extra_body"] == {"top_k": config.VLLM_TOP_K}
    assert usage["sampling_params"] == {
        "temperature": 0.5, "top_p": config.VLLM_TOP_P, "top_k": config.VLLM_TOP_K,
        "max_tokens": sent["max_tokens"], "seed": 99}


def test_a_vllm_model_without_a_seed_is_refused():
    with pytest.raises(ValueError, match="needs a seed"):
        models.call_model(VLLM_KEY, "p", temperature=0.5)


def test_call_model_will_not_run_without_a_temperature():
    with pytest.raises(TypeError, match="temperature"):
        models.call_model("claude", "p")


@pytest.mark.parametrize("temperature", [0.0, 0.5, 1.0])
def test_claude_sends_the_temperature_even_when_it_is_zero(monkeypatch, temperature):
    calls = []
    done = _Obj(content=[_Obj(text="class A {}")], stop_reason="end_turn",
                usage=_Obj(input_tokens=1, output_tokens=2))

    def create(**kw):
        calls.append(kw)
        return done
    monkeypatch.setattr(models, "_get_anthropic", lambda: _Obj(messages=_Obj(create=create)))
    _, usage = models.call_model("claude", "p", temperature=temperature)
    assert calls[0]["temperature"] == temperature
    assert usage["sampling_params"] == {"temperature": temperature, "top_p": None, "top_k": None,
                                        "max_tokens": models.OUTPUT_CAPS["claude"], "seed": None}


def test_gpt_sends_the_temperature(monkeypatch):
    calls = []
    monkeypatch.setattr(models, "_get_openai", lambda: _openai_client(calls))
    models.call_model("gpt", "p", temperature=0.5)
    assert calls[0]["temperature"] == 0.5


def test_gemini_sends_the_temperature(monkeypatch):
    from google.genai import types
    calls = []
    done = _Obj(text="class A {}", candidates=[_Obj(finish_reason="STOP")],
                usage_metadata=_Obj(prompt_token_count=1, candidates_token_count=2))

    def generate_content(**kw):
        calls.append(kw)
        return done
    monkeypatch.setattr(models, "_get_gemini",
                        lambda: _Obj(models=_Obj(generate_content=generate_content)))
    monkeypatch.setattr(types, "ThinkingConfig", lambda **kw: None)
    monkeypatch.setattr(types, "GenerateContentConfig", lambda **kw: _Obj(**kw))
    models.call_model("gemini", "p", temperature=0.0)
    assert calls[0]["config"].temperature == 0.0


def test_ollama_sends_the_temperature(monkeypatch):
    import httpx
    bodies = []

    def post(url, json, timeout):
        bodies.append(json)
        return _Obj(status_code=200, json=lambda: {
            "response": "class A {}", "done_reason": "stop",
            "prompt_eval_count": 1, "eval_count": 2})
    monkeypatch.setattr(httpx, "post", post)
    models.call_model("granite-8b", "p", temperature=0.5)
    assert bodies[0]["options"]["temperature"] == 0.5


# ── the seed ─────────────────────────────────────────────────────────────

def test_seed_is_reproducible_and_differs_by_repetition():
    seed = models.request_seed
    assert seed("VUL4J-1", "L1", VLLM_KEY, 1) == seed("VUL4J-1", "L1", VLLM_KEY, 1)
    assert len({seed("VUL4J-1", "L1", VLLM_KEY, r) for r in range(1, 21)}) == 20
    assert seed("VUL4J-1", "L1", VLLM_KEY, 1) != seed("VUL4J-1", "L2", VLLM_KEY, 1)
    assert 0 <= seed("VUL4J-1", "L1", VLLM_KEY, 1) < 2**31


def test_seed_is_the_same_in_a_new_process():
    code = (f"import models; print(models.request_seed('VUL4J-1', 'L1', '{VLLM_KEY}', 2))")
    out = subprocess.run([sys.executable, "-c", code], cwd=PROJECT_ROOT, text=True,
                         capture_output=True, check=True).stdout.strip()
    assert int(out) == models.request_seed("VUL4J-1", "L1", VLLM_KEY, 2)


# ── what the log records ─────────────────────────────────────────────────

def test_the_log_records_the_settings_and_what_was_sent(monkeypatch):
    sampling = {"temperature": 0.5, "top_p": 1.0, "top_k": -1, "max_tokens": 9, "seed": 1}
    seen = {}

    def fake(key, prompt, language, temperature, seed):
        seen.update(temperature=temperature, seed=seed)
        return "class A {}", {"input_tokens": 1, "output_tokens": 2, "latency_s": 0.1,
                              "sampling_params": sampling}
    monkeypatch.setattr(generate, "call_model", fake)
    record = generate.run_cell(PAYLOAD, "L1", VLLM_KEY, temperature=0.5, repetition=3)
    expected_seed = models.request_seed("VUL4J-1", "L1", VLLM_KEY, 3)
    assert seen == {"temperature": 0.5, "seed": expected_seed}
    assert (record["temperature"], record["repetition"], record["seed"]) == (0.5, 3, expected_seed)
    assert record["sampling_params"] == sampling
    assert "sampling_params" not in record["usage"]


def test_a_cloud_cell_records_no_seed(monkeypatch):
    seen = {}

    def fake(key, prompt, language, temperature, seed):
        seen["seed"] = seed
        return "class A {}", {"input_tokens": 1, "output_tokens": 2, "latency_s": 0.1}
    monkeypatch.setattr(generate, "call_model", fake)
    record = generate.run_cell(PAYLOAD, "L1", "claude", temperature=1.0, repetition=2)
    assert seen["seed"] is None and record["seed"] is None


# ── a rejected temperature ───────────────────────────────────────────────

class _BadRequest(Exception):
    status_code = 400


@pytest.mark.parametrize("error,rejected", [
    (_BadRequest("Unsupported value: 'temperature' does not support 0"), True),
    (_BadRequest("prompt is too long"), False),
    (Exception("temperature is mentioned, but this is not a bad request"), False),
])
def test_only_a_bad_request_about_the_temperature_counts(error, rejected):
    assert models._rejects_temperature(error) is rejected


def test_a_gemini_style_error_code_counts():
    error = Exception("temperature out of range")
    error.code = 400
    assert models._rejects_temperature(error) is True


def test_a_rejected_temperature_stops_the_run_and_logs_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(generate, "LOGS_DIR", generate.LOGS_DIR)
    monkeypatch.setattr(generate, "PATCHEVAL_LOGS_DIR", generate.PATCHEVAL_LOGS_DIR)
    calls = []

    def refuse(prompt, system, temperature):
        calls.append(temperature)
        raise _BadRequest("'temperature' does not support 0 with this model")
    monkeypatch.setitem(models._DISPATCH, "gpt", refuse)
    monkeypatch.setattr(generate, "payload_for", lambda vul_id: dict(PAYLOAD))
    monkeypatch.setattr(generate.time, "sleep", lambda s: pytest.fail("must not retry"))
    monkeypatch.setattr(sys, "argv", [
        "generate.py", "--models", "gpt", "--vulns", "VUL4J-1", "--levels", "L1",
        "--temperature", "0", "--logs-dir", str(tmp_path)])
    with pytest.raises(SystemExit) as e:
        generate.main()
    assert calls == [0.0]
    assert "rejected temperature=0.0" in str(e.value)
    assert list(tmp_path.rglob("*.json")) == []


# ── the arguments ────────────────────────────────────────────────────────

@pytest.mark.parametrize("extra", [[], ["--temperature", "0.7"],
                                   ["--temperature", "0.5", "--repetition", "0"]])
def test_generate_refuses_a_missing_or_bad_setting(monkeypatch, extra):
    monkeypatch.setattr(sys, "argv", ["generate.py", "--dry-run", *extra])
    with pytest.raises(SystemExit) as e:
        generate.main()
    assert e.value.code == 2


@pytest.mark.parametrize("value", ["0", "0.0", "0.5", "1", "1.0"])
def test_every_way_of_writing_an_allowed_temperature_is_accepted(tmp_path, monkeypatch, value):
    monkeypatch.setattr(generate, "LOGS_DIR", generate.LOGS_DIR)
    monkeypatch.setattr(generate, "PATCHEVAL_LOGS_DIR", generate.PATCHEVAL_LOGS_DIR)
    monkeypatch.setattr(generate, "payload_for", lambda vul_id: dict(PAYLOAD))
    monkeypatch.setattr(sys, "argv", [
        "generate.py", "--dry-run", "--models", "claude", "--vulns", "VUL4J-1", "--levels", "L1",
        "--temperature", value, "--logs-dir", str(tmp_path)])
    generate.main()
    assert generate.LOGS_DIR.name == "r1" and generate.LOGS_DIR.parent.name == f"t{float(value)}"


# ── the folders ──────────────────────────────────────────────────────────

def test_run_subdir():
    assert config.run_subdir(0, 1) == Path("t0.0") / "r1"
    assert config.run_subdir(0.5, 2) == Path("t0.5") / "r2"
    assert config.run_subdir(1, 3) == Path("t1.0") / "r3"


def _write(path: Path, **record) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record))


def _point_at(monkeypatch, folder: Path) -> Path:
    monkeypatch.setattr(generate, "LOGS_DIR", folder)
    return folder / "VUL4J-1__L1__m.json"


def test_only_a_log_from_this_run_counts_as_done(tmp_path, monkeypatch):
    log = _point_at(monkeypatch, tmp_path)
    assert generate.cell_already_done("VUL4J-1", "L1", "m", 0.5, 2) is False
    _write(log, status="error", temperature=0.5, repetition=2)
    assert generate.cell_already_done("VUL4J-1", "L1", "m", 0.5, 2) is False
    _write(log, status="ok", temperature=0.5, repetition=2)
    assert generate.cell_already_done("VUL4J-1", "L1", "m", 0.5, 2) is True


@pytest.mark.parametrize("record", [
    {"temperature": 1.0, "repetition": 2},
    {"temperature": 0.5, "repetition": 1},
    {},                                     # an older log, from before these fields
])
def test_a_log_from_other_settings_stops_the_run(tmp_path, monkeypatch, record):
    _write(_point_at(monkeypatch, tmp_path), status="ok", **record)
    with pytest.raises(SystemExit, match="Move that log"):
        generate.cell_already_done("VUL4J-1", "L1", "m", 0.5, 2)


@pytest.fixture
def keep_evaluate_globals(monkeypatch):
    monkeypatch.setattr(evaluate, "LOGS_DIR", evaluate.LOGS_DIR)
    monkeypatch.setattr(evaluate, "RESULTS_CSV", evaluate.RESULTS_CSV)
    monkeypatch.setattr(patcheval_eval, "PATCHEVAL_LOGS_DIR", patcheval_eval.PATCHEVAL_LOGS_DIR)
    monkeypatch.setattr(patcheval_eval, "RESULTS_CSV", patcheval_eval.RESULTS_CSV)


def test_evaluate_follows_the_same_folders(tmp_path, monkeypatch, keep_evaluate_globals):
    logs, results = tmp_path / "logs", tmp_path / "results"
    monkeypatch.setattr(sys, "argv", [
        "evaluate.py", "--dataset", "patcheval", "--temperature", "0.5", "--repetition", "2",
        "--logs-dir", str(logs), "--results-dir", str(results)])
    evaluate.main()
    run = Path("t0.5") / "r2"
    assert patcheval_eval.PATCHEVAL_LOGS_DIR == (logs / run).resolve() / "patcheval"
    assert evaluate.RESULTS_CSV == (results / run).resolve() / "results.csv"
    assert patcheval_eval.RESULTS_CSV == (results / run).resolve() / "results_patcheval.csv"


def test_evaluate_default_folders_with_a_temperature(tmp_path, monkeypatch, keep_evaluate_globals):
    monkeypatch.setattr(evaluate, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setattr(evaluate, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(sys, "argv", ["evaluate.py", "--temperature", "1.0"])
    with pytest.raises(SystemExit):        # no such logs here, which ends the run
        evaluate.main()
    assert evaluate.LOGS_DIR == (tmp_path / "logs" / "t1.0" / "r1").resolve()
    assert evaluate.RESULTS_CSV == (tmp_path / "results" / "t1.0" / "r1").resolve() / "results.csv"


def test_evaluate_without_a_temperature_uses_the_folders_as_given(tmp_path, monkeypatch,
                                                                  keep_evaluate_globals):
    logs = tmp_path / "old_logs"
    monkeypatch.setattr(sys, "argv", ["evaluate.py", "--dataset", "patcheval",
                                      "--logs-dir", str(logs), "--results-dir", str(tmp_path)])
    evaluate.main()
    assert evaluate.LOGS_DIR == logs.resolve()
    assert evaluate.RESULTS_CSV == tmp_path.resolve() / "results.csv"


@pytest.mark.parametrize("argv", [["--repetition", "2"],
                                  ["--oracle", "--temperature", "0.5"]])
def test_evaluate_refuses_a_setting_that_means_nothing(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["evaluate.py", *argv])
    with pytest.raises(SystemExit) as e:
        evaluate.main()
    assert e.value.code == 2


def test_an_older_log_grades_exactly_as_before(monkeypatch):
    """A published log has none of the new fields, and a row has no new columns."""
    published = next((PROJECT_ROOT / "logs" / "published").glob("VUL4J-*.json"))
    log = json.loads(published.read_text(encoding="utf-8"))
    assert "temperature" not in log and "sampling_params" not in log
    written = {}

    def fake_grade(vul_id, primary_file, apply, entry):
        apply("/work", primary_file)
        return {"trust": "L3", "compiled": True, "pov_passed": True, "regressions": [],
                "flaky": [], "tests_run": 5, "error": ""}
    monkeypatch.setattr(evaluate, "grade", fake_grade)
    monkeypatch.setattr(evaluate, "_docker_write_file",
                        lambda path, content: written.update({path: content}))
    row = evaluate.evaluate_log(published, {})
    assert row["trust_level"] == "L3"
    assert written == {f"/work/{log['primary_file']}": log["response"]}
    assert set(row) == set(evaluate.CSV_FIELDS)
    assert "temperature" not in evaluate.CSV_FIELDS


# ── the job script ───────────────────────────────────────────────────────

def test_the_job_script_waits_an_hour_and_records_the_gpu_software():
    script = (PROJECT_ROOT / "leylak" / "run_model.sbatch").read_text(encoding="utf-8")
    assert "WAIT_TIMEOUT=3600" in script
    assert "\nnvidia-smi 2>&1" in script
    assert script.index("\nnvidia-smi 2>&1") < script.index("setsid vllm serve")
