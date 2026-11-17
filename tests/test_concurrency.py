"""
generate.py --concurrency against a fake vLLM server.

The server is a real HTTP server on 127.0.0.1 speaking the two endpoints
models._call_vllm uses (/tokenize and /v1/chat/completions), so the requests go
through the real OpenAI client and httpx from several threads at once. Each
answer carries a hash of the prompt it was given and the seed it was sent, so a
log that holds another cell's answer is caught, not just a missing log.
"""

import hashlib
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import generate  # noqa: E402
import models  # noqa: E402

MODEL = "granite-8b-bf16"
VULNS = [f"VUL4J-{n}" for n in range(1, 7)]
LEVELS = ["L1", "L2", "L3a", "L3b"]
CELLS = {(v, lv) for v in VULNS for lv in LEVELS}           # 24
# The server's own delay, out of reach of a test that patches time.sleep.
_sleep = time.sleep


def _payload(vul_id):
    # A different file per vuln, so every cell's prompt is different.
    return {
        "vul_id": vul_id, "cve_id": f"CVE-{vul_id}", "cwe_id": "CWE-22",
        "cwe_name": "Path Traversal", "primary_file": "A.java",
        "primary_content": f"class A {{ /* {vul_id} */ }}", "repair_prose": "p",
        "repair_schema": {"root_cause": "r", "canonical_repair": "c",
                          "constraints": "k", "what_to_avoid": "a"},
    }


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class FakeVLLM:
    """A vLLM stand-in that records every generation request it answers."""

    def __init__(self, delay=0.3, reject_on=None):
        self.delay = delay
        self.reject_on = reject_on      # the n-th chat request answers 400 (temperature)
        self.lock = threading.Lock()
        self.in_flight = 0
        self.max_in_flight = 0
        self.requests = []              # (seed, prompt digest), in arrival order
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/tokenize":
                    return self._send(200, {"count": 1_000,
                                            "max_model_len": models.VLLM_MAX_MODEL_LEN})
                assert self.path == "/v1/chat/completions", self.path
                prompt = body["messages"][-1]["content"]
                with fake.lock:
                    fake.requests.append((body["seed"], _digest(prompt)))
                    n = len(fake.requests)
                    fake.in_flight += 1
                    fake.max_in_flight = max(fake.max_in_flight, fake.in_flight)
                try:
                    _sleep(fake.delay)
                    if fake.reject_on is not None and n == fake.reject_on:
                        return self._send(400, {"error": {
                            "message": "temperature 0 is not supported", "type": "x",
                            "code": 400}})
                    text = f"class A {{ /* prompt={_digest(prompt)} seed={body['seed']} */ }}"
                    self._send(200, {
                        "id": f"c{n}", "object": "chat.completion", "created": 0,
                        "model": body["model"],
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": text}}],
                        "usage": {"prompt_tokens": 1_000, "completion_tokens": 20,
                                  "total_tokens": 1_020},
                    })
                finally:
                    with fake.lock:
                        fake.in_flight -= 1

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def run(tmp_path, monkeypatch):
    """run(fake, *extra_args) runs generate.main() against `fake`; returns the log folder."""
    monkeypatch.setattr(generate, "LOGS_DIR", generate.LOGS_DIR)
    monkeypatch.setattr(generate, "PATCHEVAL_LOGS_DIR", generate.PATCHEVAL_LOGS_DIR)
    monkeypatch.setattr(generate, "payload_for", _payload)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setattr(models, "_clients", {})
    servers = []

    def _run(fake, *extra):
        servers.append(fake)
        monkeypatch.setattr(models, "VLLM_BASE_URL", fake.url)
        models._clients.pop("vllm", None)       # a new server, a new client
        monkeypatch.setattr(sys, "argv", [
            "generate.py", "--models", MODEL, "--vulns", *VULNS, "--levels", *LEVELS,
            "--temperature", "0", "--logs-dir", str(tmp_path), *extra])
        generate.main()
        return tmp_path / "t0.0" / "r1"

    yield _run
    for s in servers:
        s.close()


def _logs(folder):
    out = {}
    for p in sorted(folder.glob("*.json")):
        vul_id, level, model = p.stem.split("__")
        out[(vul_id, level)] = json.loads(p.read_text())
    return out


def _assert_intact(log):
    """The log holds its own cell's answer, not another cell's."""
    assert log["status"] == "ok"
    assert log["seed"] == models.request_seed(log["vul_id"], log["level"], MODEL, 1)
    assert f"prompt={_digest(log['prompt'])}" in log["response"]
    assert f"seed={log['seed']}" in log["response"]
    assert f"/* {log['vul_id']} */" in log["prompt"]


def _no_temp_files(folder):
    assert [p.name for p in folder.rglob("*") if p.is_file() and p.suffix != ".json"] == []


# ── concurrency keeps every cell, once, intact ─────────────────────────────

def test_concurrency_logs_every_cell_once_and_intact(run):
    fake = FakeVLLM()
    folder = run(fake, "--concurrency", "4")
    logs = _logs(folder)
    assert set(logs) == CELLS
    for log in logs.values():
        _assert_intact(log)
        assert log["concurrency"] == 4
    seeds = [s for s, _ in fake.requests]
    assert len(seeds) == len(CELLS) == len(set(seeds))      # nothing requested twice
    assert fake.max_in_flight == 4                          # batched, and never more than 4
    _no_temp_files(folder)


def test_the_default_runs_one_cell_at_a_time(run):
    fake = FakeVLLM(delay=0.05)
    logs = _logs(run(fake))
    assert set(logs) == CELLS
    assert fake.max_in_flight == 1
    assert {log["concurrency"] for log in logs.values()} == {1}
    # in order, as before: vuln by vuln, level by level
    order = [(v, lv) for v in VULNS for lv in LEVELS]
    assert [s for s, _ in fake.requests] == [
        models.request_seed(v, lv, MODEL, 1) for v, lv in order]


def test_more_workers_than_cells_is_fine(run):
    fake = FakeVLLM(delay=0.05)
    logs = _logs(run(fake, "--concurrency", "64"))
    assert set(logs) == CELLS and len(fake.requests) == len(CELLS)


def test_a_cell_named_twice_is_requested_once(run):
    fake = FakeVLLM(delay=0.05)
    run_folder = run(fake, "--concurrency", "4", "--vulns", "VUL4J-1", "VUL4J-1",
                     "--levels", "L1", "L1")
    assert len(fake.requests) == 1
    assert set(_logs(run_folder)) == {("VUL4J-1", "L1")}


# ── stopping and resuming ──────────────────────────────────────────────────

def test_a_rejected_temperature_stops_new_requests_and_resuming_finishes(run):
    # The 10th request is refused. The three requests in flight beside it finish
    # and are logged; nothing new is sent after it.
    first = FakeVLLM(reject_on=10)
    with pytest.raises(SystemExit) as e:
        run(first, "--concurrency", "4")
    assert "rejected temperature" in str(e.value)
    assert len(first.requests) <= 10 + 3
    folder = Path(generate.LOGS_DIR)
    logged = _logs(folder)
    refused_seed = first.requests[9][0]
    assert len(logged) == len(first.requests) - 1           # all but the refused cell
    assert refused_seed not in {log["seed"] for log in logged.values()}
    _no_temp_files(folder)

    # Resume: only the cells without a log are requested, each once.
    second = FakeVLLM()
    run(second, "--concurrency", "4")
    resumed = {s for s, _ in second.requests}
    assert len(second.requests) == len(resumed) == len(CELLS) - len(logged)
    assert resumed.isdisjoint(log["seed"] for log in logged.values())
    final = _logs(folder)
    assert set(final) == CELLS
    for log in final.values():
        _assert_intact(log)
    _no_temp_files(folder)


def test_resuming_after_a_kill_redoes_only_what_is_missing_or_broken(run, tmp_path):
    folder = tmp_path / "t0.0" / "r1"
    first = FakeVLLM(delay=0.05)
    run(first, "--concurrency", "4")
    # What a killed run, or an older non-atomic write, could leave behind:
    gone = folder / f"VUL4J-1__L1__{MODEL}.json"
    gone.unlink()                                               # never written
    torn = folder / f"VUL4J-2__L2__{MODEL}.json"
    torn.write_text(torn.read_text()[:200])                     # cut off mid-write
    failed = folder / f"VUL4J-3__L3a__{MODEL}.json"
    failed.write_text(json.dumps({**json.loads(failed.read_text()), "status": "error"}))
    (folder / f".VUL4J-4__L1__{MODEL}.json.123.456.tmp").write_text("{")   # stray temp
    untouched = {p.name: p.read_text() for p in folder.glob("*.json")
                 if p.name not in (torn.name, failed.name)}

    second = FakeVLLM(delay=0.05)
    run(second, "--concurrency", "4")
    redone = [("VUL4J-1", "L1"), ("VUL4J-2", "L2"), ("VUL4J-3", "L3a")]
    assert sorted(s for s, _ in second.requests) == sorted(
        models.request_seed(v, lv, MODEL, 1) for v, lv in redone)
    final = _logs(folder)
    assert set(final) == CELLS
    for log in final.values():
        _assert_intact(log)
    for name, text in untouched.items():                        # ok logs are left alone
        assert (folder / name).read_text() == text


# ── the pieces ─────────────────────────────────────────────────────────────

def test_a_failed_write_leaves_the_old_log_and_no_temp_file(tmp_path, monkeypatch):
    monkeypatch.setattr(generate, "LOGS_DIR", generate.LOGS_DIR)
    monkeypatch.setattr(generate, "PATCHEVAL_LOGS_DIR", generate.PATCHEVAL_LOGS_DIR)
    generate.set_logs_dir(tmp_path)
    generate.write_log("VUL4J-1", "L1", MODEL, {"status": "ok", "n": 1})
    path = generate.log_path_for("VUL4J-1", "L1", MODEL)

    def boom(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(generate.os, "replace", boom)
    with pytest.raises(OSError):
        generate.write_log("VUL4J-1", "L1", MODEL, {"status": "ok", "n": 2})
    assert json.loads(path.read_text()) == {"status": "ok", "n": 1}
    assert [p.name for p in tmp_path.iterdir() if p.is_file()] == [path.name]


@pytest.mark.parametrize("value", ["0", "-1"])
def test_concurrency_must_be_positive(monkeypatch, value):
    monkeypatch.setattr(sys, "argv", ["generate.py", "--dry-run", "--temperature", "0",
                                      "--concurrency", value])
    with pytest.raises(SystemExit) as e:
        generate.main()
    assert e.value.code == 2


def test_threads_share_one_client(monkeypatch):
    monkeypatch.setattr(models, "_clients", {})
    made = []

    def make():
        time.sleep(0.05)                # widen the race the lock closes
        made.append(object())
        return made[-1]
    got = []
    threads = [threading.Thread(target=lambda: got.append(models._client("x", make)))
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(made) == 1 and all(g is made[0] for g in got)
