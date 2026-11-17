"""
Patch generation loop.

For each (vulnerability × prompt_level × model) cell:
  1. Build the prompt from vuln_data + schemas + prompts
  2. Call the model via models.call_model()
  3. Save a JSON log to logs/t<temperature>/r<repetition>/<vul_id>__<level>__<model>.json
     (PatchEval cells: in a patcheval/ subfolder of that)

Resumable: cells with an existing log file are skipped on re-run.
Idempotent: re-running is free; no re-billing for completed cells.

Usage:
    python generate.py --temperature 0.5   # run everything (Vul4J), into logs/t0.5/r1/

  Every command takes --temperature (0, 0.5 or 1.0); these options add to it:
    --repetition 2                         # the second repetition, logs/t0.5/r2/
    --models claude                        # only one model
    --vulns VUL4J-1                        # only one vuln
    --levels L1 L2                         # only two levels
    --dataset patcheval                    # the 109 PatchEval entries (no Docker)
    --dataset all                          # Vul4J then PatchEval
    --dry-run                              # print plan, do nothing
    --logs-dir logs/plumbing_test          # logs/plumbing_test/t0.5/r1/ instead
    --concurrency 8                        # keep up to 8 requests in flight (default 1)

Concurrency: with --concurrency N > 1, up to N cells are generated at once, so
a vLLM server can batch them. Every cell still gets its own log, written
atomically, and records the concurrency it ran under. The default, 1, runs
cells one after another for every provider; cloud models run concurrently only
when --concurrency is given.
"""

import argparse
import json
import os
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import (
    DATASETS, LOGS_DIR, MODELS, PATCHEVAL_LOGS_DIR, PROMPT_LEVELS, TEMPERATURES,
    VLLM_MODELS, run_subdir,
)
import capcheck
from models import (PromptExceedsWindow, TemperatureRejected, call_model, request_seed,
                    vllm_placeholders)
from prompts import build_prompt
from schemas import get_prose, get_schema
from vuln_data import get_vuln_payload


# ──────────────────────────────────────────────────────────────────────
# Per-cell I/O
# ──────────────────────────────────────────────────────────────────────

def log_path_for(vul_id: str, level: str, model_key: str) -> Path:
    # Vul4J logs stay where evaluate.py looks; PatchEval logs go to a
    # subdirectory it does not glob until it has a PatchEval backend.
    logs_dir = LOGS_DIR if vul_id.startswith("VUL4J-") else PATCHEVAL_LOGS_DIR
    return logs_dir / f"{vul_id}__{level}__{model_key}.json"


def set_logs_dir(path: Path) -> None:
    """Point log_path_for at another folder: Vul4J logs in it, PatchEval in patcheval/."""
    global LOGS_DIR, PATCHEVAL_LOGS_DIR
    LOGS_DIR = path.resolve()
    PATCHEVAL_LOGS_DIR = LOGS_DIR / "patcheval"
    PATCHEVAL_LOGS_DIR.mkdir(parents=True, exist_ok=True)


def cell_already_done(vul_id: str, level: str, model_key: str,
                      temperature: float, repetition: int) -> bool:
    """
    A cell is done iff its log file exists AND records a successful call. A
    successful log from other settings stops the run: the folder is wrong, and
    counting it as done would leave results from the wrong run in this one.
    """
    p = log_path_for(vul_id, level, model_key)
    if not p.exists():
        return False
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        return False
    if data.get("status") != "ok":
        return False
    found = (data.get("temperature"), data.get("repetition"))
    if found != (temperature, repetition):
        sys.exit(f"{p} records temperature, repetition = {found}, but this run is "
                 f"({temperature}, {repetition}). Move that log out of this folder.")
    return True


def write_log(vul_id: str, level: str, model_key: str, record: dict) -> None:
    """
    Write the cell's log atomically: to a temporary file beside it, then renamed
    over it. A run killed mid-write leaves either no log or a whole one, never a
    partial file that resuming would have to guess about. The temporary name
    does not end in .json, so nothing that globs the logs picks it up.
    """
    p = log_path_for(vul_id, level, model_key)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(json.dumps(record, indent=2))
        os.replace(tmp, p)
    finally:
        tmp.unlink(missing_ok=True)


# ──────────────────────────────────────────────────────────────────────
# Single-cell generation with retry
# ──────────────────────────────────────────────────────────────────────

def run_cell(
    payload: dict,
    level: str,
    model_key: str,
    *,
    temperature: float,
    repetition: int,
    concurrency: int = 1,
    max_attempts: int = 3,
    base_backoff_s: float = 4.0,
) -> dict:
    """
    Build prompt, call model with retry, return a result dict to be logged.
    Failures are recorded with status=error, except a temperature the provider
    rejects: TemperatureRejected reaches the caller, which stops the run.
    `concurrency` is only recorded: how many cells the run kept in flight.
    """
    # Vul4J payloads carry no language key and so get the Java default.
    language = payload.get("language", "Java")
    prompt = build_prompt(
        level=level,
        vuln_info=payload,
        file_path=payload["primary_file"],
        file_content=payload["primary_content"],
        language=language,
    )
    seed = (request_seed(payload["vul_id"], level, model_key, repetition)
            if model_key in VLLM_MODELS else None)

    base_record = {
        "vul_id":       payload["vul_id"],
        "cve_id":       payload["cve_id"],
        "cwe_id":       payload["cwe_id"],
        "cwe_name":     payload["cwe_name"],
        "primary_file": payload["primary_file"],
        "level":        level,
        "model_key":    model_key,
        "model_id":     MODELS[model_key],
        "temperature":  temperature,
        "repetition":   repetition,
        "seed":         seed,
        # Batching can change floating-point results, so a cell generated
        # alongside others may differ from one generated alone.
        "concurrency":  concurrency,
        "prompt_chars": len(prompt),
        "prompt":       prompt,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        # PatchEval provenance; absent from Vul4J payloads, so Vul4J
        # records keep exactly their published fields.
        **{k: payload[k] for k in ("dataset", "language", "docker_image", "sha256")
           if k in payload},
    }

    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            response_text, usage = call_model(model_key, prompt, language=language,
                                              temperature=temperature, seed=seed)
            sampling_params = usage.pop("sampling_params", None)
            record = {
                **base_record,
                "sampling_params": sampling_params,
                "status":      "ok",
                "response":    response_text,
                "usage":       usage,
                "truncated":   bool(usage.get("truncated")),
                "stop_reason": usage.get("stop_reason", ""),
                "attempts":    attempt,
            }
            if record["truncated"]:
                # The file is cut off mid-write, so it cannot compile or parse
                # and will score L0 for a reason that is not the model's repair.
                # ASCII only, and never fatal: this print sits inside the retry
                # block, so a console that cannot render it would otherwise turn
                # a paid, successful call into three retries and an error row.
                try:
                    print(f"\n      !! TRUNCATED: {payload['vul_id']} {level} {model_key} "
                          f"stopped at the output cap (stop_reason="
                          f"{record['stop_reason']!r}, output_tokens="
                          f"{usage.get('output_tokens')}). Scores L0 for truncation, "
                          f"not for the patch.", flush=True)
                except Exception:
                    pass
            return record
        except PromptExceedsWindow as e:
            # Nothing was sent, and a retry would send the same prompt.
            return {
                **base_record,
                "status":   "skipped",
                "error":    f"prompt exceeds window: {e}",
                "attempts": attempt,
            }
        except TemperatureRejected:
            raise                # a retry would be refused too, and nothing gets logged
        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            if attempt < max_attempts:
                sleep_s = base_backoff_s * (2 ** (attempt - 1))
                # ASCII: a Windows console in cp1252 raises on "⚠", and
                # this line runs on the failure path, where a crash would take
                # the whole run down with it.
                print(f"      ! attempt {attempt} failed ({last_error}); retrying in {sleep_s:.0f}s")
                time.sleep(sleep_s)

    return {
        **base_record,
        "status":   "error",
        "error":    last_error,
        "attempts": max_attempts,
    }


# ──────────────────────────────────────────────────────────────────────
# Vuln payload caching (vuln_data does a docker exec per call)
# ──────────────────────────────────────────────────────────────────────

_payload_cache: dict = {}


def payload_for(vul_id: str) -> Optional[dict]:
    if vul_id in _payload_cache:
        return _payload_cache[vul_id]
    try:
        p = get_vuln_payload(vul_id)
        # Vul4J payloads carry no language key and so get the Java guidance.
        language = p.get("language", "Java")
        p["repair_prose"]  = get_prose(p["cwe_id"], language)
        p["repair_schema"] = get_schema(p["cwe_id"], language)
        _payload_cache[vul_id] = p
        return p
    except Exception as e:
        print(f"  x {vul_id}: payload build failed: {type(e).__name__}: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────
# Pre-flight cap check
# ──────────────────────────────────────────────────────────────────────

def cap_risks(cells, reasoning_reserve: int = capcheck.GPT_REASONING_RESERVE):
    """
    (risks, unknown) for these cells, calling no API.

    Sizes come from the payload each cell would be prompted with, through the
    same cache the run uses, so nothing is fetched twice. A vuln whose payload
    cannot be built (no container, say) is reported as unknown rather than
    guessed at.
    """
    file_chars, file_tokens, prompt_chars, unknown = {}, {}, {}, []
    for vul_id, level, model_key in cells:
        if vul_id not in file_chars and vul_id not in unknown:
            payload = payload_for(vul_id)
            if payload is None:
                unknown.append(vul_id)
            else:
                file_chars[vul_id] = len(payload["primary_content"])
                # PatchEval ships an exact cl100k count; prefer it over chars.
                if payload.get("token_count"):
                    file_tokens[vul_id] = payload["token_count"]
        if vul_id in file_chars:
            payload = payload_for(vul_id)
            prompt = build_prompt(
                level=level, vuln_info=payload, file_path=payload["primary_file"],
                file_content=payload["primary_content"],
                language=payload.get("language", "Java"))
            prompt_chars[(vul_id, level, model_key)] = len(prompt)
    return (capcheck.check_cells(cells, file_chars, prompt_chars, reasoning_reserve,
                                file_tokens),
            unknown)


# ──────────────────────────────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Generate LLM patches for CWEFT")
    ap.add_argument("--models", nargs="+", choices=list(MODELS), default=list(MODELS))
    ap.add_argument("--levels", nargs="+", choices=PROMPT_LEVELS, default=PROMPT_LEVELS)
    ap.add_argument("--temperature", type=float, choices=TEMPERATURES, required=True,
                    help="sent on every request")
    ap.add_argument("--repetition", type=int, default=1,
                    help="which repetition this is, from 1 (default 1); sets the vLLM seed")
    ap.add_argument("--dataset", choices=list(DATASETS), default="vul4j",
                    help="Which vulns to run when --vulns is not given (default: vul4j)")
    ap.add_argument("--vulns",  nargs="+", default=None,
                    help="Explicit vul_ids (VUL4J-N or PatchEval CVE ids); overrides --dataset")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--logs-dir", type=Path, default=None,
                    help="base folder instead of logs/; logs go to its "
                         "t<temperature>/r<repetition>/ (PatchEval cells to patcheval/ in "
                         "that), and cells are 'done' only if logged there")
    ap.add_argument("--check-caps", action="store_true",
                    help="report which cells risk truncation at the output cap, then exit "
                         "without calling any API")
    ap.add_argument("--reasoning-reserve", type=int, default=capcheck.GPT_REASONING_RESERVE,
                    help="tokens of GPT's budget assumed to go to reasoning "
                         f"(default {capcheck.GPT_REASONING_RESERVE})")
    ap.add_argument("--concurrency", type=int, default=1,
                    help="keep up to this many requests in flight at once, so a vLLM server "
                         "can batch them (default 1: one after another). Applies to every "
                         "model in the run, cloud ones included; each log records it")
    args = ap.parse_args()
    if args.repetition < 1:
        ap.error("--repetition must be at least 1")
    if args.concurrency < 1:
        ap.error("--concurrency must be at least 1")
    set_logs_dir((args.logs_dir or LOGS_DIR) / run_subdir(args.temperature, args.repetition))
    if args.vulns is None:
        args.vulns = DATASETS[args.dataset]

    # Each cell once, in order: a vuln or level named twice would otherwise be
    # requested twice, and with --concurrency both requests could be in flight.
    cells = list(dict.fromkeys(
        (vul_id, level, model_key)
        for vul_id in args.vulns
        for level in args.levels
        for model_key in args.models
    ))

    total = len(cells)
    pending = [c for c in cells if not cell_already_done(*c, args.temperature, args.repetition)]
    skipped = total - len(pending)

    print(f"Plan: {total} cells  |  already done: {skipped}  |  to run: {len(pending)}")
    print(f"Models: {args.models}")
    print(f"Levels: {args.levels}")
    print(f"Vulns:  {len(args.vulns)}")
    print(f"Sampling: temperature={args.temperature}  repetition={args.repetition}")
    print(f"Concurrency: {args.concurrency}")
    print(f"Logs:   {LOGS_DIR}")
    print()

    # Which of these cells cannot fit their file in the budget? Checked before
    # anything is spent, from the source file alone.
    to_check = cells if args.check_caps else pending
    risks, unknown = cap_risks(to_check, args.reasoning_reserve)
    if args.check_caps:
        print(capcheck.report(risks, len(to_check), unknown))
        return
    print(capcheck.summary_line(risks, len(to_check), len(set(unknown))))
    print()

    if args.dry_run:
        print("Dry run - exiting before any API calls.")
        return

    if not pending:
        print("Nothing to do. All cells already have ok logs.")
        return

    unfilled = vllm_placeholders(args.models)
    if unfilled:
        sys.exit(f"No Hugging Face id yet for {', '.join(unfilled)}. Fill them in under "
                 f"VLLM_MODELS in config.py, or leave them out with --models.")

    started_at = time.time()
    counts, rejected = generate_cells(pending, temperature=args.temperature,
                                      repetition=args.repetition,
                                      concurrency=args.concurrency)
    if rejected is not None:
        sys.exit(f"Stopping: {rejected}\nNothing was logged for that cell. Leave this model "
                 f"out with --models, or choose a temperature it accepts.")

    elapsed = time.time() - started_at
    print()
    print(f"Done in {elapsed/60:.1f} min  |  ok={counts['ok']}  error={counts['error']}  "
          f"skipped={counts['skipped']}")


def _generate_one(vul_id: str, level: str, model_key: str, payload: dict, *,
                  temperature: float, repetition: int, concurrency: int) -> dict:
    """One cell, start to finish: generate, then write its log. Runs in a worker."""
    record = run_cell(payload, level, model_key, temperature=temperature,
                      repetition=repetition, concurrency=concurrency)
    write_log(vul_id, level, model_key, record)
    return record


def _outcome(record: dict) -> str:
    if record["status"] == "ok":
        u = record["usage"]
        return f"ok  ({u['latency_s']:.1f}s  in={u['input_tokens']} out={u['output_tokens']})"
    if record["status"] == "skipped":
        return f"SKIPPED ({record['error']})"
    return f"ERROR ({record['error']})"


def generate_cells(pending, *, temperature: float, repetition: int, concurrency: int = 1):
    """
    Generate every pending cell, keeping at most `concurrency` in flight.

    Returns ({"ok": n, "error": n, "skipped": n}, rejected), where `rejected`
    is the TemperatureRejected that stopped the run, or None.

    Cells are handed out in order, one more each time one finishes, so nothing
    waits in a queue: once a provider rejects the temperature, no further
    request is sent. Requests already in flight are allowed to finish and are
    logged, since they were already paid for. Each worker writes its own
    cell's log as soon as the cell is done, so a run stopped at any point
    leaves only whole logs, and resuming redoes just the cells without one.
    With concurrency 1 this is the plain sequential loop, one cell at a time.
    """
    counts = {"ok": 0, "error": 0, "skipped": 0}
    rejected = None
    total = len(pending)
    finished = 0
    sequential = concurrency == 1

    def report(cell, record):
        nonlocal finished
        finished += 1
        counts["ok" if record["status"] == "ok" else
               "skipped" if record["status"] == "skipped" else "error"] += 1
        if sequential:          # the "[i/n] cell ... " half was printed at submit
            print(_outcome(record), flush=True)
        else:
            print(f"[{finished}/{total}] {cell[0]}  {cell[1]}  {cell[2]}  "
                  f"{_outcome(record)}", flush=True)

    queue = iter(enumerate(pending, start=1))
    in_flight = {}
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="cell") as pool:
        while True:
            # Top up to `concurrency` in flight, unless the run is stopping.
            while rejected is None and len(in_flight) < concurrency:
                nxt = next(queue, None)
                if nxt is None:
                    break
                i, (vul_id, level, model_key) = nxt
                if sequential:
                    print(f"[{i}/{total}] {vul_id}  {level}  {model_key}", end="  ... ",
                          flush=True)
                payload = payload_for(vul_id)
                if payload is None:
                    write_log(vul_id, level, model_key, {
                        "vul_id": vul_id, "level": level, "model_key": model_key,
                        "temperature": temperature, "repetition": repetition,
                        "concurrency": concurrency,
                        "status": "error", "error": "payload build failed",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    report((vul_id, level, model_key), {"status": "error",
                                                        "error": "payload build failed"})
                    continue
                future = pool.submit(_generate_one, vul_id, level, model_key, payload,
                                     temperature=temperature, repetition=repetition,
                                     concurrency=concurrency)
                in_flight[future] = (vul_id, level, model_key)
            if not in_flight:
                break
            done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
            for future in done:
                cell = in_flight.pop(future)
                try:
                    record = future.result()
                except TemperatureRejected as e:
                    print("STOPPED" if sequential else
                          f"STOPPED {cell[0]}  {cell[1]}  {cell[2]}: temperature rejected",
                          flush=True)
                    rejected = rejected or e
                    continue
                report(cell, record)
    return counts, rejected


if __name__ == "__main__":
    main()