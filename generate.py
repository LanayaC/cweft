"""
Patch generation loop.

For each (vulnerability × prompt_level × model) cell:
  1. Build the prompt from vuln_data + schemas + prompts
  2. Call the model via models.call_model()
  3. Save a JSON log to logs/<vul_id>__<level>__<model>.json
     (PatchEval cells: logs/patcheval/<CVE-ID>__<level>__<model>.json)

Resumable: cells with an existing log file are skipped on re-run.
Idempotent: re-running is free; no re-billing for completed cells.

Usage:
    python generate.py                     # run everything (Vul4J)
    python generate.py --models claude     # only one model
    python generate.py --vulns VUL4J-1     # only one vuln
    python generate.py --levels L1 L2      # only two levels
    python generate.py --dataset patcheval # the 109 PatchEval entries (no Docker)
    python generate.py --dataset all       # Vul4J then PatchEval
    python generate.py --dry-run           # print plan, do nothing
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import (
    DATASETS, LOGS_DIR, MODELS, PATCHEVAL_LOGS_DIR, PROMPT_LEVELS,
)
from models import call_model
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


def cell_already_done(vul_id: str, level: str, model_key: str) -> bool:
    """A cell is done iff its log file exists AND records a successful call."""
    p = log_path_for(vul_id, level, model_key)
    if not p.exists():
        return False
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        return False
    return data.get("status") == "ok"


def write_log(vul_id: str, level: str, model_key: str, record: dict) -> None:
    p = log_path_for(vul_id, level, model_key)
    p.write_text(json.dumps(record, indent=2))


# ──────────────────────────────────────────────────────────────────────
# Single-cell generation with retry
# ──────────────────────────────────────────────────────────────────────

def run_cell(
    payload: dict,
    level: str,
    model_key: str,
    max_attempts: int = 3,
    base_backoff_s: float = 4.0,
) -> dict:
    """
    Build prompt, call model with retry, return a result dict to be logged.
    Never raises — failures are recorded with status=error.
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

    base_record = {
        "vul_id":       payload["vul_id"],
        "cve_id":       payload["cve_id"],
        "cwe_id":       payload["cwe_id"],
        "cwe_name":     payload["cwe_name"],
        "primary_file": payload["primary_file"],
        "level":        level,
        "model_key":    model_key,
        "model_id":     MODELS[model_key],
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
            response_text, usage = call_model(model_key, prompt, language=language)
            return {
                **base_record,
                "status":   "ok",
                "response": response_text,
                "usage":    usage,
                "attempts": attempt,
            }
        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            if attempt < max_attempts:
                sleep_s = base_backoff_s * (2 ** (attempt - 1))
                print(f"      ⚠ attempt {attempt} failed ({last_error}); retrying in {sleep_s:.0f}s")
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
        p["repair_prose"]  = get_prose(p["cwe_id"])
        p["repair_schema"] = get_schema(p["cwe_id"])
        _payload_cache[vul_id] = p
        return p
    except Exception as e:
        print(f"  ✗ {vul_id}: payload build failed: {type(e).__name__}: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Generate LLM patches for CWEFT")
    ap.add_argument("--models", nargs="+", choices=list(MODELS), default=list(MODELS))
    ap.add_argument("--levels", nargs="+", choices=PROMPT_LEVELS, default=PROMPT_LEVELS)
    ap.add_argument("--dataset", choices=list(DATASETS), default="vul4j",
                    help="Which vulns to run when --vulns is not given (default: vul4j)")
    ap.add_argument("--vulns",  nargs="+", default=None,
                    help="Explicit vul_ids (VUL4J-N or PatchEval CVE ids); overrides --dataset")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.vulns is None:
        args.vulns = DATASETS[args.dataset]

    cells = [
        (vul_id, level, model_key)
        for vul_id in args.vulns
        for level in args.levels
        for model_key in args.models
    ]

    total = len(cells)
    pending = [c for c in cells if not cell_already_done(*c)]
    skipped = total - len(pending)

    print(f"Plan: {total} cells  |  already done: {skipped}  |  to run: {len(pending)}")
    print(f"Models: {args.models}")
    print(f"Levels: {args.levels}")
    print(f"Vulns:  {len(args.vulns)}")
    print()

    if args.dry_run:
        print("Dry run — exiting before any API calls.")
        return

    if not pending:
        print("Nothing to do. All cells already have ok logs.")
        return

    started_at = time.time()
    ok_count = 0
    err_count = 0

    for i, (vul_id, level, model_key) in enumerate(pending, start=1):
        prefix = f"[{i}/{len(pending)}]"
        print(f"{prefix} {vul_id}  {level}  {model_key}", end="  ... ", flush=True)

        payload = payload_for(vul_id)
        if payload is None:
            write_log(vul_id, level, model_key, {
                "vul_id": vul_id, "level": level, "model_key": model_key,
                "status": "error", "error": "payload build failed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            err_count += 1
            continue

        record = run_cell(payload, level, model_key)
        write_log(vul_id, level, model_key, record)

        if record["status"] == "ok":
            ok_count += 1
            u = record["usage"]
            print(f"ok  ({u['latency_s']:.1f}s  in={u['input_tokens']} out={u['output_tokens']})")
        else:
            err_count += 1
            print(f"ERROR ({record['error']})")

    elapsed = time.time() - started_at
    print()
    print(f"Done in {elapsed/60:.1f} min  |  ok={ok_count}  error={err_count}")


if __name__ == "__main__":
    main()