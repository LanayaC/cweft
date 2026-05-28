"""
Patch evaluation loop.

Reads each generation log, applies the patched file in a fresh checkout,
compiles and tests it in the container, and classifies the result as
L0/L1/L2/L3. Resumable: cells already in results.csv are skipped.

    python evaluate.py                     # all logs
    python evaluate.py --models claude     # one model
    python evaluate.py --vulns VUL4J-1     # one vuln
    python evaluate.py --levels L1 L2      # some levels
    python evaluate.py --limit 5           # smoke test
"""

import argparse
import csv
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from config import (
    CONTAINER_NAME, CONTAINER_WORK_DIR, DOCKER_EXEC_TIMEOUT,
    LOGS_DIR, RESULTS_DIR,
)
from vuln_data import get_vuln_payload, ensure_checkout, checkout_dir


RESULTS_CSV = RESULTS_DIR / "results.csv"

CSV_FIELDS = [
    "vul_id", "cve_id", "cwe_id", "cwe_name",
    "level", "model_key", "model_id",
    "compiled", "pov_passed", "regressions",
    "trust_level",
    "compile_log_chars", "test_log_chars",
    "error", "timestamp",
]


def _docker_exec(cmd: List[str], check: bool = False, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    full = ["docker", "exec", CONTAINER_NAME] + cmd
    return subprocess.run(
        full, check=check, capture_output=True, text=True,
        timeout=timeout or DOCKER_EXEC_TIMEOUT,
    )


def _docker_write_file(container_path: str, content: str) -> None:
    # Pipe via stdin to dodge argument-size and quoting limits.
    proc = subprocess.run(
        ["docker", "exec", "-i", CONTAINER_NAME, "tee", container_path],
        input=content, text=True, capture_output=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to write {container_path}: {proc.stderr}")


def fresh_checkout(vul_id: str) -> str:
    # Force a clean checkout so a prior patch can't leak into this run.
    return ensure_checkout(vul_id, force=True)


def run_compile(workdir: str) -> Tuple[bool, str]:
    res = _docker_exec(["vul4j", "compile", "-d", workdir])
    wrapper_log = (res.stdout or "") + "\n--- stderr ---\n" + (res.stderr or "")

    maven_log = ""
    try:
        cat = _docker_exec(["cat", f"{workdir}/VUL4J/compile.log"], check=False)
        if cat.returncode == 0:
            maven_log = cat.stdout
    except Exception:
        pass

    log = wrapper_log + "\n--- maven log ---\n" + maven_log
    success = (res.returncode == 0) and ("BUILD FAILURE" not in log)
    return success, log


def run_tests(workdir: str) -> Tuple[bool, str, Optional[Dict]]:
    res = _docker_exec(["vul4j", "test", "-d", workdir])
    wrapper_log = (res.stdout or "") + "\n--- stderr ---\n" + (res.stderr or "")

    maven_log = ""
    try:
        cat = _docker_exec(["cat", f"{workdir}/VUL4J/testing.log"], check=False)
        if cat.returncode == 0:
            maven_log = cat.stdout
    except Exception:
        pass

    log = wrapper_log + "\n--- maven test log ---\n" + maven_log

    parsed = None
    try:
        cat = _docker_exec(["cat", f"{workdir}/VUL4J/testing_results.json"], check=False)
        if cat.returncode == 0 and cat.stdout.strip():
            parsed = json.loads(cat.stdout)
    except Exception:
        pass

    return True, log, parsed


def classify(
    compiled: bool,
    test_results: Optional[Dict],
    pov_tests: Set[str],
) -> Tuple[str, Optional[bool], Optional[List[str]]]:
    """
    Map a compile/test outcome onto a trust level.

    L0 no compile, L1 compiles but PoV still fails, L2 PoV passes with
    regressions, L3 PoV passes and everything else passes too.

    A PoV entry can be "Class#method" or just "Class" (when the original
    test_cmd named the whole class), so we match at either granularity.
    """
    if not compiled:
        return "L0", None, None

    if test_results is None:
        return "L1", None, None

    tests_block = test_results.get("tests", test_results)
    failing = tests_block.get("failures") or tests_block.get("failing_tests") or []

    failing_names = {
        f"{t.get('test_class','')}#{t.get('test_method','')}"
        for t in failing
    }

    pov_classes = {p for p in pov_tests if "#" not in p}
    pov_class_methods = {p for p in pov_tests if "#" in p}

    def is_pov(failing_name: str) -> bool:
        if failing_name in pov_class_methods:
            return True
        cls = failing_name.split("#", 1)[0]
        return cls in pov_classes

    pov_still_failing = {f for f in failing_names if is_pov(f)}
    regressions = failing_names - pov_still_failing
    pov_passed = len(pov_still_failing) == 0

    if not pov_passed:
        return "L1", False, sorted(regressions) if regressions else None
    elif regressions:
        return "L2", True, sorted(regressions)
    else:
        return "L3", True, []


def evaluate_log(log_path: Path) -> Dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        log = json.loads(log_path.read_text())
    except Exception as e:
        return _error_row(log_path, timestamp, f"log read failed: {e}")

    if log.get("status") != "ok":
        return _error_row(log_path, timestamp, "generation status != ok", log)

    vul_id = log["vul_id"]
    level = log["level"]
    model_key = log["model_key"]
    response = log.get("response", "")
    primary_file = log["primary_file"]

    try:
        payload = get_vuln_payload(vul_id)
    except Exception as e:
        return _error_row(log_path, timestamp, f"payload rebuild failed: {e}", log)

    pov_tests = set(payload.get("failing_tests", []))

    try:
        workdir = fresh_checkout(vul_id)
    except subprocess.TimeoutExpired:
        return _error_row(log_path, timestamp, "checkout timed out", log)
    except Exception as e:
        return _error_row(log_path, timestamp, f"checkout failed: {e}", log)

    target_path = f"{workdir}/{primary_file}"
    try:
        _docker_write_file(target_path, response)
    except Exception as e:
        return _error_row(log_path, timestamp, f"file write failed: {e}", log)

    try:
        compiled, compile_log = run_compile(workdir)
    except subprocess.TimeoutExpired:
        return _error_row(log_path, timestamp, "compile timed out", log)
    except Exception as e:
        return _error_row(log_path, timestamp, f"compile crashed: {e}", log)

    test_log = ""
    test_results = None
    if compiled:
        try:
            _, test_log, test_results = run_tests(workdir)
        except subprocess.TimeoutExpired:
            test_log = "TIMEOUT during testing"
        except Exception as e:
            test_log = f"test crashed: {e}"

    trust, pov_passed, regressions = classify(compiled, test_results, pov_tests)

    return {
        "vul_id":            vul_id,
        "cve_id":            log.get("cve_id", ""),
        "cwe_id":            log.get("cwe_id", ""),
        "cwe_name":          log.get("cwe_name", ""),
        "level":             level,
        "model_key":         model_key,
        "model_id":          log.get("model_id", ""),
        "compiled":          compiled,
        "pov_passed":        pov_passed if pov_passed is not None else "",
        "regressions":       ";".join(regressions) if regressions else "",
        "trust_level":       trust,
        "compile_log_chars": len(compile_log),
        "test_log_chars":    len(test_log),
        "error":             "",
        "timestamp":         timestamp,
    }


def _error_row(log_path: Path, timestamp: str, error: str, log: Optional[Dict] = None) -> Dict:
    log = log or {}
    return {
        "vul_id":            log.get("vul_id", _parse_vul_id(log_path)),
        "cve_id":            log.get("cve_id", ""),
        "cwe_id":            log.get("cwe_id", ""),
        "cwe_name":          log.get("cwe_name", ""),
        "level":             log.get("level", _parse_level(log_path)),
        "model_key":         log.get("model_key", _parse_model(log_path)),
        "model_id":          log.get("model_id", ""),
        "compiled":          "",
        "pov_passed":        "",
        "regressions":       "",
        "trust_level":       "ERROR",
        "compile_log_chars": 0,
        "test_log_chars":    0,
        "error":             error,
        "timestamp":         timestamp,
    }


def _parse_vul_id(p: Path) -> str:
    m = re.match(r"(VUL4J-\d+)__", p.name)
    return m.group(1) if m else ""


def _parse_level(p: Path) -> str:
    m = re.match(r"VUL4J-\d+__(L\d[ab]?)__", p.name)
    return m.group(1) if m else ""


def _parse_model(p: Path) -> str:
    m = re.match(r"VUL4J-\d+__L\d[ab]?__(\w+)\.json", p.name)
    return m.group(1) if m else ""


def load_done_cells() -> Set[Tuple[str, str, str]]:
    if not RESULTS_CSV.exists():
        return set()
    done = set()
    with RESULTS_CSV.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            done.add((row["vul_id"], row["level"], row["model_key"]))
    return done


def append_row(row: Dict) -> None:
    write_header = not RESULTS_CSV.exists()
    with RESULTS_CSV.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def main():
    ap = argparse.ArgumentParser(description="Evaluate generated CWEFT patches")
    ap.add_argument("--models", nargs="+", default=None,
                    help="Subset of models (default: all in logs)")
    ap.add_argument("--levels", nargs="+", default=None,
                    help="Subset of levels (default: all in logs)")
    ap.add_argument("--vulns",  nargs="+", default=None,
                    help="Subset of vuln IDs (default: all in logs)")
    ap.add_argument("--limit",  type=int, default=None,
                    help="Cap the number of cells to evaluate (smoke test)")
    args = ap.parse_args()

    all_logs = sorted(LOGS_DIR.glob("*.json"))
    if not all_logs:
        print("No logs found in", LOGS_DIR)
        sys.exit(1)

    def keep(p: Path) -> bool:
        v, l, m = _parse_vul_id(p), _parse_level(p), _parse_model(p)
        if args.vulns  and v not in args.vulns:  return False
        if args.levels and l not in args.levels: return False
        if args.models and m not in args.models: return False
        return True

    candidate_logs = [p for p in all_logs if keep(p)]

    done = load_done_cells()
    pending = [
        p for p in candidate_logs
        if (_parse_vul_id(p), _parse_level(p), _parse_model(p)) not in done
    ]

    if args.limit is not None:
        pending = pending[: args.limit]

    already = done & {(_parse_vul_id(p), _parse_level(p), _parse_model(p)) for p in candidate_logs}
    print(f"Total logs:    {len(all_logs)}")
    print(f"Candidates:    {len(candidate_logs)}")
    print(f"Already done:  {len(already)}")
    print(f"To evaluate:   {len(pending)}")
    print(f"Results CSV:   {RESULTS_CSV}")
    print()

    if not pending:
        print("Nothing to evaluate. All requested cells are already in results.csv.")
        return

    counts = {"L0": 0, "L1": 0, "L2": 0, "L3": 0, "ERROR": 0}

    for i, log_path in enumerate(pending, start=1):
        vul = _parse_vul_id(log_path)
        lvl = _parse_level(log_path)
        mdl = _parse_model(log_path)
        print(f"[{i}/{len(pending)}] {vul}  {lvl}  {mdl}", end="  ... ", flush=True)

        try:
            row = evaluate_log(log_path)
        except Exception as e:
            row = _error_row(
                log_path, datetime.now(timezone.utc).isoformat(),
                f"unhandled: {type(e).__name__}: {e}",
            )

        append_row(row)
        counts[row["trust_level"]] = counts.get(row["trust_level"], 0) + 1
        tag = row["trust_level"]
        if tag == "ERROR":
            print(f"{tag}  ({row['error']})")
        elif tag in ("L2", "L3"):
            print(f"{tag}  pov_passed")
        else:
            print(tag)

    print()
    print("Summary:")
    for k in ("L0", "L1", "L2", "L3", "ERROR"):
        print(f"  {k}: {counts.get(k, 0)}")


if __name__ == "__main__":
    main()
