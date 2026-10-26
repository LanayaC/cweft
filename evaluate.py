"""
Patch evaluation loop.

Reads each generation log, applies the patched file in a fresh checkout,
compiles and tests it in the container, and classifies the result as
L0/L1/L2/L3. Resumable: cells already in results/results.csv are skipped.
That file is for new runs; the published 504 are frozen in results/published/.

    python evaluate.py                     # all logs
    python evaluate.py --models claude     # one model
    python evaluate.py --vulns VUL4J-1     # one vuln
    python evaluate.py --levels L1 L2      # some levels
    python evaluate.py --limit 5           # smoke test
    python evaluate.py --dataset patcheval # PatchEval logs (patcheval_eval.py)
    python evaluate.py --logs-dir logs/plumbing_test --results-dir results/plumbing_test
    python evaluate.py --oracle            # original -> L1, reference fix -> L3

Grading follows the PatchEval rules (vul4j_grading.py): the PoV is Vul4J's own
failing_tests, all of which must run and pass, and regressions are counted
only among the tests that passed in all three reference-fix runs recorded in
data/vul4j/baseline.json (vul4j_baseline.py). An entry not in that baseline,
or not "ok" there, is refused rather than graded.
"""

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from config import (
    CONTAINER_NAME, CONTAINER_WORK_DIR, DOCKER_EXEC_TIMEOUT,
    LOGS_DIR, RESULTS_DIR, SUBSET,
)
import vul4j_baseline as vb
import vul4j_grading as vg
from vuln_data import get_vuln_payload, ensure_checkout, checkout_dir


RESULTS_CSV = RESULTS_DIR / "results.csv"

CSV_FIELDS = [
    "vul_id", "cve_id", "cwe_id", "cwe_name",
    "level", "model_key", "model_id",
    "compiled", "pov_passed", "judged_set_size", "tests_run",
    "regressions", "n_regressions", "flaky_excluded",
    "trust_level",
    "truncated", "stop_reason",
    "grader", "error", "timestamp",
]


def _docker_exec(cmd: List[str], check: bool = False, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    # vul4j_baseline.docker_run enforces the timeout inside the container, so
    # a timed-out compile or test run is really stopped, child processes too.
    res = vb.docker_run(cmd, timeout or DOCKER_EXEC_TIMEOUT)
    if check and res.returncode != 0:
        raise subprocess.CalledProcessError(res.returncode, cmd, res.stdout, res.stderr)
    return res


def _docker_write_file(container_path: str, content: str) -> None:
    # Pipe via stdin to dodge argument-size and quoting limits.
    proc = vb.docker_run(["tee", container_path], 60, input_text=content)
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to write {container_path}: {proc.stderr}")


def fresh_checkout(vul_id: str) -> str:
    # Force a clean checkout so a prior patch can't leak into this run.
    return ensure_checkout(vul_id, force=True)


def restore_primary(workdir: str, primary_file: str) -> None:
    # Put the vulnerable file back once a patch has been scored. generate.py
    # reads the primary file from this same checkout, so a patch left on disk
    # would become the "vulnerable" file in the next prompt. `checkout --`
    # restores from the index, where `vul4j checkout` staged the original.
    proc = _docker_exec(["git", "-C", workdir, "checkout", "--", primary_file])
    if proc.returncode != 0:
        print(f"  WARNING: could not restore {workdir}/{primary_file}: "
              f"{proc.stderr.strip()}", file=sys.stderr)


def run_compile(workdir: str) -> Tuple[bool, str]:
    res = _docker_exec(["vul4j", "compile", "-d", workdir], timeout=vb.COMPILE_TIMEOUT)
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


REFUSED = "refused"
ERROR = "ERROR"
GRADER = "vul4j-baseline/1"

ORACLE_VULNERABLE = "oracle_vulnerable"
ORACLE_REFERENCE = "oracle_reference"
ORACLE_CSV_NAME = "oracle.csv"
ORACLE_FIELDS = CSV_FIELDS + ["expected", "as_expected"]


def load_baseline() -> Dict[str, Dict]:
    """data/vul4j/baseline.json's entries, or {} before it exists."""
    if not vb.BASELINE_PATH.exists():
        return {}
    return json.loads(vb.BASELINE_PATH.read_text(encoding="utf-8")).get("entries") or {}


def refusal(entry: Optional[Dict]) -> str:
    """Why this entry cannot be graded, or "" when it can."""
    if not entry:
        return "not in data/vul4j/baseline.json (run vul4j_baseline.py)"
    if entry.get("status") != vb.OK:
        return f"baseline status is {entry.get('status')!r}, not {vb.OK!r}"
    if not entry.get("pov"):
        return "baseline entry has no PoV tests"
    if not entry.get("judged"):
        return "baseline entry has no judged set"
    return ""


def classify(compiled: bool, first: Optional[Dict[str, str]],
             rerun: Optional[Dict[str, str]], entry: Dict) -> Dict:
    """
    The trust level from one graded run (and its rerun, if one was needed),
    by the rules in vul4j_grading: the PoV is the baseline's resolved PoV
    tests, all of which must run and pass; regressions are counted among the
    baseline's judged tests only.
    """
    out = {"pov_passed": None, "regressions": [], "flaky": [], "note": ""}
    if not compiled:
        return {**out, "trust": vg.L0}
    if not first:
        return {**out, "trust": vg.L1, "note": "vul4j test wrote no results"}
    pov_ok, note = vg.pov_outcome(entry["pov"], first)
    if not pov_ok:
        return {**out, "trust": vg.L1, "pov_passed": False, "note": note}
    regressions, flaky = vg.count_regressions(entry["judged"], first, rerun)
    return {**out, "trust": vg.trust_level(True, True, len(regressions)),
            "pov_passed": True, "regressions": regressions, "flaky": flaky}


def grade(vul_id: str, primary_file: str, apply: Callable[[str, str], None],
          entry: Optional[Dict]) -> Dict:
    """
    Grade one candidate: `apply(workdir, primary_file)` puts it into a fresh
    checkout; then compile, `vul4j test`, and classify against the baseline.
    A judged test that did not pass gets one more `vul4j test` before it counts.
    """
    result = {"trust": ERROR, "compiled": "", "pov_passed": None, "regressions": [],
              "flaky": [], "tests_run": "", "error": ""}
    why = refusal(entry)
    if why:
        return {**result, "trust": REFUSED, "error": why}
    try:
        workdir = fresh_checkout(vul_id)
        vb.make_offline(workdir)               # Maven resolves from the local repository only
    except Exception as e:
        return {**result, "error": f"checkout failed: {type(e).__name__}: {e}"}
    try:
        apply(workdir, primary_file)
        compiled, _ = run_compile(workdir)
        if not compiled:
            return {**result, "trust": vg.L0, "compiled": False}
        raw = vb.run_tests(workdir)
        first = vg.fold_results(raw) if raw else None
        decided = classify(True, first, None, entry)
        if decided["pov_passed"] and vg.needs_rerun(entry["judged"], first):
            second = vb.run_tests(workdir)
            decided = classify(True, first, vg.fold_results(second) if second else {}, entry)
        return {**result, "trust": decided["trust"], "compiled": True,
                "pov_passed": decided["pov_passed"], "regressions": decided["regressions"],
                "flaky": decided["flaky"], "tests_run": len(first or {}),
                "error": decided["note"]}
    except subprocess.TimeoutExpired as e:
        return {**result, "error": f"timed out: {' '.join(map(str, e.cmd))[-120:]}"}
    except Exception as e:
        return {**result, "error": f"{type(e).__name__}: {e}"}
    finally:
        # Whatever happened above, leave the checkout holding the vulnerable file.
        restore_primary(workdir, primary_file)


def _row(meta: Dict, graded: Dict, entry: Optional[Dict], timestamp: str) -> Dict:
    regressions = graded["regressions"] or []
    return {
        "vul_id":            meta.get("vul_id", ""),
        "cve_id":            meta.get("cve_id", ""),
        "cwe_id":            meta.get("cwe_id", ""),
        "cwe_name":          meta.get("cwe_name", ""),
        "level":             meta.get("level", ""),
        "model_key":         meta.get("model_key", ""),
        "model_id":          meta.get("model_id", ""),
        "compiled":          graded["compiled"],
        "pov_passed":        "" if graded["pov_passed"] is None else graded["pov_passed"],
        "judged_set_size":   (entry or {}).get("judged_count", ""),
        "tests_run":         graded["tests_run"],
        "regressions":       ";".join(regressions),
        "n_regressions":     len(regressions) if graded["pov_passed"] else "",
        "flaky_excluded":    ";".join(graded["flaky"] or []),
        "trust_level":       graded["trust"],
        "truncated":         bool(meta.get("truncated")),
        "stop_reason":       meta.get("stop_reason", ""),
        "grader":            GRADER,
        "error":             graded["error"],
        "timestamp":         timestamp,
    }


def evaluate_log(log_path: Path, baseline: Optional[Dict[str, Dict]] = None) -> Dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        log = json.loads(log_path.read_text(encoding="utf-8"))
    except Exception as e:
        return _error_row(log_path, timestamp, f"log read failed: {e}")
    if log.get("status") != "ok":
        return _error_row(log_path, timestamp, "generation status != ok", log)

    baseline = load_baseline() if baseline is None else baseline
    entry = baseline.get(log["vul_id"])
    response = log.get("response", "")

    def apply(workdir: str, primary_file: str) -> None:
        _docker_write_file(f"{workdir}/{primary_file}", response)

    graded = grade(log["vul_id"], log["primary_file"], apply, entry)
    return _row(log, graded, entry, timestamp)


def _error_row(log_path: Path, timestamp: str, error: str, log: Optional[Dict] = None) -> Dict:
    log = log or {}
    meta = {**log,
            "vul_id": log.get("vul_id", _parse_vul_id(log_path)),
            "level": log.get("level", _parse_level(log_path)),
            "model_key": log.get("model_key", _parse_model(log_path))}
    graded = {"trust": ERROR, "compiled": "", "pov_passed": None, "regressions": [],
              "flaky": [], "tests_run": "", "error": error}
    return _row(meta, graded, None, timestamp)


# ── Oracle: the original file must grade L1, the reference fix L3 ────────

def oracle(vul_ids: List[str], results_dir: Path) -> int:
    """
    Grade each entry's original vulnerable file (expected L1) and Vul4J's
    reference fix (expected L3) against the baseline. Appends to
    <results_dir>/oracle.csv, skipping cells already there, and writes
    oracle_summary.txt. Returns how many came out other than expected.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    path = results_dir / ORACLE_CSV_NAME
    done = set()
    if path.exists():
        with path.open(encoding="utf-8", newline="") as f:
            done = {(r["vul_id"], r["model_key"]) for r in csv.DictReader(f)}
    baseline = load_baseline()

    def keep_original(workdir: str, primary_file: str) -> None:
        pass                                    # the fresh checkout is the original

    def reference(workdir: str, primary_file: str) -> None:
        vb.apply_reference(workdir)

    cases = [(ORACLE_VULNERABLE, keep_original, vg.L1), (ORACLE_REFERENCE, reference, vg.L3)]
    total = len(vul_ids) * len(cases)
    i = 0
    for vul_id in vul_ids:
        payload = get_vuln_payload(vul_id)
        entry = baseline.get(vul_id)
        for model_key, apply, expected in cases:
            i += 1
            if (vul_id, model_key) in done:
                continue
            t0 = time.time()
            graded = grade(vul_id, payload["primary_file"], apply, entry)
            meta = {**payload, "level": "oracle", "model_key": model_key, "model_id": model_key}
            row = _row(meta, graded, entry, datetime.now(timezone.utc).isoformat())
            row["expected"] = expected
            row["as_expected"] = row["trust_level"] == expected
            new = not path.exists()
            with path.open("a", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=ORACLE_FIELDS)
                if new:
                    w.writeheader()
                w.writerow(row)
            print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] ({i}/{total}) "
                  f"{vul_id:10s} {model_key:18s} expected {expected} got {row['trust_level']:8s} "
                  f"{'OK' if row['as_expected'] else 'WRONG'}  "
                  f"({time.time() - t0:.0f}s) {row['regressions'][:80]} {row['error'][:80]}",
                  flush=True)

    with path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    wrong = [r for r in rows if r["as_expected"] != "True"]
    lines = [f"{len(rows)} oracle cells graded, {len(rows) - len(wrong)} as expected, "
             f"{len(wrong)} not."]
    for r in wrong:
        lines.append(f"  {r['vul_id']:10s} {r['model_key']:18s} expected {r['expected']} got "
                     f"{r['trust_level']}  {r['regressions'][:100]} {r['error'][:100]}")
    (results_dir / "oracle_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines), flush=True)
    return len(wrong)


def _parse_vul_id(p: Path) -> str:
    m = re.match(r"(VUL4J-\d+)__", p.name)
    return m.group(1) if m else ""


def _parse_level(p: Path) -> str:
    m = re.match(r"VUL4J-\d+__(L\d[ab]?)__", p.name)
    return m.group(1) if m else ""


def _parse_model(p: Path) -> str:
    m = re.match(r"VUL4J-\d+__L\d[ab]?__([\w-]+)\.json", p.name)
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


def _check_header() -> None:
    """
    Refuse to append rows wider than the file's header.

    A results.csv written by an older version of this code may lack columns
    this version writes. Appending the new shape to it would produce rows the
    header cannot describe, so say so instead and leave the file alone.
    """
    if not RESULTS_CSV.exists():
        return
    with RESULTS_CSV.open(newline="") as f:
        header = (f.readline().strip() or "").split(",")
    if header != CSV_FIELDS:
        missing = [c for c in CSV_FIELDS if c not in header]
        raise RuntimeError(
            f"{RESULTS_CSV} has an older header (missing: {', '.join(missing) or 'none'}; "
            f"{len(header)} columns, this code writes {len(CSV_FIELDS)}). Appending would "
            f"corrupt it. Move it aside and let this write a new "
            f"one, or re-evaluate into a fresh file."
        )


def append_row(row: Dict) -> None:
    _check_header()
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
    ap.add_argument("--dataset", choices=["vul4j", "patcheval"], default="vul4j",
                    help="Which benchmark's logs to evaluate (default: vul4j)")
    ap.add_argument("--logs-dir", type=Path, default=None,
                    help="read logs from here instead of logs/ (PatchEval: its patcheval/)")
    ap.add_argument("--results-dir", type=Path, default=None,
                    help="write results.csv / results_patcheval.csv here instead of results/")
    ap.add_argument("--oracle", action="store_true",
                    help="Vul4J: grade each entry's original file (expect L1) and reference "
                         "fix (expect L3) against data/vul4j/baseline.json; results go to "
                         "--results-dir (default results/oracle_vul4j/)")
    args = ap.parse_args()

    if args.oracle and args.dataset == "vul4j":
        out = args.results_dir or (RESULTS_DIR / "oracle_vul4j")
        wrong = oracle(args.vulns or SUBSET, out)
        sys.exit(1 if wrong else 0)

    global LOGS_DIR, RESULTS_CSV
    import patcheval_eval
    if args.logs_dir is not None:
        LOGS_DIR = args.logs_dir.resolve()
        patcheval_eval.PATCHEVAL_LOGS_DIR = LOGS_DIR / "patcheval"
    if args.results_dir is not None:
        args.results_dir.mkdir(parents=True, exist_ok=True)
        RESULTS_CSV = args.results_dir.resolve() / RESULTS_CSV.name
        patcheval_eval.RESULTS_CSV = args.results_dir.resolve() / patcheval_eval.RESULTS_CSV.name

    if args.dataset == "patcheval":
        patcheval_eval.main(args)
        return

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

    baseline = load_baseline()
    counts = {"L0": 0, "L1": 0, "L2": 0, "L3": 0, ERROR: 0, REFUSED: 0}

    for i, log_path in enumerate(pending, start=1):
        vul = _parse_vul_id(log_path)
        lvl = _parse_level(log_path)
        mdl = _parse_model(log_path)
        print(f"[{i}/{len(pending)}] {vul}  {lvl}  {mdl}", end="  ... ", flush=True)

        try:
            row = evaluate_log(log_path, baseline)
        except Exception as e:
            row = _error_row(
                log_path, datetime.now(timezone.utc).isoformat(),
                f"unhandled: {type(e).__name__}: {e}",
            )

        append_row(row)
        counts[row["trust_level"]] = counts.get(row["trust_level"], 0) + 1
        tag = row["trust_level"]
        if tag in (ERROR, REFUSED):
            print(f"{tag}  ({row['error']})")
        elif tag in ("L2", "L3"):
            print(f"{tag}  pov_passed, {row['n_regressions']} regressions of "
                  f"{row['judged_set_size']} judged")
        else:
            print(f"{tag}  {row['error']}".rstrip())

    print()
    print("Summary:")
    for k in ("L0", "L1", "L2", "L3", ERROR, REFUSED):
        print(f"  {k}: {counts.get(k, 0)}")


if __name__ == "__main__":
    main()
