"""
The whole Vul4J grader validation, start to finish, unattended:

  1. scripts/check_vul4j_offline.py   every entry compiles offline (pre-builds if not)
  2. vul4j_baseline.py --redo         all 42 baselines, one code version
  3. evaluate.py --oracle             original -> L1, reference fix -> L3, all 42
  4. scripts/regrade_published_vul4j.py

Each step's output is appended to results/oracle_vul4j/run.log. A step that
fails is logged and the next one still runs. While this runs, Windows is told
the system is in use, so it does not drop into (Modern) Standby, which pauses
Docker and stretches an hour of grading over a night. Closing the lid can
still put the machine to sleep.

    python scripts/run_vul4j_validation.py
    python scripts/run_vul4j_validation.py --resume     # after an interruption

--resume skips the offline check (it records each entry as it goes and was
complete), redoes only the baselines not built by the current code, and lets
the oracle skip the cells already in oracle.csv. Nothing finished is redone;
an entry interrupted half-way was never written, so it is simply done again.
"""

import argparse
import ctypes
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
LOG = PROJECT_ROOT / "results" / "oracle_vul4j" / "run.log"

ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001


def keep_awake(on: bool) -> None:
    if sys.platform == "win32":
        flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0)
        ctypes.windll.kernel32.SetThreadExecutionState(flags)


def stale(entries: dict, ids: list, current: str) -> list:
    """
    The ids the baseline still has to (re)do: missing, recorded as 'error', or
    built by code other than the current code (another code_fingerprint).
    Lives here rather than in vul4j_baseline.py, whose own bytes are part of
    that fingerprint: changing it would make every finished entry stale.
    """
    def todo(v: str) -> bool:
        e = entries.get(v)
        return (e is None or e.get("status") == "error"
                or e.get("code_fingerprint") != current)
    return [v for v in ids if todo(v)]


def stale_baseline_ids() -> list:
    import vul4j_baseline as vb
    from config import SUBSET
    entries = (json.loads(vb.BASELINE_PATH.read_text(encoding="utf-8"))["entries"]
               if vb.BASELINE_PATH.exists() else {})
    return stale(entries, SUBSET, vb.code_fingerprint())


def step(log, name: str, args: list) -> int:
    log.write(f"=== {name} start {datetime.now().isoformat(timespec='seconds')}\n")
    log.flush()
    rc = subprocess.call([sys.executable, "-u"] + args, cwd=PROJECT_ROOT,
                         stdout=log, stderr=subprocess.STDOUT)
    log.write(f"=== {name} exit {rc} {datetime.now().isoformat(timespec='seconds')}\n")
    log.flush()
    return rc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the Vul4J grader validation")
    ap.add_argument("--skip-offline-check", action="store_true")
    ap.add_argument("--resume", action="store_true",
                    help="continue an interrupted run: no offline check, only stale baselines")
    args = ap.parse_args(argv)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    keep_awake(True)
    try:
        with LOG.open("a", encoding="utf-8") as log:
            if not (args.skip_offline_check or args.resume):
                step(log, "offline check", ["scripts/check_vul4j_offline.py"])
            if args.resume:
                todo = stale_baseline_ids()
                log.write(f"=== resume: {len(todo)} baseline entries to redo: {' '.join(todo)}\n")
                if todo:
                    step(log, "baseline", ["vul4j_baseline.py", "--redo", "--only"] + todo)
            else:
                step(log, "baseline", ["vul4j_baseline.py", "--redo"])
            step(log, "oracle", ["evaluate.py", "--oracle"])
            step(log, "published re-grade", ["scripts/regrade_published_vul4j.py"])
            log.write(f"=== all done {datetime.now().isoformat(timespec='seconds')}\n")
    finally:
        keep_awake(False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
