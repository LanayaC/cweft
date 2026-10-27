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
    python scripts/run_vul4j_validation.py --skip-offline-check
"""

import argparse
import ctypes
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG = PROJECT_ROOT / "results" / "oracle_vul4j" / "run.log"

ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001


def keep_awake(on: bool) -> None:
    if sys.platform == "win32":
        flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0)
        ctypes.windll.kernel32.SetThreadExecutionState(flags)


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
    args = ap.parse_args(argv)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    keep_awake(True)
    try:
        with LOG.open("a", encoding="utf-8") as log:
            if not args.skip_offline_check:
                step(log, "offline check", ["scripts/check_vul4j_offline.py"])
            step(log, "baseline", ["vul4j_baseline.py", "--redo"])
            step(log, "oracle", ["evaluate.py", "--oracle"])
            step(log, "published re-grade", ["scripts/regrade_published_vul4j.py"])
            log.write(f"=== all done {datetime.now().isoformat(timespec='seconds')}\n")
    finally:
        keep_awake(False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
