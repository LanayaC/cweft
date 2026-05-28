"""
Live progress monitor for the evaluation run.

Run in a SEPARATE terminal tab (open with the + in VS Code's terminal pane).
Refreshes every 30 seconds. Press Ctrl+C to stop monitoring — this does NOT
stop the evaluation run, only the monitor itself.

Usage:
    python monitor.py             # refresh every 30s
    python monitor.py --once      # print once and exit (good for cron / quick check)
    python monitor.py --interval 10   # refresh every 10s
"""

import argparse
import csv
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from config import RESULTS_DIR, SUBSET, PROMPT_LEVELS, MODELS, TOTAL_CELLS

RESULTS_CSV = RESULTS_DIR / "results.csv"


def load_rows():
    if not RESULTS_CSV.exists():
        return []
    with RESULTS_CSV.open() as f:
        return list(csv.DictReader(f))


def fmt_pct(n, total):
    if total == 0:
        return "0.0%"
    return f"{100 * n / total:.1f}%"


def render(rows):
    n = len(rows)
    pct = 100 * n / TOTAL_CELLS if TOTAL_CELLS else 0

    print("\033[2J\033[H", end="")  # clear screen
    print("═" * 78)
    print(f"  CWEFT Evaluation Monitor  —  {datetime.now().strftime('%H:%M:%S')}")
    print("═" * 78)
    print()
    print(f"Progress: {n} / {TOTAL_CELLS} cells  ({pct:.1f}%)")

    # Progress bar
    bar_width = 60
    filled = int(bar_width * pct / 100)
    bar = "█" * filled + "░" * (bar_width - filled)
    print(f"[{bar}]")
    print()

    if not rows:
        print("Waiting for first result to land in results.csv ...")
        return

    # ── Trust level distribution ────────────────────────────
    trust = Counter(r["trust_level"] for r in rows)
    print("Trust level distribution:")
    for k in ("L0", "L1", "L2", "L3", "ERROR"):
        c = trust.get(k, 0)
        print(f"  {k:6}  {c:4d}   ({fmt_pct(c, n)})")
    print()

    # ── Per-model L3 rate ───────────────────────────────────
    print("Per-model breakdown:")
    print(f"  {'model':10}  {'cells':>5}  {'L0':>4}  {'L1':>4}  {'L2':>4}  {'L3':>4}  {'L3%':>6}  {'err':>4}")
    by_model = defaultdict(list)
    for r in rows:
        by_model[r["model_key"]].append(r["trust_level"])
    for model in sorted(by_model):
        levels = by_model[model]
        c = len(levels)
        cnt = Counter(levels)
        l3_rate = fmt_pct(cnt.get("L3", 0), c)
        print(f"  {model:10}  {c:>5}  {cnt.get('L0',0):>4}  "
              f"{cnt.get('L1',0):>4}  {cnt.get('L2',0):>4}  "
              f"{cnt.get('L3',0):>4}  {l3_rate:>6}  "
              f"{cnt.get('ERROR',0):>4}")
    print()

    # ── Per-prompt-level breakdown ──────────────────────────
    print("Per-prompt-level breakdown:")
    print(f"  {'level':6}  {'cells':>5}  {'L0':>4}  {'L1':>4}  {'L2':>4}  {'L3':>4}  {'L3%':>6}  {'err':>4}")
    by_level = defaultdict(list)
    for r in rows:
        by_level[r["level"]].append(r["trust_level"])
    for level in ("L1", "L2", "L3a", "L3b"):
        levels = by_level.get(level, [])
        c = len(levels)
        if c == 0:
            print(f"  {level:6}  {'-':>5}")
            continue
        cnt = Counter(levels)
        l3_rate = fmt_pct(cnt.get("L3", 0), c)
        print(f"  {level:6}  {c:>5}  {cnt.get('L0',0):>4}  "
              f"{cnt.get('L1',0):>4}  {cnt.get('L2',0):>4}  "
              f"{cnt.get('L3',0):>4}  {l3_rate:>6}  "
              f"{cnt.get('ERROR',0):>4}")
    print()

    # ── Model × prompt-level matrix ─────────────────────────
    print("L3 rate by (model × prompt level):")
    print(f"  {'model':10}  {'L1':>8}  {'L2':>8}  {'L3a':>8}  {'L3b':>8}")
    cells_by = defaultdict(list)
    for r in rows:
        cells_by[(r["model_key"], r["level"])].append(r["trust_level"])
    for model in sorted(set(MODELS.keys()) & {r["model_key"] for r in rows}):
        line = f"  {model:10}"
        for level in ("L1", "L2", "L3a", "L3b"):
            cell_rows = cells_by.get((model, level), [])
            if not cell_rows:
                line += f"  {'-':>8}"
            else:
                c = len(cell_rows)
                l3 = sum(1 for t in cell_rows if t == "L3")
                line += f"  {l3:>2}/{c:>2} ({100*l3/c:.0f}%)".rjust(11)
        print(line)
    print()

    # ── Recent activity ─────────────────────────────────────
    print("Last 5 cells:")
    for r in rows[-5:]:
        tag = r["trust_level"]
        marker = "✓" if tag == "L3" else ("⚠" if tag == "L2" else " ")
        print(f"  {marker}  {r['vul_id']:10}  {r['level']:4}  {r['model_key']:8}  → {tag}")
    print()

    # ── ETA ────────────────────────────────────────────────
    if n >= 3 and n < TOTAL_CELLS:
        ts_first = datetime.fromisoformat(rows[0]["timestamp"].replace("Z", "+00:00"))
        ts_last = datetime.fromisoformat(rows[-1]["timestamp"].replace("Z", "+00:00"))
        elapsed_s = (ts_last - ts_first).total_seconds()
        if elapsed_s > 0:
            per_cell_s = elapsed_s / max(n - 1, 1)
            remaining = TOTAL_CELLS - n
            eta_s = per_cell_s * remaining
            eta_h = eta_s / 3600
            print(f"Rate: {per_cell_s:.1f}s per cell   ETA: {eta_h:.1f}h "
                  f"({remaining} cells left)")
    elif n >= TOTAL_CELLS:
        print("✓ ALL DONE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="Print once and exit")
    ap.add_argument("--interval", type=int, default=30, help="Refresh interval in seconds")
    args = ap.parse_args()

    if args.once:
        render(load_rows())
        return

    try:
        while True:
            render(load_rows())
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n\nMonitor stopped. Evaluation run is still active in the other terminal.")


if __name__ == "__main__":
    main()