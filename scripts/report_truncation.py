"""
How many cells in a results file were truncated at the output cap.

A truncated candidate is a file the provider stopped mid-write. It cannot
compile or parse, so it scores L0 for a reason that has nothing to do with the
repair. This counts those cells by model and by prompt level, so an L0 rate can
be read net of them.

    python scripts/report_truncation.py                         # results/published/results.csv
    python scripts/report_truncation.py results/results.csv     # a new run
    python scripts/report_truncation.py results/results_patcheval.csv
    python scripts/report_truncation.py --by-vuln

Works on any results CSV that carries a `truncated` column. A file written
before that column existed is reported as such rather than as zero truncations
(see docs/output-cap-truncation.md for how the published 504 were measured).
"""

import argparse
import collections
import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CSV = PROJECT_ROOT / "results" / "published" / "results.csv"

TRUE = {"true", "1", "yes"}
# results.csv keys cells by vul_id; results_patcheval.csv by cve.
ID_COLUMNS = ("vul_id", "cve")


def is_true(value: str) -> bool:
    return (value or "").strip().lower() in TRUE


def load(path: Path) -> list:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def id_column(rows: list) -> str:
    for col in ID_COLUMNS:
        if rows and col in rows[0]:
            return col
    return ""


def table(title: str, counts: collections.Counter, totals: collections.Counter) -> None:
    print(f"\n{title}")
    width = max([len(str(k)) for k in totals] + [len(title), 8])
    for key in sorted(totals):
        n, total = counts.get(key, 0), totals[key]
        pct = f"{100 * n / total:.1f}%" if total else "-"
        print(f"  {str(key):<{width}}  {n:>5} of {total:>5}  {pct:>6}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    ap.add_argument("csv_path", nargs="?", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--by-vuln", action="store_true",
                    help="also list the affected vulnerabilities")
    args = ap.parse_args(argv)

    if not args.csv_path.exists():
        print(f"No such results file: {args.csv_path}", file=sys.stderr)
        return 2
    rows = load(args.csv_path)
    if not rows:
        print(f"{args.csv_path} has no rows")
        return 0
    if "truncated" not in rows[0]:
        print(f"{args.csv_path} has no `truncated` column: it was written before "
              f"truncation was recorded, so truncation cannot be read from it.")
        print("Re-evaluate against logs that carry the flag, or measure it from the "
              "logs directly as docs/output-cap-truncation.md shows.")
        return 1

    truncated = [r for r in rows if is_true(r.get("truncated"))]
    print(f"{args.csv_path}: {len(truncated)} of {len(rows)} cells truncated at the "
          f"output cap ({100 * len(truncated) / len(rows):.1f}%)")

    by_model_t = collections.Counter(r["model_key"] for r in truncated)
    by_model_a = collections.Counter(r["model_key"] for r in rows)
    table("by model", by_model_t, by_model_a)

    by_level_t = collections.Counter(r["level"] for r in truncated)
    by_level_a = collections.Counter(r["level"] for r in rows)
    table("by level", by_level_t, by_level_a)

    reasons = collections.Counter(r.get("stop_reason", "") for r in truncated)
    if reasons:
        print("\nstop reasons seen on truncated cells")
        for reason, n in reasons.most_common():
            print(f"  {reason or '(blank)':<24} {n}")

    # What the truncation costs: how many of those cells scored L0.
    l0 = [r for r in truncated if r.get("trust_level") == "L0"]
    all_l0 = [r for r in rows if r.get("trust_level") == "L0"]
    if all_l0:
        print(f"\n{len(l0)} truncated cells scored L0, out of {len(all_l0)} L0s in the "
              f"file ({100 * len(l0) / len(all_l0):.0f}% of L0s)")

    col = id_column(rows)
    if args.by_vuln and col and truncated:
        print(f"\nby {col}")
        per = collections.defaultdict(list)
        for r in truncated:
            per[r[col]].append(f"{r['level']}/{r['model_key']}")
        for key in sorted(per):
            print(f"  {key:<18} {len(per[key]):>3}  {', '.join(sorted(per[key]))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
