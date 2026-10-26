"""
Which published Vul4J cells would change level under the fixed grader?

Reads results/published/results.csv and data/vul4j/baseline.json; changes
neither. No test is re-run: each cell's level is recomputed from what the
published row recorded, by the rules in vul4j_grading.py.

What a published row records: L0 rows did not compile. Otherwise the row's
`regressions` holds every failing test EXCEPT those the old grader matched to
its PoV (derived from test_cmd, kept in data/vul4j/manifest.json as
failing_tests_from_test_cmd).

  * pov_passed = True: the old PoV matched no failure, so `regressions` is the
    full list of failures and the new level follows exactly.
  * pov_passed = False: some failures were hidden as "PoV". When the old PoV
    names exactly the new PoV tests, the new PoV failed too and the cell stays
    L1. When the old PoV was a whole class, the row does not say which method
    failed, so the new level is reported as undetermined, with what it could be.

Assumptions, stated in the output: every PoV test ran in the published run
(it is in every baseline run of the same suite), and no rerun - the new
grader gives a failing judged test one rerun, the published run had none.

    python scripts/regrade_published_vul4j.py

Writes results/oracle_vul4j/published_regrade.csv (every row, old and new)
and published_regrade_summary.txt.
"""

import collections
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import vul4j_grading as vg  # noqa: E402

PUBLISHED = PROJECT_ROOT / "results" / "published" / "results.csv"
BASELINE = PROJECT_ROOT / "data" / "vul4j" / "baseline.json"
MANIFEST = PROJECT_ROOT / "data" / "vul4j" / "manifest.json"
OUT = PROJECT_ROOT / "results" / "oracle_vul4j"

EXACT, UNDETERMINED, NO_BASELINE = "exact", "undetermined", "no_baseline"


def regrade_row(row: dict, old_pov: list, entry: dict) -> dict:
    """{'new': level or '', 'basis': ..., 'possible': [...], 'reason': ...} for one row."""
    t = row["trust_level"]
    if t not in ("L0", "L1", "L2", "L3"):
        return {"new": t, "basis": EXACT, "possible": [t], "reason": "not graded"}
    if t == "L0":
        return {"new": "L0", "basis": EXACT, "possible": ["L0"], "reason": "did not compile"}
    if not entry or entry.get("status") != "ok":
        return {"new": "", "basis": NO_BASELINE, "possible": [],
                "reason": f"baseline status {(entry or {}).get('status', 'missing')}"}
    if row["pov_passed"] == "":
        return {"new": "L1", "basis": EXACT, "possible": ["L1"], "reason": "no test results"}

    pov = set(entry["pov"])
    judged = set(entry["judged"])
    known = {vg.canonical(n) for n in row["regressions"].split(";") if n.strip()}

    def level_from(failing: set) -> tuple:
        if failing & pov:
            return "L1", "PoV test failing"
        regs = sorted(failing & judged)
        if regs:
            return "L2", f"{len(regs)} judged test(s) failing: " + ";".join(regs)[:300]
        untouched = len(failing)
        return "L3", (f"PoV passes; {untouched} failure(s) all outside the judged set"
                      if untouched else "PoV passes; nothing failing")

    if row["pov_passed"] == "True":
        new, why = level_from(known)
        return {"new": new, "basis": EXACT, "possible": [new], "reason": why}

    # pov_passed == False: failures matched by the old PoV are not in the row.
    old_methods = {vg.canonical(p) for p in old_pov if "#" in p}
    old_classes = {p for p in old_pov if "#" not in p}
    if old_methods and not old_classes and old_methods <= pov:
        return {"new": "L1", "basis": EXACT, "possible": ["L1"],
                "reason": "old PoV is a subset of the new PoV, and it failed"}
    if known & pov:
        return {"new": "L1", "basis": EXACT, "possible": ["L1"], "reason": "PoV test failing"}
    possible = ["L1"]
    if known & judged:
        possible.append("L2")
    else:
        possible += ["L2", "L3"]
    return {"new": "", "basis": UNDETERMINED, "possible": possible,
            "reason": "old PoV was " + ", ".join(sorted(old_classes | old_methods))[:200]
                      + "; the row does not say which of its tests failed"}


def main() -> int:
    if not BASELINE.exists():
        print(f"No {BASELINE}: run vul4j_baseline.py first.")
        return 2
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))["entries"]
    manifest = {e["vul_id"]: e for e in
                json.loads(MANIFEST.read_text(encoding="utf-8"))["entries"]}
    with PUBLISHED.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    out_rows = []
    for row in rows:
        v = row["vul_id"]
        r = regrade_row(row, manifest[v]["failing_tests_from_test_cmd"], baseline.get(v))
        out_rows.append({
            "vul_id": v, "level": row["level"], "model_key": row["model_key"],
            "old": row["trust_level"], "new": r["new"], "basis": r["basis"],
            "possible": "/".join(r["possible"]),
            "changed": bool(r["new"]) and r["new"] != row["trust_level"],
            "reason": r["reason"],
        })

    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "published_regrade.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0]))
        w.writeheader()
        w.writerows(out_rows)

    changed = [r for r in out_rows if r["changed"]]
    undetermined = [r for r in out_rows if r["basis"] == UNDETERMINED]
    unbased = [r for r in out_rows if r["basis"] == NO_BASELINE]
    lines = [
        f"{len(out_rows)} published Vul4J cells re-graded from the published rows (no test re-run).",
        f"  changed level: {len(changed)}    undetermined: {len(undetermined)}    "
        f"no usable baseline: {len(unbased)}",
        "  Assumes every PoV test ran in the published run, and applies no rerun.",
        "",
        "Changed cells (old -> new):",
    ]
    for r in sorted(changed, key=lambda r: (r["vul_id"], r["level"], r["model_key"])):
        lines.append(f"  {r['vul_id']:10s} {r['level']:4s} {r['model_key']:7s} "
                     f"{r['old']} -> {r['new']}   {r['reason'][:110]}")
    for title, key in (("By model", "model_key"), ("By prompt level", "level")):
        lines += ["", f"{title} (changed cells, as old->new: count):"]
        groups = collections.defaultdict(collections.Counter)
        for r in changed:
            groups[r[key]][f"{r['old']}->{r['new']}"] += 1
        for g in sorted({r[key] for r in out_rows}):
            moves = ", ".join(f"{k}: {n}" for k, n in sorted(groups[g].items())) or "none"
            lines.append(f"  {g:7s} {sum(groups[g].values()):3d} changed   {moves}")
    if undetermined:
        lines += ["", "Undetermined (old L1; could be any of the listed levels):"]
        for r in undetermined:
            lines.append(f"  {r['vul_id']:10s} {r['level']:4s} {r['model_key']:7s} "
                         f"L1 -> {r['possible']}   {r['reason'][:100]}")
    if unbased:
        lines += ["", "Not re-graded (baseline not ok):"]
        for v in sorted({r["vul_id"] for r in unbased}):
            lines.append(f"  {v}: {next(r['reason'] for r in unbased if r['vul_id'] == v)}")
    old_dist = collections.Counter(r["old"] for r in out_rows)
    new_dist = collections.Counter(r["new"] or r["old"] for r in out_rows
                                   if r["basis"] == EXACT)
    lines += ["", f"Old distribution: {dict(sorted(old_dist.items()))}",
              f"New distribution (exact cells only): {dict(sorted(new_dist.items()))}"]
    (OUT / "published_regrade_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
