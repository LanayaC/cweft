"""
CWEFT analysis — turns results/results.csv into publication tables + stats.

Outputs:
  results/analysis_summary.txt   human-readable tables for the paper
  results/table_overall.csv
  results/table_by_level.csv
  results/table_by_model.csv
  results/table_model_x_level.csv
  results/table_by_cwe.csv
  results/mcnemar.txt

Usage:  python analyze.py
"""

import csv
from collections import Counter, defaultdict
from pathlib import Path

from config import RESULTS_DIR, SUBSET, PROMPT_LEVELS, MODELS

CSV = RESULTS_DIR / "results.csv"
LEVELS = ["L1", "L2", "L3a", "L3b"]       # prompt levels
TRUST = ["L0", "L1", "L2", "L3"]          # trust levels
MODEL_KEYS = ["claude", "gemini", "gpt"]


def load():
    rows = list(csv.DictReader(CSV.open()))
    rows = [r for r in rows if r["trust_level"] in TRUST]   # drop any stray ERROR
    return rows


def pct(n, d):
    return f"{100*n/d:.1f}%" if d else "—"


def dist(rows):
    """Trust-level counts for a set of rows."""
    c = Counter(r["trust_level"] for r in rows)
    return {t: c.get(t, 0) for t in TRUST}


def l3_rate(rows):
    n = len(rows)
    return (sum(1 for r in rows if r["trust_level"] == "L3"), n)


def pov_pass_rate(rows):
    """L2 + L3 = vuln identified and fixed."""
    n = len(rows)
    return (sum(1 for r in rows if r["trust_level"] in ("L2", "L3")), n)


def compile_rate(rows):
    """L1+L2+L3 = compiled."""
    n = len(rows)
    return (sum(1 for r in rows if r["trust_level"] != "L0"), n)


def mcnemar(rows):
    """
    McNemar's test on paired L3a vs L3b binary outcomes (L3 = success).
    Pairs are matched on (vul_id, model_key).
    Returns dict per model + pooled with the 2x2 table and exact p-value.
    """
    from math import comb

    def exact_p(b, c):
        # two-sided exact binomial test on the discordant pairs
        n = b + c
        if n == 0:
            return 1.0
        k = min(b, c)
        # P(X <= k) + P(X >= n-k) under Binom(n, 0.5)
        tail = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
        p = 2 * tail
        return min(p, 1.0)

    def fixed(rows_, level, model):
        out = {}
        for r in rows_:
            if r["level"] == level and r["model_key"] == model:
                out[r["vul_id"]] = (r["trust_level"] == "L3")
        return out

    results = {}
    for model in MODEL_KEYS + ["pooled"]:
        a = b = c = d = 0
        models_iter = MODEL_KEYS if model == "pooled" else [model]
        for m in models_iter:
            f3a = fixed(rows, "L3a", m)
            f3b = fixed(rows, "L3b", m)
            for vid in set(f3a) & set(f3b):
                x, y = f3a[vid], f3b[vid]
                if x and y: a += 1
                elif not x and y: b += 1     # L3b fixed, L3a didn't
                elif x and not y: c += 1     # L3a fixed, L3b didn't
                else: d += 1
        p = exact_p(b, c)
        results[model] = dict(a=a, b=b, c=c, d=d, p=p,
                              discordant=b + c)
    return results


def main():
    rows = load()
    N = len(rows)
    out_lines = []

    def w(s=""):
        out_lines.append(s)
        print(s)

    w("=" * 70)
    w("CWEFT ANALYSIS")
    w("=" * 70)
    w(f"Total cells: {N}   Vulns: {len(set(r['vul_id'] for r in rows))}   "
      f"Levels: {len(LEVELS)}   Models: {len(MODEL_KEYS)}")
    w()

    #   Table 1: Overall  
    w("TABLE 1 — Overall trust-level distribution")
    d = dist(rows)
    for t in TRUST:
        w(f"  {t}: {d[t]:4d}  ({pct(d[t], N)})")
    cr = compile_rate(rows); pp = pov_pass_rate(rows); l3 = l3_rate(rows)
    w(f"  Compile rate (L1+L2+L3): {pct(cr[0], cr[1])}")
    w(f"  PoV pass rate (L2+L3):   {pct(pp[0], pp[1])}")
    w(f"  L3 (correct) rate:       {pct(l3[0], l3[1])}")
    w()
    with (RESULTS_DIR / "table_overall.csv").open("w", newline="") as f:
        wr = csv.writer(f); wr.writerow(["trust", "count", "pct"])
        for t in TRUST: wr.writerow([t, d[t], f"{100*d[t]/N:.1f}"])

    #   Table 2: By prompt level (HEADLINE)  
    w("TABLE 2 — By prompt level  [HEADLINE]")
    w(f"  {'level':6}{'n':>5}{'L0':>6}{'L1':>6}{'L2':>6}{'L3':>6}"
      f"{'L3%':>8}{'PoV%':>8}{'Comp%':>8}")
    rows_by_level = defaultdict(list)
    for r in rows: rows_by_level[r["level"]].append(r)
    t2 = []
    for lv in LEVELS:
        rr = rows_by_level[lv]; dd = dist(rr); n = len(rr)
        l3r = pct(dd["L3"], n)
        povr = pct(dd["L2"] + dd["L3"], n)
        compr = pct(n - dd["L0"], n)
        w(f"  {lv:6}{n:>5}{dd['L0']:>6}{dd['L1']:>6}{dd['L2']:>6}"
          f"{dd['L3']:>6}{l3r:>8}{povr:>8}{compr:>8}")
        t2.append([lv, n, dd["L0"], dd["L1"], dd["L2"], dd["L3"], l3r, povr, compr])
    w()
    with (RESULTS_DIR / "table_by_level.csv").open("w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["level","n","L0","L1","L2","L3","L3_rate","PoV_rate","compile_rate"])
        wr.writerows(t2)

    #   Table 3: By model  
    w("TABLE 3 — By model")
    w(f"  {'model':8}{'n':>5}{'L0':>6}{'L1':>6}{'L2':>6}{'L3':>6}"
      f"{'L3%':>8}{'PoV%':>8}{'Comp%':>8}")
    rows_by_model = defaultdict(list)
    for r in rows: rows_by_model[r["model_key"]].append(r)
    t3 = []
    for m in MODEL_KEYS:
        rr = rows_by_model[m]; dd = dist(rr); n = len(rr)
        l3r = pct(dd["L3"], n)
        povr = pct(dd["L2"] + dd["L3"], n)
        compr = pct(n - dd["L0"], n)
        w(f"  {m:8}{n:>5}{dd['L0']:>6}{dd['L1']:>6}{dd['L2']:>6}"
          f"{dd['L3']:>6}{l3r:>8}{povr:>8}{compr:>8}")
        t3.append([m, n, dd["L0"], dd["L1"], dd["L2"], dd["L3"], l3r, povr, compr])
    w()
    with (RESULTS_DIR / "table_by_model.csv").open("w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["model","n","L0","L1","L2","L3","L3_rate","PoV_rate","compile_rate"])
        wr.writerows(t3)

    #   Table 4: Model x prompt level (L3 rate) 
    w("TABLE 4 — L3 rate by (model × prompt level)")
    w(f"  {'model':8}" + "".join(f"{lv:>10}" for lv in LEVELS))
    cellmap = defaultdict(list)
    for r in rows: cellmap[(r["model_key"], r["level"])].append(r)
    t4 = []
    for m in MODEL_KEYS:
        line = f"  {m:8}"; row_out = [m]
        for lv in LEVELS:
            rr = cellmap[(m, lv)]; n = len(rr)
            k = sum(1 for r in rr if r["trust_level"] == "L3")
            line += f"{k}/{n} ({100*k/n:.0f}%)".rjust(10)
            row_out.append(f"{k}/{n}")
        w(line); t4.append(row_out)
    w()
    with (RESULTS_DIR / "table_model_x_level.csv").open("w", newline="") as f:
        wr = csv.writer(f); wr.writerow(["model"] + LEVELS); wr.writerows(t4)

    #   Table 5: By CWE  
    w("TABLE 5 — L3 rate by CWE class (across all conditions)")
    w(f"  {'CWE':12}{'n_cells':>8}{'L3':>5}{'L3%':>8}  name")
    rows_by_cwe = defaultdict(list)
    for r in rows: rows_by_cwe[r["cwe_id"]].append(r)
    t5 = []
    for cwe in sorted(rows_by_cwe, key=lambda c: -l3_rate(rows_by_cwe[c])[0]):
        rr = rows_by_cwe[cwe]; n = len(rr)
        k = sum(1 for r in rr if r["trust_level"] == "L3")
        name = rr[0]["cwe_name"][:40]
        w(f"  {cwe:12}{n:>8}{k:>5}{pct(k,n):>8}  {name}")
        t5.append([cwe, n, k, f"{100*k/n:.1f}", rr[0]["cwe_name"]])
    w()
    with (RESULTS_DIR / "table_by_cwe.csv").open("w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["cwe_id","n_cells","L3_count","L3_rate","cwe_name"])
        wr.writerows(t5)

    #   McNemar: L3a vs L3b  
    w("McNEMAR TEST — L3a (prose) vs L3b (schema), success = L3")
    w("  (b = L3b fixed & L3a didn't; c = L3a fixed & L3b didn't)")
    mc = mcnemar(rows)
    mc_lines = ["McNemar L3a vs L3b (success = L3 outcome)\n"]
    for m in MODEL_KEYS + ["pooled"]:
        r = mc[m]
        line = (f"  {m:8} a={r['a']:3} b={r['b']:3} c={r['c']:3} d={r['d']:3} "
                f"discordant={r['discordant']:3}  p={r['p']:.4f} "
                f"{'(sig)' if r['p'] < 0.05 else '(n.s.)'}")
        w(line); mc_lines.append(line + "\n")
    w()
    (RESULTS_DIR / "mcnemar.txt").write_text("".join(mc_lines))

    #   Save full summary  
    (RESULTS_DIR / "analysis_summary.txt").write_text("\n".join(out_lines))
    w("Wrote: analysis_summary.txt + table_*.csv + mcnemar.txt to results/")


if __name__ == "__main__":
    main()
