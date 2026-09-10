"""
L0 triage — split the L0 bucket into two causes.

STANDALONE. Imports nothing from the CWEFT pipeline, writes nothing the
pipeline reads, and never touches logs/ or results/results.csv. Safe to run
while anything else is running; safe to delete.

For every row in results.csv with trust_level == "L0", this reads the matching
logs/<vul>__<level>__<model>.json, pulls the `response` field, and classifies
it as:

    a_not_java        the response was never usable Java — prose, empty,
                      truncated mid-file, or fenced markdown
    b_plausible_java  structurally a Java file; it failed to compile for
                      repair reasons (bad symbol, type error, missing import)

Output is a CSV keyed on (vul_id, level, model_key), which is the same key
results.csv uses, so it joins 1:1.

    python l0_triage.py
    python l0_triage.py --logs /path/to/logs --out /tmp/l0_triage.csv
    python l0_triage.py --all          # classify every row, not just L0

CAVEAT: this is a structural heuristic, not a Java parser. It answers "could
this plausibly be a Java file" — it cannot tell you the code is correct. It is
deliberately biased toward calling things (a): anything that fails a structural
check is (a), so (b) means "nothing structurally wrong with it". Audit with
--sample, and see the counts printed at the end.
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────
# Java lexical stripping
#
# Comments are removed, and string/char/text-block *contents* are blanked,
# so that braces and keywords inside literals or comments cannot fool the
# structural checks below. Newlines inside removed regions are preserved so
# line-oriented checks stay meaningful.
# ──────────────────────────────────────────────────────────────────────

def strip_noncode(src: str) -> str:
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if c == "/" and nxt == "/":                      # line comment
            while i < n and src[i] != "\n":
                i += 1
            continue

        if c == "/" and nxt == "*":                      # block comment
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue

        if c == '"' and src[i:i + 3] == '"""':           # text block
            i += 3
            while i < n and src[i:i + 3] != '"""':
                if src[i] == "\n":
                    out.append("\n")
                i += 1
            i += 3
            out.append('""')
            continue

        if c == '"':                                     # string literal
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "\n":                       # unterminated
                    break
                i += 1
            if i < n and src[i] == '"':
                i += 1
            out.append('""')
            continue

        if c == "'":                                     # char literal
            i += 1
            while i < n and src[i] != "'":
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "\n":
                    break
                i += 1
            if i < n and src[i] == "'":
                i += 1
            out.append("''")
            continue

        out.append(c)
        i += 1

    return "".join(out)


# ──────────────────────────────────────────────────────────────────────
# Structural signals
# ──────────────────────────────────────────────────────────────────────

TYPE_DECL_RE = re.compile(
    r"\b(?:class|interface|enum|record)\s+[A-Za-z_$]|@interface\s+[A-Za-z_$]"
)

# What the first real line of a Java source file is allowed to look like,
# once comments are gone.
JAVA_START_RE = re.compile(
    r"^\s*(?:package\b|import\b|@[A-Za-z_$]|public\b|private\b|protected\b"
    r"|abstract\b|final\b|static\b|strictfp\b|sealed\b|non-sealed\b"
    r"|class\b|interface\b|enum\b|record\b)"
)


def first_code_line(stripped: str) -> str:
    for line in stripped.splitlines():
        if line.strip():
            return line.strip()
    return ""


def analyze(response: str) -> dict:
    """Return structural signals plus a verdict for one model response."""
    raw = response or ""
    stripped = strip_noncode(raw)

    code = stripped.strip()
    fcl = first_code_line(stripped)

    signals = {
        "response_chars": len(raw),
        "brace_balance": code.count("{") - code.count("}"),
        "has_type_decl": bool(TYPE_DECL_RE.search(code)),
        "ends_with_brace": code.endswith("}"),
        "starts_like_java": bool(JAVA_START_RE.match(fcl)) if fcl else False,
        "fence_residue": "```" in code,
        "first_code_line": fcl[:120],
    }

    flags = []
    if not code:
        flags.append("empty")
    else:
        if signals["fence_residue"]:
            flags.append("fence_residue")
        if not signals["starts_like_java"]:
            flags.append("prose_preamble")
        if not signals["has_type_decl"]:
            flags.append("no_type_decl")
        if signals["brace_balance"] != 0:
            flags.append("unbalanced_braces")
        if not signals["ends_with_brace"]:
            flags.append("no_trailing_brace")

    # Precedence: most diagnostic cause first.
    order = [
        "empty",
        "prose_preamble",
        "no_type_decl",
        "fence_residue",
        "unbalanced_braces",
        "no_trailing_brace",
    ]
    primary = next((f for f in order if f in flags), "")

    signals["category"] = "a_not_java" if flags else "b_plausible_java"
    signals["primary_reason"] = primary or "structurally_ok"
    signals["all_flags"] = ";".join(flags)
    return signals


# ──────────────────────────────────────────────────────────────────────
# Driver
# ──────────────────────────────────────────────────────────────────────

OUT_FIELDS = [
    "vul_id", "level", "model_key",          # join key, matches results.csv
    "cwe_id", "model_id", "trust_level",
    "category", "primary_reason", "all_flags",
    "response_chars", "brace_balance",
    "has_type_decl", "ends_with_brace", "starts_like_java", "fence_residue",
    "log_status", "log_found", "first_code_line",
]


def main():
    ap = argparse.ArgumentParser(description="Split the L0 bucket by failure cause")
    ap.add_argument("--results", default="results/results.csv")
    ap.add_argument("--logs", default="logs")
    ap.add_argument("--out", default="results/l0_triage.csv")
    ap.add_argument("--all", action="store_true",
                    help="Classify every row, not just trust_level == L0")
    ap.add_argument("--sample", type=int, default=0,
                    help="Print the first N chars of N responses per category for auditing")
    args = ap.parse_args()

    results_path = Path(args.results)
    logs_dir = Path(args.logs)
    out_path = Path(args.out)

    if not results_path.exists():
        sys.exit(f"No results CSV at {results_path}")
    if not logs_dir.is_dir():
        sys.exit(f"No logs directory at {logs_dir}")

    with results_path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    targets = rows if args.all else [r for r in rows if r["trust_level"] == "L0"]
    print(f"Rows in results.csv: {len(rows)}")
    print(f"Rows to classify:    {len(targets)}"
          f"{'' if args.all else ' (trust_level == L0)'}")

    out_rows = []
    counts = {"a_not_java": 0, "b_plausible_java": 0, "unknown": 0}
    reasons = {}
    samples = {"a_not_java": [], "b_plausible_java": []}

    for r in targets:
        vul_id, level, model_key = r["vul_id"], r["level"], r["model_key"]
        log_path = logs_dir / f"{vul_id}__{level}__{model_key}.json"

        base = {
            "vul_id": vul_id,
            "level": level,
            "model_key": model_key,
            "cwe_id": r.get("cwe_id", ""),
            "model_id": r.get("model_id", ""),
            "trust_level": r.get("trust_level", ""),
        }

        if not log_path.exists():
            out_rows.append({**base, "category": "unknown",
                             "primary_reason": "log_missing", "all_flags": "log_missing",
                             "log_found": False, "log_status": "",
                             "response_chars": 0, "brace_balance": "",
                             "has_type_decl": "", "ends_with_brace": "",
                             "starts_like_java": "", "fence_residue": "",
                             "first_code_line": ""})
            counts["unknown"] += 1
            reasons["log_missing"] = reasons.get("log_missing", 0) + 1
            continue

        try:
            log = json.loads(log_path.read_text(encoding="utf-8"))
        except Exception as e:
            out_rows.append({**base, "category": "unknown",
                             "primary_reason": f"log_unreadable: {type(e).__name__}",
                             "all_flags": "log_unreadable",
                             "log_found": True, "log_status": "",
                             "response_chars": 0, "brace_balance": "",
                             "has_type_decl": "", "ends_with_brace": "",
                             "starts_like_java": "", "fence_residue": "",
                             "first_code_line": ""})
            counts["unknown"] += 1
            reasons["log_unreadable"] = reasons.get("log_unreadable", 0) + 1
            continue

        sig = analyze(log.get("response", ""))
        row = {**base, **sig, "log_found": True, "log_status": log.get("status", "")}
        out_rows.append(row)
        counts[row["category"]] += 1
        reasons[row["primary_reason"]] = reasons.get(row["primary_reason"], 0) + 1

        if args.sample and len(samples.get(row["category"], [])) < args.sample:
            samples[row["category"]].append(
                (vul_id, level, model_key, row["primary_reason"],
                 (log.get("response", "") or "")[:300])
            )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        w.writeheader()
        w.writerows(out_rows)

    total = len(out_rows)
    print(f"\nWrote {total} rows to {out_path}\n")
    print("Category:")
    for k in ("a_not_java", "b_plausible_java", "unknown"):
        n = counts[k]
        pct = f"{100 * n / total:.1f}%" if total else "0.0%"
        print(f"  {k:18} {n:4d}  ({pct})")

    print("\nPrimary reason:")
    for k, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"  {k:22} {n:4d}")

    if args.sample:
        for cat, items in samples.items():
            if not items:
                continue
            print(f"\n{'=' * 70}\nSAMPLES — {cat}\n{'=' * 70}")
            for vul_id, level, model_key, reason, text in items:
                print(f"\n--- {vul_id} {level} {model_key}  [{reason}] ---")
                print(text)


if __name__ == "__main__":
    main()
