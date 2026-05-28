"""
Spot-check a single evaluated cell: shows the LLM's patch next to the human
patch and the recorded verdict, so you can confirm the classifier is honest.

Usage:
    python spotcheck.py VUL4J-74 L2 gemini
    python spotcheck.py --list-l3          # list all L3 cells to pick from
    python spotcheck.py --list-l2          # list all L2 cells
"""

import csv
import json
import subprocess
import sys
from pathlib import Path

from config import RESULTS_DIR, LOGS_DIR, CONTAINER_NAME

CSV = RESULTS_DIR / "results.csv"


def list_cells(trust):
    rows = [r for r in csv.DictReader(CSV.open()) if r["trust_level"] == trust]
    print(f"\n{len(rows)} cells with trust_level={trust}:\n")
    for r in rows:
        print(f"  {r['vul_id']:10} {r['level']:4} {r['model_key']:8} "
              f"{r['cwe_id']:10} pov_passed={r['pov_passed']}")
    print()


def get_human_patch(vul_id):
    """Read the human patch file content from the container."""
    # The checkout from the eval run should still be at /tmp/cweft/<vul_id>
    info_path = f"/tmp/cweft/{vul_id}/VUL4J/vulnerability_info.json"
    try:
        out = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "cat", info_path],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return None
        info = json.loads(out.stdout)
        patches = info.get("human_patch", [])
        if not patches:
            return None
        return patches[0]["file_path"], patches[0]["content"]
    except Exception as e:
        return None


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--list-l3":
        list_cells("L3"); return
    if len(sys.argv) == 2 and sys.argv[1] == "--list-l2":
        list_cells("L2"); return
    if len(sys.argv) != 4:
        print("Usage: python spotcheck.py VUL4J-N LEVEL MODEL")
        print("   or: python spotcheck.py --list-l3 / --list-l2")
        return

    vul_id, level, model = sys.argv[1], sys.argv[2], sys.argv[3]

    # 1. The recorded verdict
    row = None
    for r in csv.DictReader(CSV.open()):
        if (r["vul_id"] == vul_id and r["level"] == level
                and r["model_key"] == model):
            row = r; break
    if not row:
        print(f"No results row for {vul_id} {level} {model}")
        return

    print("=" * 72)
    print(f"CELL: {vul_id}  {level}  {model}")
    print("=" * 72)
    print(f"CWE:         {row['cwe_id']} — {row['cwe_name']}")
    print(f"CVE:         {row['cve_id']}")
    print(f"Verdict:     {row['trust_level']}")
    print(f"compiled:    {row['compiled']}")
    print(f"pov_passed:  {row['pov_passed']}")
    print(f"regressions: {row['regressions']}")
    print()

    # 2. The LLM's response
    log_path = LOGS_DIR / f"{vul_id}__{level}__{model}.json"
    if not log_path.exists():
        print(f"(log not found: {log_path})")
        return
    log = json.loads(log_path.read_text())
    llm_code = log.get("response", "")

    # 3. The human patch
    hp = get_human_patch(vul_id)

    print("-" * 72)
    print("HUMAN PATCH (ground truth fix)")
    print("-" * 72)
    if hp:
        fpath, content = hp
        print(f"File: {fpath}\n")
        print(content[:4000])
        if len(content) > 4000:
            print(f"\n... [{len(content)-4000} more chars]")
    else:
        print("(could not read human patch from container — "
              "checkout may have been cleaned)")
    print()

    print("-" * 72)
    print(f"LLM PATCH ({model}, {level})")
    print("-" * 72)
    print(llm_code[:4000])
    if len(llm_code) > 4000:
        print(f"\n... [{len(llm_code)-4000} more chars]")
    print()
    print("=" * 72)
    print("MANUAL CHECK: Does the LLM patch address the same root cause as the")
    print("human patch? If verdict=L3, both should close the vulnerability and")
    print("the LLM patch should not obviously break unrelated behavior.")
    print("=" * 72)


if __name__ == "__main__":
    main()