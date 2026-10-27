"""
Can each Vul4J entry compile with Maven offline (-o)?

For every entry, in a scratch checkout: make the build offline (Maven -o via
.mvn/maven.config, Gradle via the CWEFT init script; see
vul4j_baseline.make_offline), run `vul4j compile` on the original code, and
record whether it built. An entry that fails offline is compiled ONCE online,
which fills the local caches (~/.m2, ~/.gradle) with whatever was missing (the
"pre-build"), and is then tried offline again.

    python scripts/check_vul4j_offline.py                 # every entry
    python scripts/check_vul4j_offline.py --only VUL4J-24

Writes results/oracle_vul4j/offline_compile.csv.
"""

import argparse
import csv
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import vul4j_baseline as vb  # noqa: E402
from config import SUBSET  # noqa: E402

OUT = PROJECT_ROOT / "results" / "oracle_vul4j" / "offline_compile.csv"
SCRATCH = "/tmp/cweft_offline"


def checkout(vul_id: str) -> str:
    workdir = f"{SCRATCH}/{vul_id}"
    vb.docker_run(["rm", "-rf", workdir], 300)
    vb.docker_run(["mkdir", "-p", SCRATCH], 60)
    res = vb.docker_run(["vul4j", "checkout", "--id", vul_id, "-d", workdir], 1800)
    if res.returncode != 0:
        raise RuntimeError(f"checkout failed: {res.stderr.strip()[-200:]}")
    return workdir


def compile_timed(workdir: str) -> tuple:
    t0 = time.time()
    try:
        ok = vb.compile_ok(workdir)
    except Exception as e:
        return False, round(time.time() - t0, 1), f"{type(e).__name__}"
    return ok, round(time.time() - t0, 1), ""


def failure_hint(workdir: str) -> str:
    log = vb.docker_run(["sh", "-c", f"grep -m3 -E 'ERROR|offline' {workdir}/VUL4J/compile.log"],
                        60).stdout
    return " | ".join(line.strip()[:150] for line in log.splitlines())


def check_one(vul_id: str) -> dict:
    row = {"vul_id": vul_id, "build": "", "offline_ok": "", "prebuilt": False,
           "seconds": "", "note": ""}
    workdir = checkout(vul_id)
    try:
        row["build"] = vb.make_offline(workdir)
        if not row["build"]:
            row["note"] = "neither pom.xml nor build.gradle found"
            return row
        ok, secs, err = compile_timed(workdir)
        if not ok:
            first_hint = err or failure_hint(workdir)
            # Pre-build: one online compile to fill the local repository.
            vb.make_offline(workdir, online=True)
            online_ok, online_secs, _ = compile_timed(workdir)
            vb.make_offline(workdir)
            ok, secs, err = compile_timed(workdir)
            row.update(prebuilt=True,
                       note=f"offline failed first ({first_hint[:200]}); online compile "
                            f"{'ok' if online_ok else 'FAILED'} in {online_secs}s")
            if not ok:
                row["note"] += f"; offline after pre-build failed: {err or failure_hint(workdir)[:200]}"
        row.update(offline_ok=ok, seconds=secs)
        return row
    finally:
        vb.docker_run(["rm", "-rf", workdir], 300)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check every Vul4J entry compiles offline")
    ap.add_argument("--only", nargs="+", default=None)
    args = ap.parse_args(argv)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    done = {}
    if OUT.exists():
        with OUT.open(encoding="utf-8", newline="") as f:
            done = {r["vul_id"]: r for r in csv.DictReader(f)}
    todo = [v for v in (args.only or SUBSET) if v not in done]
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] offline compile check: "
          f"{len(todo)} to do", flush=True)
    for i, vul_id in enumerate(todo, start=1):
        try:
            row = check_one(vul_id)
        except Exception as e:
            row = {"vul_id": vul_id, "build": "", "offline_ok": False, "prebuilt": False,
                   "seconds": "", "note": f"{type(e).__name__}: {e}"[:300]}
        new = not OUT.exists()
        with OUT.open("a", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(row))
            if new:
                w.writeheader()
            w.writerow(row)
        print(f"  ({i}/{len(todo)}) {vul_id:10s} {row['build']:6s} offline_ok={row['offline_ok']} "
              f"{row['seconds']}s {'(pre-built) ' if row['prebuilt'] else ''}{row['note'][:150]}",
              flush=True)
    with OUT.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    bad = [r["vul_id"] for r in rows if r["offline_ok"] != "True"]
    print(f"offline compile check done: {sum(r['offline_ok'] == 'True' for r in rows)} entries "
          f"compile offline ({sum(r['build'] == 'gradle' for r in rows)} of them Gradle); "
          f"failing: {bad or 'none'}", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
