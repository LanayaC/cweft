"""
Baseline a Vul4J entry: prove its PoV detects the hole, then record the set of
tests a patch will later be judged on. The same rules as patcheval_baseline.py.

Per entry, in a scratch checkout inside the vul4j-alldeps container (never the
/tmp/cweft checkout that generation and grading use), with Maven offline (-o,
see make_offline) and every command under a timeout that kills its whole
process tree inside the container (see docker_run):

  1. the vulnerable file on disk has the SHA-256 of the exported copy in
     data/vul4j/ (scripts/export_vul4j_sources.py)
  2. the original code compiles, and `vul4j test` runs once on it
  3. the reference fix (Vul4J's human patch) is applied, compiles, and
     `vul4j test` runs RUNS (3) times on it
  4. the PoV tests - Vul4J's failing_tests column - are matched to tests that
     really ran (vul4j_grading.resolve_pov); at least one must FAIL on the
     original (the hole is there), and all must PASS in every reference run

The judged set is the tests that passed in ALL reference runs, PoV excluded
(vul4j_grading.judged_set). A test that fails on the reference fix, such as
one that needs the network, or that disagrees across runs, is excluded and
the reason recorded. Nothing here grades a model's patch.

    python vul4j_baseline.py                    # every entry in config.SUBSET
    python vul4j_baseline.py --only VUL4J-77 --redo
    python vul4j_baseline.py --retry-errors     # redo crashed/timed-out entries too

Writes data/vul4j/baseline.json, merging one entry per vulnerability and
saving after each, so a crash loses at most the entry in flight. An entry
already in the file is skipped unless --redo. A failing entry is recorded
with its status and the batch carries on.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import vul4j_grading as vg
import vuln_data
from config import CONTAINER_NAME, PROJECT_ROOT, SUBSET

BASELINE_PATH = PROJECT_ROOT / "data" / "vul4j" / "baseline.json"
SCHEMA = "cweft-vul4j-baseline/1"
SCRATCH = "/tmp/cweft_baseline"

RUNS = 3
COMPILE_TIMEOUT = 1800
TEST_TIMEOUT = 2700       # the slowest suite (VUL4J-61) takes about 12 minutes

OK = "ok"
FINGERPRINTED = ["vul4j_grading.py", "vul4j_baseline.py"]


def code_fingerprint() -> str:
    h = hashlib.sha256()
    for mod in FINGERPRINTED:
        h.update((PROJECT_ROOT / mod).read_bytes())
    return h.hexdigest()[:12]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Docker ───────────────────────────────────────────────────────────────

KILL_GRACE = 30          # seconds between TERM and KILL inside the container
HOST_SLACK = 120         # the host gives up this long after the container should have
# Gradle normally hands the build to a daemon in its own session, which a
# process-group kill cannot reach. Without the daemon the build stays in the group.
CONTAINER_ENV = {"GRADLE_OPTS": "-Dorg.gradle.daemon=false"}
TIMED_OUT = (124, 137)   # GNU timeout: TERM sent (124), or KILL after the grace (137)


def docker_run(cmd: List[str], timeout: int, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    """
    Run `cmd` in the container, killing the whole process tree on timeout.

    Killing the `docker exec` client does not stop the command inside the
    container, so the limit is enforced in there: GNU timeout runs the command
    in its own process group and signals the whole group (Maven and the test
    JVMs it forks) when time is up, then KILLs it KILL_GRACE seconds later.
    Output goes to temporary files, not pipes: on Windows a pipe stays open,
    and a wait on it blocks, for as long as anything inside still holds it.

    Raises subprocess.TimeoutExpired when the limit was hit; stdin is closed
    unless `input_text` is given (Gradle reads stdin otherwise).
    """
    env = [a for k, v in CONTAINER_ENV.items() for a in ("-e", f"{k}={v}")]
    full = (["docker", "exec", "-i"] + env + [CONTAINER_NAME,
            "timeout", "-k", str(KILL_GRACE), str(int(timeout))] + list(cmd))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        started = time.time()
        proc = subprocess.Popen(full, stdout=out, stderr=err,
                                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL)
        try:
            if input_text is not None:
                proc.stdin.write(input_text.encode("utf-8"))
                proc.stdin.close()
            rc = proc.wait(timeout=timeout + KILL_GRACE + HOST_SLACK)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise
        out.seek(0)
        err.seek(0)
        stdout = out.read().decode("utf-8", "replace")
        stderr = err.read().decode("utf-8", "replace")
    if rc in TIMED_OUT and time.time() - started >= timeout:
        raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(cmd, rc, stdout, stderr)


_exec = docker_run


def make_offline(workdir: str) -> bool:
    """
    Make Maven run offline in this checkout (-o via .mvn/maven.config, which
    Maven 3.3+ reads from the project root), appending to a config the project
    already has. Returns False for a Gradle project, which is left as it is.
    """
    probe = docker_run(["test", "-f", f"{workdir}/pom.xml"], 60)
    if probe.returncode != 0:
        return False
    script = ('mkdir -p "$1/.mvn" && f="$1/.mvn/maven.config" && '
              '(grep -qx -- -o "$f" 2>/dev/null || echo -o >> "$f")')
    res = docker_run(["sh", "-c", script, "sh", workdir], 60)
    if res.returncode != 0:
        raise RuntimeError(f"could not make {workdir} offline: {res.stderr.strip()}")
    return True


def checkout(vul_id: str) -> str:
    workdir = f"{SCRATCH}/{vul_id}"
    _exec(["rm", "-rf", workdir], 300)
    _exec(["mkdir", "-p", SCRATCH], 60)
    res = _exec(["vul4j", "checkout", "--id", vul_id, "-d", workdir], 1800)
    if res.returncode != 0:
        raise RuntimeError(f"vul4j checkout failed: {res.stderr.strip()[-300:]}")
    make_offline(workdir)
    return workdir


def remove_checkout(vul_id: str) -> None:
    _exec(["rm", "-rf", f"{SCRATCH}/{vul_id}"], 300)


def compile_ok(workdir: str) -> bool:
    res = _exec(["vul4j", "compile", "-d", workdir], COMPILE_TIMEOUT)
    log = _exec(["cat", f"{workdir}/VUL4J/compile.log"], 60).stdout
    return res.returncode == 0 and "BUILD FAILURE" not in (res.stdout + log)


def run_tests(workdir: str, timeout: int = TEST_TIMEOUT) -> Optional[dict]:
    """`vul4j test` once; its testing_results.json, or None if it wrote none."""
    _exec(["vul4j", "test", "-d", workdir], timeout)
    out = _exec(["cat", f"{workdir}/VUL4J/testing_results.json"], 60)
    if out.returncode != 0 or not out.stdout.strip():
        return None
    return json.loads(out.stdout)


_APPLY_REFERENCE = """
import json, sys
d = sys.argv[1]
info = json.load(open(d + "/VUL4J/vulnerability_info.json"))
for h in info["human_patch"]:
    with open(d + "/" + h["file_path"], "w") as f:
        f.write(h["content"])
    print(h["file_path"])
"""


def apply_reference(workdir: str) -> List[str]:
    """Write Vul4J's human-patched file(s) into the checkout, inside the container."""
    res = _exec(["python3", "-", workdir], 120, input_text=_APPLY_REFERENCE)
    if res.returncode != 0:
        raise RuntimeError(f"could not apply the reference fix: {res.stderr.strip()[-300:]}")
    return res.stdout.split()


def file_sha256(workdir: str, rel: str) -> str:
    res = subprocess.run(["docker", "exec", CONTAINER_NAME, "cat", f"{workdir}/{rel}"],
                         capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
    return hashlib.sha256(res.stdout).hexdigest()


# ── One entry ────────────────────────────────────────────────────────────

def _run_summary(results: Optional[dict], folded: Dict[str, str], seconds: float) -> dict:
    failing = sorted(n for n, s in folded.items() if s == vg.FAILED)
    counts = {s: sum(1 for v in folded.values() if v == s)
              for s in (vg.PASSED, vg.FAILED, vg.SKIPPED)}
    return {"seconds": round(seconds, 1), "results_written": results is not None,
            "counts": counts, "failing": failing}


def baseline_one(vul_id: str, log=print) -> dict:
    payload = vuln_data.get_vuln_payload(vul_id)
    manifest = vuln_data._vul4j_manifest()[vul_id]
    entry = {
        "vul_id": vul_id,
        "started_at": _now(),
        "code_fingerprint": code_fingerprint(),
        "primary_file": payload["primary_file"],
        "pov_raw": list(payload["failing_tests"]),
        "pov_source": manifest.get("failing_tests_source", ""),
        "status": "error",
        "phase": "checkout",
    }
    t_start = time.time()

    def done(status: str, message: str = "") -> dict:
        entry["status"] = status
        entry["ok"] = status == OK
        if message:
            entry["message"] = message
        entry["finished_at"] = _now()
        entry["elapsed_seconds"] = round(time.time() - t_start, 1)
        return entry

    workdir = checkout(vul_id)
    try:
        entry["phase"] = "frozen_file"
        sha = file_sha256(workdir, payload["primary_file"])
        entry["frozen_file"] = {"sha256": sha, "matches_exported_copy": sha == manifest["sha256"]}
        if sha != manifest["sha256"]:
            return done("frozen_file_mismatch", "the checkout's file differs from data/vul4j/")

        entry["phase"] = "original"
        if not compile_ok(workdir):
            return done("compile_failed_original")
        t0 = time.time()
        res = run_tests(workdir)
        original = vg.fold_results(res)
        entry["original_run"] = _run_summary(res, original, time.time() - t0)
        log(f"    original: {entry['original_run']['counts']} in {entry['original_run']['seconds']}s")

        entry["phase"] = "reference"
        entry["reference_files"] = apply_reference(workdir)
        if not compile_ok(workdir):
            return done("compile_failed_reference")
        runs, summaries = [], []
        for i in range(RUNS):
            t0 = time.time()
            res = run_tests(workdir)
            folded = vg.fold_results(res)
            runs.append(folded)
            summaries.append(_run_summary(res, folded, time.time() - t0))
            log(f"    reference run {i + 1}/{RUNS}: {summaries[-1]['counts']} in {summaries[-1]['seconds']}s")
        entry["reference_runs"] = summaries

        entry["phase"] = "pov"
        observed = set(original)
        for run in runs:
            observed.update(run)
        pov, unresolved, notes = vg.resolve_pov(entry["pov_raw"], observed)
        entry["pov"] = pov
        entry["pov_notes"] = notes
        if unresolved or not pov:
            entry["pov_unresolved"] = unresolved
            return done("pov_not_found", "PoV tests not among the tests that ran: "
                        + ", ".join(unresolved or entry["pov_raw"]))
        on_original = {p: original.get(p, vg.MISSING) for p in pov}
        entry["pov_on_original"] = on_original
        entry["pov_on_reference"] = [{p: run.get(p, vg.MISSING) for p in pov} for run in runs]
        if not any(s == vg.FAILED for s in on_original.values()):
            return done("pov_not_failing_on_original")
        if not all(vg.pov_outcome(pov, run)[0] for run in runs):
            return done("pov_not_passing_on_reference")

        entry["phase"] = "judged"
        judged, excluded = vg.judged_set(runs, pov)
        entry["judged"] = judged
        entry["judged_count"] = len(judged)
        entry["excluded"] = excluded
        entry["excluded_count"] = len(excluded)
        if not judged:
            return done("no_judged_set")
        entry["phase"] = "done"
        return done(OK)
    finally:
        remove_checkout(vul_id)


# ── The file ─────────────────────────────────────────────────────────────

def load() -> dict:
    if BASELINE_PATH.exists():
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    return {"schema": SCHEMA, "container": CONTAINER_NAME, "entries": {}}


def save(data: dict) -> None:
    data["generated_at"] = _now()
    tmp = BASELINE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=False) + "\n", encoding="utf-8", newline="\n")
    tmp.replace(BASELINE_PATH)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Baseline the Vul4J entries (judged sets)")
    ap.add_argument("--only", nargs="+", default=None, help="these VUL4J ids only")
    ap.add_argument("--redo", action="store_true", help="redo entries already in the file")
    ap.add_argument("--retry-errors", action="store_true",
                    help="redo entries whose status is 'error' (a crash or timeout), keep the rest")
    args = ap.parse_args(argv)

    data = load()
    image = subprocess.run(["docker", "inspect", "-f", "{{.Image}}", CONTAINER_NAME],
                           capture_output=True, text=True).stdout.strip()
    data["image"] = image
    def wanted(v: str) -> bool:
        if args.redo or v not in data["entries"]:
            return True
        return args.retry_errors and data["entries"][v].get("status") == "error"

    todo = [v for v in (args.only or SUBSET) if wanted(v)]
    print(f"[{_now()}] baseline: {len(todo)} to do, {len(data['entries'])} already in "
          f"{BASELINE_PATH}", flush=True)
    t_batch = time.time()
    for i, vul_id in enumerate(todo, start=1):
        print(f"[{_now()}] ({i}/{len(todo)}) {vul_id}", flush=True)
        try:
            entry = baseline_one(vul_id, log=lambda m: print(m, flush=True))
        except Exception as e:
            entry = {"vul_id": vul_id, "status": "error", "ok": False,
                     "message": f"{type(e).__name__}: {e}", "finished_at": _now()}
        data["entries"][vul_id] = entry
        save(data)
        print(f"    -> {entry['status']}"
              + (f"  judged={entry.get('judged_count')} excluded={entry.get('excluded_count')}"
                 if entry["status"] == OK else f"  {entry.get('message', '')}")
              + f"  ({entry.get('elapsed_seconds', '?')}s)", flush=True)
    counts: Dict[str, int] = {}
    for e in data["entries"].values():
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    print(f"[{_now()}] baseline done in {round((time.time() - t_batch) / 60, 1)} min: {counts}",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
