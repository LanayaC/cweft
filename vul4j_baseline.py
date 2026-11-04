"""
Baseline a Vul4J entry: prove its PoV detects the hole, then record the set of
tests a patch will later be judged on. The same rules as patcheval_baseline.py.

Per entry, in a scratch checkout inside a throwaway container of its own (see
container: committed from vul4j-alldeps, no network, removed afterwards; never
the /tmp/cweft checkout that generation and grading use), with Maven and Gradle
offline (see make_offline) and every command under a timeout that kills its whole
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
one that needs the network (there is none; see container), or that disagrees
across runs, is excluded and the reason recorded. Nothing here grades a
model's patch.

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
import os
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Callable, Dict, Iterator, List, Optional

import patcheval_docker as pdock      # the docker helpers only (sh, image_present)
import vul4j_grading as vg
import vuln_data
from config import CONTAINER_NAME, PROJECT_ROOT, SUBSET

# vul4j-alldeps: the container every Vul4J container is committed from. It is
# only ever read, never reconfigured, and CONTAINER_NAME below is rebound per
# container, so this keeps a name for the original.
SOURCE_CONTAINER = CONTAINER_NAME

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


# ── Containers ───────────────────────────────────────────────────────────

GRADER_IMAGE = "cweft/vul4j-grader:latest"
BASE_IMAGE_LABEL = "cweft.base_image"
VUL4J_PREFIX = "cweft_v4_"
COMMIT_TIMEOUT = 3600
NETWORK = "none"
LOOPBACK = "127.0.0.1"


def ensure_grader_image(baselined_image: str = "") -> str:
    """
    GRADER_IMAGE, committed from vul4j-alldeps if it is not there yet.

    The Maven and Gradle caches live in the vul4j-alldeps container, not in its
    image, so an offline build needs a commit of the container rather than the
    image it was started from. With `baselined_image` given, refuses an image
    built on anything else; the baseline passes nothing, because it is the run
    that decides what that image is.
    """
    def label() -> str:
        r = pdock.sh(["docker", "image", "inspect", GRADER_IMAGE, "--format",
                      "{{index .Config.Labels \"" + BASE_IMAGE_LABEL + "\"}}"])
        return r.stdout.strip() if r.rc == 0 else ""

    if not pdock.image_present(GRADER_IMAGE):
        base = pdock.sh(["docker", "inspect", "-f", "{{.Image}}", SOURCE_CONTAINER]).stdout.strip()
        print(f"Committing {SOURCE_CONTAINER} to {GRADER_IMAGE} (once; this takes a few minutes)",
              flush=True)
        r = pdock.sh(["docker", "commit", "--change", f"LABEL {BASE_IMAGE_LABEL}={base}",
                      SOURCE_CONTAINER, GRADER_IMAGE], timeout=COMMIT_TIMEOUT)
        if r.rc != 0:
            raise RuntimeError(f"docker commit failed: {r.stderr[-500:]}")
    if baselined_image and label() != baselined_image:
        raise RuntimeError(f"{GRADER_IMAGE} is built on {label() or 'an unknown image'}, but "
                           f"data/vul4j/baseline.json recorded {baselined_image}")
    return GRADER_IMAGE


def sweep_vul4j_containers() -> List[str]:
    """Remove leftover per-cell Vul4J containers. Returns the names removed."""
    r = pdock.sh(["docker", "ps", "-a", "--filter", f"name=^{VUL4J_PREFIX}",
                  "--format", "{{.Names}}"])
    names = [n for n in r.stdout.split() if n.startswith(VUL4J_PREFIX)]
    for n in names:
        pdock.sh(["docker", "rm", "-f", n])
    return names


@contextmanager
def container(image: str = "",
              before_remove: Optional[Callable[[str], None]] = None) -> Iterator[str]:
    """
    A throwaway container for one entry or one cell, as CONTAINER_NAME here and
    in vuln_data for as long as the block runs. Removed afterwards, whatever
    happened inside.

    It runs with --network none, as every PatchEval container does
    (patcheval_docker.start_container). A test that reaches the network passes
    or fails by what is on the other end, so with a network it can pass all
    three reference runs, enter the judged set, and then fail during grading
    for a reason that has nothing to do with the patch - which is how machine
    load became a verdict. With no network such a test fails the same way in
    every run and is excluded, consistently, at baseline time.

    --network none also leaves /etc/hosts without a line for the container's
    own name, and InetAddress.getLocalHost() then throws UnknownHostException,
    which kills anything that serves from inside the container: WildFly for
    VUL4J-66, cargo's Jetty and Tomcat for VUL4J-45. So the name is mapped to
    loopback, which reaches nothing a bare --network none could not reach -
    there is still no interface, no DNS and no route off the container - while
    a server a test starts can bind and be called. A test that wants the
    internet still fails the same way in every run.

    `before_remove` is called with the container's name while it still exists,
    for anything that must be read out of it first.
    """
    global CONTAINER_NAME
    name = f"{VUL4J_PREFIX}{os.getpid()}_{uuid.uuid4().hex[:8]}"
    ref = image or ensure_grader_image()
    r = pdock.sh(["docker", "run", "-d", "--name", name, "--network", NETWORK,
                  "--hostname", name, "--add-host", f"{name}:{LOOPBACK}",
                  "--pull", "never", ref, "tail", "-f", "/dev/null"], timeout=300)
    if r.rc != 0:
        raise RuntimeError(f"docker run {ref} failed: {r.stderr[-500:]}")
    previous = CONTAINER_NAME
    CONTAINER_NAME = vuln_data.CONTAINER_NAME = name
    try:
        yield name
    finally:
        if before_remove is not None:
            before_remove(name)
        CONTAINER_NAME = vuln_data.CONTAINER_NAME = previous
        pdock.sh(["docker", "rm", "-f", name])


MAVEN, GRADLE = "maven", "gradle"
GRADLE_MARKER = ".cweft-offline"
GRADLE_INIT = "/root/.gradle/init.d/cweft-offline.gradle"
# Vul4J's Gradle commands cannot be given --offline, so an init script (read
# by every Gradle build in the container) sets the same switch, but only for a
# build whose root directory holds the marker that make_offline writes.
GRADLE_INIT_SCRIPT = """\
// Installed by CWEFT (vul4j_baseline.make_offline). A build whose root holds
// .cweft-offline runs as if --offline were given; every other build is untouched.
if (new File(gradle.startParameter.currentDir, ".cweft-offline").exists()) {
    gradle.startParameter.offline = true
    gradle.settingsEvaluated { println "CWEFT: Gradle offline=" + gradle.startParameter.offline }
}
"""


def make_offline(workdir: str, online: bool = False) -> str:
    """
    Make this checkout's build resolve dependencies from the local caches only,
    and return its build system ("maven" or "gradle"; "" if neither).

    Maven: -o in .mvn/maven.config, which Maven 3.3+ reads from the project
    root, appended to any config the project already has. Gradle: the marker
    file GRADLE_INIT_SCRIPT looks for. online=True removes either again, for a
    one-off online build that fills the caches.
    """
    if docker_run(["test", "-f", f"{workdir}/pom.xml"], 60).returncode == 0:
        if online:
            script = 'f="$1/.mvn/maven.config"; [ -f "$f" ] && sed -i "/^-o$/d" "$f"; true'
        else:
            script = ('mkdir -p "$1/.mvn" && f="$1/.mvn/maven.config" && '
                      '(grep -qx -- -o "$f" 2>/dev/null || echo -o >> "$f")')
        system = MAVEN
    elif docker_run(["sh", "-c", 'for f in build.gradle build.gradle.kts settings.gradle '
                                 'settings.gradle.kts gradlew; do [ -e "$1/$f" ] && exit 0; done; exit 1',
                     "sh", workdir], 60).returncode == 0:
        install = docker_run(["sh", "-c", f'mkdir -p "$(dirname {GRADLE_INIT})" && cat > {GRADLE_INIT}'],
                             60, input_text=GRADLE_INIT_SCRIPT)
        if install.returncode != 0:
            raise RuntimeError(f"could not install {GRADLE_INIT}: {install.stderr.strip()}")
        script = (f'rm -f "$1/{GRADLE_MARKER}"' if online else f'touch "$1/{GRADLE_MARKER}"')
        system = GRADLE
    else:
        return ""
    res = docker_run(["sh", "-c", script, "sh", workdir], 60)
    if res.returncode != 0:
        raise RuntimeError(f"could not set {workdir} {'online' if online else 'offline'}: "
                           f"{res.stderr.strip()}")
    return system


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


def compile_failure_reason(workdir: str, limit: int = 400) -> str:
    """
    Why the last compile failed, taken from the log it already wrote: Maven's
    "Failed to execute goal" line names both the plugin and the cause. An entry
    that leaves the subset should say why in the file rather than leave the
    next person to reproduce the failure to find out.
    """
    log = _exec(["cat", f"{workdir}/VUL4J/compile.log"], 60).stdout or ""
    lines = [ln.strip() for ln in log.splitlines()]
    for want in ("Failed to execute goal", "UnknownHostException", "BUILD FAILURE"):
        for ln in lines:
            if want in ln:
                return ln[:limit]
    errors = [ln for ln in lines if "[ERROR]" in ln]
    return errors[-1][:limit] if errors else ""


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
            return done("compile_failed_original", compile_failure_reason(workdir))
        t0 = time.time()
        res = run_tests(workdir)
        original = vg.fold_results(res)
        entry["original_run"] = _run_summary(res, original, time.time() - t0)
        log(f"    original: {entry['original_run']['counts']} in {entry['original_run']['seconds']}s")

        entry["phase"] = "reference"
        entry["reference_files"] = apply_reference(workdir)
        if not compile_ok(workdir):
            return done("compile_failed_reference", compile_failure_reason(workdir))
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
    return {"schema": SCHEMA, "container": SOURCE_CONTAINER, "entries": {}}


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
    image = subprocess.run(["docker", "inspect", "-f", "{{.Image}}", SOURCE_CONTAINER],
                           capture_output=True, text=True).stdout.strip()
    data["image"] = image
    # Every entry runs in a container from this image, as grading does, so the
    # judged sets are derived in the same environment they are later used in.
    data["grader_image"] = ensure_grader_image()
    data["network"] = NETWORK
    for name in sweep_vul4j_containers():
        print(f"removed a leftover container: {name}", flush=True)
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
            with container():
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
