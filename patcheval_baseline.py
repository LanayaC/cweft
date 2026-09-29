"""
Baseline a PatchEval CVE: prove its image can be trusted, then record the set
of tests a patch will later be judged on.

Per CVE, inside the image (run by digest, no network):

  1. the vulnerable file in the repo has the sha256 of the frozen copy in
     data/patcheval/files/
  2. the L0 check passes on that file and fails on a deliberately broken copy
  3. vul-run.sh FAILS (the bug is really there) and fix-run.sh PASSES (the
     reference fix really fixes it)
  4. the repo's own test command runs 3x on the original code and 3x on the
     reference-fixed code, parsed by patcheval_testparse

The judged set is the tests that passed in ALL THREE reference-fixed runs.
A test that fails on the reference, or disagrees across the three runs, is
excluded and the reason recorded. Nothing here grades a model's patch.

The test command comes from the image's own unit_test.sh where there is one
(its `git apply .../fix.patch` line removed: this module controls when the
fix is applied), otherwise from a per-language default. Either way the
runner is given the flags that make its output machine-readable, and every
change is recorded in the baseline.

    python patcheval_baseline.py CVE-2017-0360
    python patcheval_baseline.py CVE-2017-0360 CVE-2023-24623 --keep-image

Writes data/patcheval/baseline.json, merging one entry per CVE.
"""

import argparse
import hashlib
import json
import re
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from posixpath import splitext

from config import PATCHEVAL_DIR
import patcheval_docker as pdock
import patcheval_l0 as pl0
import patcheval_testparse as ptp


BASELINE_PATH = PATCHEVAL_DIR / "baseline.json"
SCHEMA = "cweft-patcheval-baseline/1"

WORKSPACE = "/workspace"
FIX_RUN = f"{WORKSPACE}/fix-run.sh"
VUL_RUN = f"{WORKSPACE}/vul-run.sh"
FIX_PATCH = f"{WORKSPACE}/fix.patch"
UNIT_TEST = f"{WORKSPACE}/unit_test.sh"

RUNS = 3
MIN_TIMEOUT = 120          # never give a command less than this
MAX_TIMEOUT = 900          # 15 min cap, per the per-CVE limit
TIMEOUT_FACTOR = 3         # ... = max(3x observed, MIN), capped at MAX
ADMIN_TIMEOUT = 180        # resets, patch applies, cat, small queries

# Appended to make a copy of the file that no parser accepts, to prove the
# L0 check can fail. "<<<" starts no valid construct in any of the four.
BROKEN_SUFFIX = b"\n<<< cweft broken syntax >>>\n"

REPORT_XML = "/tmp/cweft_report.xml"
REPORT_JSON = "/tmp/cweft_report.json"

_CD_WORKSPACE = re.compile(r"^\s*cd\s+(/workspace/[^\s;&|]+)", re.M)
_GIT_APPLY_FIX = re.compile(r"git\s+apply\b.*fix\.patch")
_UNITTEST = re.compile(r"(?P<py>\S*python[0-9.]*)\s+-m\s+unittest\s+(?P<args>.*)$")

SHIM_PATH = "/tmp/cweft_unittest_junit.py"

# `python -m unittest` prints only prose, and several images are Python 2
# with no pytest to run the same modules. This runs the very same test
# modules through unittest itself and writes JUnit XML, which
# patcheval_testparse already reads. Python 2.7 and 3.x both run it.
UNITTEST_SHIM = '''
import sys, unittest
import xml.etree.ElementTree as ET

out, names = sys.argv[1], sys.argv[2:]
loader = unittest.TestLoader()
suite = loader.loadTestsFromNames(names) if names else loader.discover(".")


def clean(text):
    text = (text or "")[:2000]
    return "".join(c for c in text if c == "\\n" or c == "\\t" or c >= " ")


class Collector(unittest.TestResult):
    def __init__(self):
        unittest.TestResult.__init__(self)
        self.records = []

    def addSuccess(self, test):
        self.records.append((test, "passed", ""))

    def addFailure(self, test, err):
        self.records.append((test, "failure", self._exc_info_to_string(err, test)))

    def addError(self, test, err):
        self.records.append((test, "error", self._exc_info_to_string(err, test)))

    def addSkip(self, test, reason):
        self.records.append((test, "skipped", reason))

    def addExpectedFailure(self, test, err):
        self.records.append((test, "passed", ""))

    def addUnexpectedSuccess(self, test):
        self.records.append((test, "failure", "unexpected success"))


result = Collector()
suite.run(result)

root = ET.Element("testsuite", {"name": "unittest", "tests": str(len(result.records))})
for test, outcome, detail in result.records:
    test_id = test.id()
    classname, _, method = test_id.rpartition(".")
    case = ET.SubElement(root, "testcase", {"classname": classname, "name": method})
    if outcome != "passed":
        detail = clean(detail)
        first = detail.strip().split("\\n")[-1][:200] if detail.strip() else outcome
        node = ET.SubElement(case, outcome, {"message": first})
        node.text = detail
ET.ElementTree(root).write(out, encoding="utf-8")
sys.exit(1 if [r for r in result.records if r[1] in ("failure", "error")] else 0)
'''


class BaselineError(RuntimeError):
    """This CVE cannot be baselined; the entry records why."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def budget(observed_seconds: float) -> int:
    """Timeout for a repeat of something that took `observed_seconds`."""
    return int(min(max(TIMEOUT_FACTOR * observed_seconds, MIN_TIMEOUT), MAX_TIMEOUT))


def manifest() -> dict:
    entries = json.loads((PATCHEVAL_DIR / "manifest.json").read_text(encoding="utf-8"))
    return {e["cve_id"]: e for e in entries}


def frozen_bytes(cve: str, entry: dict) -> bytes:
    """The frozen vulnerable file, checked against its recorded sha256."""
    path = PATCHEVAL_DIR / "files" / cve / entry["vulnerable_file_path"]
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != entry["sha256"]:
        raise BaselineError(f"{path} has sha256 {digest}, manifest says {entry['sha256']}")
    return data


# ── Container-side helpers ───────────────────────────────────────────────

def _run(name: str, cmd: str, timeout: float = ADMIN_TIMEOUT, what: str = ""):
    r = pdock.exec_in(name, cmd, timeout=timeout)
    if r.timed_out:
        raise BaselineError(f"{what or cmd} timed out after {timeout}s")
    return r


def find_repo_dir(name: str) -> str:
    """The repo directory, from the `cd /workspace/<repo>` line in fix-run.sh."""
    r = _run(name, f"cat {FIX_RUN}", what="read fix-run.sh")
    if r.rc != 0:
        raise BaselineError(f"cannot read {FIX_RUN}: {r.stderr.strip()[:200]}")
    found = _CD_WORKSPACE.findall(r.stdout)
    if not found:
        raise BaselineError(f"{FIX_RUN} has no `cd {WORKSPACE}/...` line")
    repo_dir = found[0].rstrip("/")
    q = shlex.quote(repo_dir)
    if _run(name, f"cd {q} && git rev-parse --is-inside-work-tree").rc != 0:
        raise BaselineError(f"{repo_dir} is not a git work tree")
    return repo_dir


def reset_repo(name: str, repo_dir: str) -> None:
    """Back to the committed state: no patch, no files a run left behind."""
    q = shlex.quote(repo_dir)
    r = _run(name, f"cd {q} && git reset --hard -q && git clean -fdq", what="git reset")
    if r.rc != 0:
        raise BaselineError(f"resetting {repo_dir} failed: {(r.stderr or r.stdout).strip()[:200]}")


def apply_fix(name: str, repo_dir: str) -> None:
    """Apply fix.patch, with the fallback chain fix-run.sh itself uses."""
    q, p = shlex.quote(repo_dir), shlex.quote(FIX_PATCH)
    cmd = (
        f"cd {q} && "
        f"if git apply --check --whitespace=nowarn {p} 2>/dev/null; then "
        f"  git apply --whitespace=nowarn {p}; "
        f"elif git apply --reverse --check --whitespace=nowarn {p} 2>/dev/null; then "
        f"  echo 'patch already applied'; "
        f"elif git apply --check --3way --whitespace=nowarn {p} 2>/dev/null; then "
        f"  git apply --3way --whitespace=nowarn {p}; "
        f"else echo 'git apply failed' >&2; exit 1; fi"
    )
    r = _run(name, cmd, what="git apply fix.patch")
    if r.rc != 0:
        raise BaselineError(f"applying {FIX_PATCH} failed: {(r.stderr or r.stdout).strip()[:200]}")


def file_exists(name: str, path: str) -> bool:
    return _run(name, f"test -f {shlex.quote(path)}").rc == 0


# ── Checks 1-3 ───────────────────────────────────────────────────────────

def check_frozen_file(name: str, repo_dir: str, rel_path: str, data: bytes) -> dict:
    in_container = pdock.file_sha256(name, f"{repo_dir}/{rel_path}")
    expected = hashlib.sha256(data).hexdigest()
    if in_container != expected:
        raise BaselineError(
            f"{repo_dir}/{rel_path} in the image has sha256 {in_container}, "
            f"the frozen copy has {expected}"
        )
    return {"sha256": expected, "matches_frozen_copy": True}


def check_l0(name: str, repo_dir: str, rel_path: str, data: bytes) -> dict:
    """L0 passes on the real file and fails on a broken copy of it."""
    good = pl0.check_l0(name, repo_dir, rel_path)
    if not good.passed:
        raise BaselineError(f"L0 failed on the unmodified file: {good.error_tail[:200]}")

    target = f"{repo_dir}/{rel_path}"
    try:
        pdock.write_file_bytes(name, target, data + BROKEN_SUFFIX)
        broken = pl0.check_l0(name, repo_dir, rel_path)
    finally:
        pdock.write_file_bytes(name, target, data)   # verifies the sha256 again
    if broken.passed:
        raise BaselineError(f"L0 passed on a deliberately broken file ({good.checker})")

    return {
        "checker": good.checker,
        "tool_version": good.version,
        "passes_on_original": True,
        "fails_on_broken_copy": True,
        "broken_copy_error_tail": broken.error_tail[:300],
    }


def check_poc_polarity(name: str, repo_dir: str) -> dict:
    """vul-run.sh must fail (bug present) and fix-run.sh must pass (fix works)."""
    reset_repo(name, repo_dir)
    vul = pdock.exec_in(name, f"bash {VUL_RUN}", timeout=MAX_TIMEOUT)
    if vul.timed_out:
        raise BaselineError(f"vul-run.sh timed out after {MAX_TIMEOUT}s")
    if vul.rc == 0:
        raise BaselineError("vul-run.sh passed on the vulnerable code: the PoC does not show the bug")

    reset_repo(name, repo_dir)
    fix_timeout = budget(vul.seconds)
    fix = pdock.exec_in(name, f"bash {FIX_RUN}", timeout=fix_timeout)
    if fix.timed_out:
        raise BaselineError(f"fix-run.sh timed out after {fix_timeout}s")
    if fix.rc != 0:
        tail = (fix.stdout + fix.stderr).strip()[-300:]
        raise BaselineError(f"fix-run.sh failed on the reference fix (rc={fix.rc}): {tail}")
    reset_repo(name, repo_dir)

    return {
        "vul_run": {"rc": vul.rc, "seconds": vul.seconds, "failed_as_expected": True},
        "fix_run": {"rc": fix.rc, "seconds": fix.seconds, "passed_as_expected": True,
                    "timeout_used": fix_timeout},
    }


# ── The test command ─────────────────────────────────────────────────────

class TestPlan:
    """How to run the repo's tests and read the result."""

    def __init__(self, command: str, source: str, fmt: str,
                 output_file: str = "", notes=None, runner: str = ""):
        self.command = command
        self.source = source          # "unit_test.sh" or "language_default"
        self.fmt = fmt                # a patcheval_testparse format name
        self.output_file = output_file  # "" when the report is on stdout
        self.notes = list(notes or [])
        self.runner = runner

    def as_dict(self) -> dict:
        return {"command": self.command, "source": self.source, "runner": self.runner,
                "format": self.fmt, "output_file": self.output_file, "notes": self.notes}


# Turning a plain runner invocation into one that emits a parseable report.
# Each rule: (does this line invoke the runner?, how to instrument it, format,
# where the report lands).
_INSTRUMENT = [
    (re.compile(r"\bpytest\b"),
     lambda line: f"{line} --junitxml={REPORT_XML} -p no:cacheprovider",
     "junit_xml", REPORT_XML, "pytest"),
    (re.compile(r"\bgo\s+test\b"),
     lambda line: re.sub(r"\bgo\s+test\b", "go test -json", line, count=1),
     "go_json", "", "go test"),
    (re.compile(r"\bjest\b"),
     lambda line: f"{line} --json --outputFile={REPORT_JSON} --ci",
     "jest_json", REPORT_JSON, "jest"),
    # --reporter-option output=, not a shell redirect: the suite's own
    # console output lands on stdout interleaved with the report otherwise.
    (re.compile(r"\bmocha\b"),
     lambda line: f"{line} --reporter json --reporter-option output={REPORT_JSON}",
     "mocha_json", REPORT_JSON, "mocha"),
    (re.compile(r"\bnode\s+--test\b"),
     lambda line: f"{line} --test-reporter=tap",
     "tap", "", "node --test"),
    # --junit-path, not --reporter=junit: deno prints "Check file:///..."
    # around the report otherwise.
    (re.compile(r"\bdeno\s+test\b"),
     lambda line: f"{line} --junit-path={REPORT_XML}",
     "junit_xml", REPORT_XML, "deno test"),
]


def _unittest_line(name: str, line: str):
    """`python -m unittest MODULE...` -> the same modules through the shim."""
    m = _UNITTEST.search(line)
    if not m:
        return None
    args = shlex.split(m.group("args"))
    modules = [a for a in args if not a.startswith("-")]
    dropped = [a for a in args if a.startswith("-")]
    if any(a == "discover" for a in modules):
        modules = [a for a in modules if a != "discover"]
    py = m.group("py")
    pdock.write_file_bytes(name, SHIM_PATH, UNITTEST_SHIM.encode("utf-8"))
    new = f"{py} {SHIM_PATH} {REPORT_XML} {' '.join(shlex.quote(x) for x in modules)}".strip()
    note = (f"unittest has no machine-readable output; ran the same modules "
            f"({', '.join(modules) or 'discovered'}) through the JUnit XML shim")
    if dropped:
        note += f"; dropped unittest flags {' '.join(dropped)}"
    return line[:m.start()] + new, note


def _instrument_script(text: str, name: str):
    """
    Instrument the runner line in a shell script. Returns
    (new_text, fmt, output_file, runner, notes) or raises if no rule matches.
    """
    lines = text.splitlines()
    notes, kept = [], []
    for line in lines:
        if _GIT_APPLY_FIX.search(line):
            notes.append(f"removed the fix.patch line: {line.strip()}")
            continue
        kept.append(line)

    for i, line in enumerate(kept):
        if line.strip().startswith("#"):
            continue
        shimmed = _unittest_line(name, line)
        if shimmed:
            kept[i], note = shimmed
            notes.append(note)
            return "\n".join(kept), "junit_xml", REPORT_XML, "unittest (JUnit XML shim)", notes
        for pattern, instrument, fmt, out, runner in _INSTRUMENT:
            if pattern.search(line):
                kept[i] = instrument(line)
                notes.append(f"instrumented for {fmt}: {line.strip()} -> {kept[i].strip()}")
                return "\n".join(kept), fmt, out, runner, notes
    raise BaselineError(
        "unit_test.sh names no test runner this module can make machine-readable "
        f"(known: pytest, unittest, go test, jest, mocha, node --test, deno test)"
    )


def _read_json(name: str, repo_dir: str, path: str) -> dict:
    r = _run(name, f"cd {shlex.quote(repo_dir)} && cat {shlex.quote(path)}")
    if r.rc != 0:
        return {}
    try:
        return json.loads(r.stdout)
    except ValueError:
        return {}


def _has_dep(pkg: dict, *names: str) -> bool:
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
    scripts = " ".join((pkg.get("scripts") or {}).values())
    return any(n in deps or re.search(rf"\b{re.escape(n)}\b", scripts) for n in names)


def _python_with_pytest(name: str, repo_dir: str) -> str:
    """The first interpreter that has pytest: the PoC env's, then the image's."""
    candidates = []
    try:
        candidates.append(pl0.python_interpreter(name))
    except pl0.L0SetupError:
        pass
    candidates += ["python3", "python"]
    for py in candidates:
        if _run(name, f"cd {shlex.quote(repo_dir)} && {shlex.quote(py)} -m pytest --version").rc == 0:
            return py
    raise BaselineError(f"no interpreter with pytest among {candidates}")


def _default_plan(name: str, repo_dir: str, rel_path: str) -> TestPlan:
    ext = splitext(rel_path)[1]
    notes = ["no unit_test.sh in the image; used the per-language default"]

    if ext == ".py":
        try:
            py = _python_with_pytest(name, repo_dir)
        except BaselineError:
            py = pl0.python_interpreter(name)
            pdock.write_file_bytes(name, SHIM_PATH, UNITTEST_SHIM.encode("utf-8"))
            return TestPlan(f"{shlex.quote(py)} {SHIM_PATH} {REPORT_XML}", "language_default",
                            "junit_xml", REPORT_XML,
                            notes + [f"no pytest; unittest discovery through the JUnit XML "
                                     f"shim with {py}"], "unittest (JUnit XML shim)")
        cmd = f"{shlex.quote(py)} -m pytest -q --junitxml={REPORT_XML} -p no:cacheprovider"
        return TestPlan(cmd, "language_default", "junit_xml", REPORT_XML,
                        notes + [f"pytest via {py}"], "pytest")

    if ext == ".go":
        return TestPlan("GOPROXY=off go test -json ./...", "language_default", "go_json",
                        "", notes + ["offline: GOPROXY=off"], "go test")

    if ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"):
        pkg = _read_json(name, repo_dir, "package.json")
        if _has_dep(pkg, "jest"):
            return TestPlan(f"npx --no-install jest --json --outputFile={REPORT_JSON} --ci",
                            "language_default", "jest_json", REPORT_JSON,
                            notes + ["jest found in package.json"], "jest")
        if _has_dep(pkg, "mocha"):
            return TestPlan(f"npx --no-install mocha --reporter json "
                            f"--reporter-option output={REPORT_JSON}",
                            "language_default", "mocha_json", REPORT_JSON,
                            notes + ["mocha found in package.json"], "mocha")
        if ext.startswith(".ts") and _run(name, "command -v deno").rc == 0:
            return TestPlan(f"deno test -A --no-check --junit-path={REPORT_XML}",
                            "language_default", "junit_xml", REPORT_XML,
                            notes + ["no jest/mocha; deno test"], "deno test")
        return TestPlan("node --test --test-reporter=tap", "language_default", "tap",
                        "", notes + ["no jest/mocha in package.json; node --test"], "node --test")

    raise BaselineError(f"no default test command for {ext!r} files ({rel_path})")


def resolve_test_plan(name: str, repo_dir: str, rel_path: str) -> TestPlan:
    if not file_exists(name, UNIT_TEST):
        return _default_plan(name, repo_dir, rel_path)

    r = _run(name, f"cat {UNIT_TEST}", what="read unit_test.sh")
    if r.rc != 0:
        raise BaselineError(f"cannot read {UNIT_TEST}: {r.stderr.strip()[:200]}")
    script, fmt, out, runner, notes = _instrument_script(r.stdout, name)
    staged = "/tmp/cweft_unit_test.sh"
    pdock.write_file_bytes(name, staged, script.encode("utf-8"))
    return TestPlan(f"bash {staged}", "unit_test.sh", fmt, out, notes, runner)


# ── Running the tests ────────────────────────────────────────────────────

def run_tests(name: str, repo_dir: str, plan: TestPlan, timeout: float) -> dict:
    """One test run. Returns the parsed report plus what it took to get it."""
    r = pdock.exec_in(name, f"cd {shlex.quote(repo_dir)} && {plan.command}", timeout=timeout)
    if plan.output_file:
        cat = _run(name, f"cat {shlex.quote(plan.output_file)}; "
                         f"rm -f {shlex.quote(plan.output_file)}")
        raw = cat.stdout
    else:
        # stdout only: a runner's own progress chatter goes to stderr and
        # would make the report unparsable if mixed in.
        raw = r.stdout
    report = ptp.parse(plan.fmt, raw)
    return {
        "rc": r.rc,
        "seconds": r.seconds,
        "timed_out": r.timed_out,
        "timeout_used": int(timeout),
        "stderr_tail": r.stderr.strip()[-300:],
        "status": report.status,
        "message": report.message[:300],
        "counts": report.counts,
        "total": report.total,
        "cases": {c.name: c.outcome for c in report.cases},
    }


def _judge(fixed_runs) -> tuple:
    """
    Judged set: passed in all three reference-fixed runs. Everything else
    that was seen is excluded, with why.
    """
    unusable = [r for r in fixed_runs if r["status"] != ptp.OK]
    if unusable:
        return [], {}, (f"{len(unusable)} of {len(fixed_runs)} reference runs unusable: "
                        f"{unusable[0]['status']} ({unusable[0]['message'][:120]})")

    seen = sorted({n for r in fixed_runs for n in r["cases"]})
    judged, excluded = [], {}
    for n in seen:
        outcomes = [r["cases"].get(n, "missing") for r in fixed_runs]
        if all(o == ptp.PASSED for o in outcomes):
            judged.append(n)
        elif all(o == ptp.SKIPPED for o in outcomes):
            excluded[n] = "skipped_on_reference"
        elif ptp.PASSED not in outcomes:
            excluded[n] = f"fails_on_reference ({outcomes[0]})"
        else:
            excluded[n] = "mixed_across_runs (" + ",".join(outcomes) + ")"
    return judged, excluded, ""


# ── One CVE ──────────────────────────────────────────────────────────────

def baseline_cve(cve: str, entry: dict, keep_image: bool = False) -> dict:
    rel_path = entry["vulnerable_file_path"]
    data = frozen_bytes(cve, entry)
    record = {
        "cve_id": cve,
        "language": entry["prompt_language"],
        "vulnerable_file_path": rel_path,
        "image_tag": entry["docker_image"],
        "started_at": _now(),
        "ok": False,
    }

    tag = entry["docker_image"]
    pulled = pdock.ensure_image(tag)
    record["image_pulled"] = pulled
    name = pdock.container_name("baseline", cve.replace("-", "_"))
    started = False
    try:
        digest = pdock.repo_digest(tag)
        record["image_digest"] = digest
        pdock.start_container(name, digest)
        started = True

        repo_dir = find_repo_dir(name)
        record["repo_dir"] = repo_dir
        record["frozen_file"] = check_frozen_file(name, repo_dir, rel_path, data)
        record["l0"] = check_l0(name, repo_dir, rel_path, data)
        record["poc"] = check_poc_polarity(name, repo_dir)

        plan = resolve_test_plan(name, repo_dir, rel_path)
        record["test_plan"] = plan.as_dict()

        # First run sets the timeout for the rest.
        timeout = MAX_TIMEOUT
        original_runs, fixed_runs = [], []
        for i in range(RUNS):
            reset_repo(name, repo_dir)
            run = run_tests(name, repo_dir, plan, timeout)
            original_runs.append(run)
            timeout = budget(run["seconds"])
        for i in range(RUNS):
            reset_repo(name, repo_dir)
            apply_fix(name, repo_dir)
            fixed_runs.append(run_tests(name, repo_dir, plan, timeout))
        reset_repo(name, repo_dir)

        record["original_runs"] = original_runs
        record["reference_fixed_runs"] = fixed_runs
        judged, excluded, problem = _judge(fixed_runs)
        record["judged"] = judged
        record["judged_count"] = len(judged)
        record["excluded"] = excluded
        record["durations_seconds"] = {
            "original": [r["seconds"] for r in original_runs],
            "reference_fixed": [r["seconds"] for r in fixed_runs],
            "timeout_after_first_run": timeout,
        }
        if problem:
            record["problem"] = problem
        elif not judged:
            record["problem"] = "no test passed in all three reference-fixed runs"
        else:
            record["ok"] = True
    except (BaselineError, pl0.L0SetupError, RuntimeError, ValueError) as e:
        record["problem"] = f"{type(e).__name__}: {e}"
    finally:
        if started:
            pdock.remove_container(name)
        if pulled and not keep_image:
            record["image_removed"] = pdock.remove_image(tag, pulled)
    record["finished_at"] = _now()
    return record


# ── Entry point ──────────────────────────────────────────────────────────

def load_baseline() -> dict:
    if BASELINE_PATH.exists():
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    return {"schema": SCHEMA, "entries": {}}


def save_baseline(doc: dict) -> None:
    doc["schema"] = SCHEMA
    doc["generated_at"] = _now()
    doc["docker_server"] = pdock.sh(
        ["docker", "version", "--format", "{{.Server.Version}}"]).stdout.strip()
    BASELINE_PATH.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Baseline PatchEval CVEs (no grading)")
    ap.add_argument("cves", nargs="+", help="CVE ids from data/patcheval/manifest.json")
    ap.add_argument("--keep-image", action="store_true",
                    help="keep images this run pulled (default: remove them)")
    args = ap.parse_args()

    entries = manifest()
    unknown = [c for c in args.cves if c not in entries]
    if unknown:
        print(f"Not in the manifest: {', '.join(unknown)}", file=sys.stderr)
        return 2

    doc = load_baseline()
    doc.setdefault("entries", {})
    failures = 0
    for i, cve in enumerate(args.cves, start=1):
        print(f"[{i}/{len(args.cves)}] {cve} ({entries[cve]['prompt_language']}) ...",
              flush=True)
        t0 = time.time()
        record = baseline_cve(cve, entries[cve], keep_image=args.keep_image)
        doc["entries"][cve] = record
        save_baseline(doc)
        if record["ok"]:
            plan = record["test_plan"]
            print(f"    ok  {plan['runner']} from {plan['source']}  "
                  f"judged={record['judged_count']}  excluded={len(record['excluded'])}  "
                  f"({time.time() - t0:.0f}s)")
        else:
            failures += 1
            print(f"    PROBLEM: {record.get('problem', 'unknown')}")

    left = pdock.sweep_containers()
    if left:
        print(f"Swept leftover containers: {', '.join(left)}")
    print(f"Wrote {BASELINE_PATH}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
