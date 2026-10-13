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

    python patcheval_baseline.py                      # every manifest entry
    python patcheval_baseline.py --language go        # one language
    python patcheval_baseline.py --only CVE-2017-0360 --redo

Writes data/patcheval/baseline.json, merging one entry per CVE and saving
after each, so a crash loses at most the CVE in flight. A CVE already in the
file is skipped unless --redo. One CVE at a time: pull, run, remove the image
if we pulled it. A CVE that fails is recorded and the batch carries on. The
batch stops cleanly, rather than filling the disk, if free space falls below
DISK_FLOOR_GB.
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

from config import PATCHEVAL_DIR, PROJECT_ROOT
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
DISK_FLOOR_GB = 40         # stop the batch rather than fill the disk
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


# Per-CVE outcome, recorded as `status`.
OK = "ok"
NO_JUDGED_SET = "no_judged_set"      # the tests ran, but nothing is judgeable
SETUP_FAILED = "setup_failed"        # the image or its test command is unusable
ERROR = "error"                      # Docker or this module misbehaved

# Phases, so a failure can say which part gave up.
SETUP_PHASES = ("frozen_copy", "repo_dir", "frozen_file", "l0", "poc", "test_plan")

# A test that cannot reach the network says so in one of these ways. The
# container is deliberately offline, so this is the commonest reason a repo's
# own suite cannot judge anything.
NETWORK_MARKERS = (
    "dial tcp", "no such host", "getaddrinfo", "EAI_AGAIN", "ENOTFOUND",
    "ECONNREFUSED", "ECONNRESET", "EHOSTUNREACH", "ENETUNREACH",
    "Network is unreachable", "Temporary failure in name resolution",
    "Connection refused", "connection refused", "socket hang up",
    "Name or service not known", "URLError", "ConnectionError",
    "gaierror", "SSLError", "Max retries exceeded", "net::ERR_",
    "request to http", "fetch failed", "Could not resolve host",
)


def disk_free_gb(path: str = ".") -> float:
    import shutil
    return round(shutil.disk_usage(path).free / 2 ** 30, 1)


def code_fingerprint() -> str:
    """
    Short hash of this module and the parser, recorded per entry: a baseline
    file can hold entries made before and after a fix, and the fingerprint is
    what says which is which.
    """
    h = hashlib.sha256()
    for mod in ("patcheval_baseline.py", "patcheval_testparse.py"):
        h.update((PROJECT_ROOT / mod).read_bytes())
    return h.hexdigest()[:12]


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
                 output_file: str = "", notes=None, runner: str = "",
                 scope: str = "repo", stream: str = "stdout"):
        self.command = command
        self.source = source          # "unit_test.sh" or "language_default"
        self.fmt = fmt                # a patcheval_testparse format name
        self.output_file = output_file  # "" when the report is on stdout
        self.notes = list(notes or [])
        self.runner = runner
        self.scope = scope            # "repo", "package" (the patched file's), "as_written"
        self.stream = stream          # where the report is: "stdout" or "both"

    def as_dict(self) -> dict:
        return {"command": self.command, "source": self.source, "runner": self.runner,
                "format": self.fmt, "output_file": self.output_file, "scope": self.scope,
                "stream": self.stream, "notes": self.notes}


# Turning a plain runner invocation into one that emits a parseable report.
# Each rule: (does this line invoke the runner?, how to instrument it, format,
# where the report lands).
def _after_runner(pattern: str, flags: str):
    """
    Put the reporting flags straight after the runner token, never at the end
    of the line. A script's runner line may carry a `-k "long expression"`, a
    pipe, or a redirect, and appending past those breaks the command.
    """
    return lambda line: re.sub(pattern, lambda m: f"{m.group(0)} {flags}", line, count=1)


_INSTRUMENT = [
    # Django's runner and manage.py test: unittest text, and only at verbosity
    # 2 does it name each test. Its report goes to stderr.
    (re.compile(r"\bruntests\.py\b"),
     _after_runner(r"\bruntests\.py\b", "-v 2"),
     "unittest_text", "", "django runtests.py", "both"),
    (re.compile(r"\bmanage\.py\s+test\b"),
     _after_runner(r"\bmanage\.py\s+test\b", "-v 2"),
     "unittest_text", "", "manage.py test", "both"),
    (re.compile(r"\bpytest\b"),
     _after_runner(r"\bpytest\b", f"--junitxml={REPORT_XML} -p no:cacheprovider"),
     "junit_xml", REPORT_XML, "pytest"),
    (re.compile(r"\bgo\s+test\b"),
     _after_runner(r"\bgo\s+test\b", "-json"),
     "go_json", "", "go test"),
    (re.compile(r"\bjest\b"),
     _after_runner(r"\bjest\b", f"--json --outputFile={REPORT_JSON} --ci"),
     "jest_json", REPORT_JSON, "jest"),
    # --reporter-option output=, not a shell redirect: the suite's own
    # console output lands on stdout interleaved with the report otherwise.
    (re.compile(r"\bmocha\b"),
     _after_runner(r"\bmocha\b", f"--reporter json --reporter-option output={REPORT_JSON}"),
     "mocha_json", REPORT_JSON, "mocha"),
    (re.compile(r"\bnode\s+--test\b"),
     _after_runner(r"\bnode\s+--test\b", "--test-reporter=tap"),
     "tap", "", "node --test"),
    # --junit-path, not --reporter=junit: deno prints "Check file:///..."
    # around the report otherwise.
    (re.compile(r"\bdeno\s+test\b"),
     _after_runner(r"\bdeno\s+test\b", f"--junit-path={REPORT_XML}"),
     "junit_xml", REPORT_XML, "deno test"),
    # TAP-native JS runners. tape prints TAP with no flag at all; node-tap and
    # ava need telling. "tape" must be matched before "tap" cannot happen by
    # accident: \btap\b does not match inside "tape".
    (re.compile(r"\btape\b"),
     lambda line: line,
     "tap", "", "tape", "stdout"),
    (re.compile(r"\btap\b"),
     _after_runner(r"\btap\b", "--reporter=tap"),
     "tap", "", "node-tap", "stdout"),
    (re.compile(r"\bava\b"),
     _after_runner(r"\bava\b", "--tap"),
     "tap", "", "ava", "stdout"),
]
# Rules written without a stream read the report from stdout (or from the file
# they were told to write, when output_file is set).
_INSTRUMENT = [rule if len(rule) == 6 else rule + ("stdout",) for rule in _INSTRUMENT]


def _drop_fix_patch(line: str, name: str, repo_dir: str) -> tuple:
    """
    Take fix.patch out of a `git apply` line but keep any other patch on it.
    Several scripts apply the fix alongside a dep.patch or test.patch that the
    tests genuinely need; dropping the whole line would drop those too. This
    module decides when the reference fix goes on, so only fix.patch must go.

    Some scripts name a patch the image does not ship (CVE-2022-4643 asks for
    /workspace/test.patch, which is absent). Keeping it would make `git apply`
    fail and, under `set -e`, kill the whole script, so a missing patch is
    dropped as well and said so.
    Returns (line_or_None, note).
    """
    tokens = line.split()
    others = [t for t in tokens if t.endswith(".patch") and not t.endswith("fix.patch")]
    present = [t for t in others
               if file_exists(name, t if t.startswith("/") else f"{repo_dir}/{t}")]
    missing = [t for t in others if t not in present]

    if not present:
        note = f"removed the fix.patch line: {line.strip()}"
        if missing:
            note += f" (it also named {', '.join(missing)}, absent from the image)"
        return None, note

    kept = [t for t in tokens if not t.endswith("fix.patch") and t not in missing]
    note = (f"dropped fix.patch from the git apply line but kept "
            f"{', '.join(present)}: {line.strip()}")
    if missing:
        note += f"; also dropped {', '.join(missing)}, absent from the image"
    return " ".join(kept), note


def _join_continuations(text: str) -> tuple:
    """
    Fold `\\`-continued lines into one logical line, so instrumenting a runner
    line cannot land in the middle of a command. Returns (lines, joined_count).
    """
    out, joined, buf = [], 0, ""
    for raw in text.splitlines():
        if raw.rstrip().endswith("\\") and not raw.rstrip().endswith("\\\\"):
            buf += raw.rstrip()[:-1].rstrip() + " "
            joined += 1
            continue
        out.append(buf + raw if buf else raw)
        buf = ""
    if buf:
        out.append(buf.rstrip())
    return out, joined


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


_NPM_TEST = re.compile(r"(?P<prefix>.*?)\b(?:npm|yarn|pnpm)\s+(?:run\s+)?test\b(?P<args>.*)$")
_ANSIBLE = re.compile(r"\bansible-playbook\b\s+(?P<rest>\S+)")

# One playbook, one test: ansible-playbook is not a test runner, so each
# invocation's exit code becomes a JUnit testcase named after its playbook.
_ANSIBLE_PREAMBLE = """
CWEFT_STEPS=/tmp/cweft_steps.tsv
: > "$CWEFT_STEPS"
cweft_record() { printf '%s\\t%s\\n' "$1" "$2" >> "$CWEFT_STEPS"; }
cweft_report() {
  {
    printf '<testsuite name="ansible-playbook">\\n'
    while IFS=$'\\t' read -r step rc; do
      printf '  <testcase classname="ansible-playbook" name="%s">' "$step"
      [ "$rc" = "0" ] || printf '<failure message="exit status %s"></failure>' "$rc"
      printf '</testcase>\\n'
    done < "$CWEFT_STEPS"
    printf '</testsuite>\\n'
  } > REPORT_XML_PATH
}
trap cweft_report EXIT
"""


def _ansible_script(lines: list, notes: list):
    """Wrap each ansible-playbook line so its exit status is recorded."""
    out, steps = [], 0
    for line in lines:
        if line.strip().startswith("#") or not _ANSIBLE.search(line):
            # `set -e` would abandon the run at the first failing playbook.
            out.append(re.sub(r"^\s*set\s+-e\s*$", "set +e", line))
            continue
        playbook = _ANSIBLE.search(line).group("rest")
        steps += 1
        out.append(f"( {line.strip()} ); cweft_record {shlex.quote(playbook)} $?")
    if not steps:
        return None
    preamble = _ANSIBLE_PREAMBLE.replace("REPORT_XML_PATH", REPORT_XML)
    notes.append(f"ansible-playbook is not a test runner: recorded each of the {steps} "
                 f"playbook invocations as one JUnit testcase, named after the playbook, "
                 f"passing when it exits 0; `set -e` relaxed so one failure does not "
                 f"abandon the rest")
    return "\n".join(out[:1] + [preamble] + out[1:])


def _resolve_npm_test(name: str, repo_dir: str, line: str, notes: list):
    """
    Replace `npm test` with the command package.json's test script runs, so the
    real runner can be instrumented. Returns the rewritten line, or None.
    """
    m = _NPM_TEST.match(line)
    if not m:
        return None
    pkg = _read_json(name, repo_dir, "package.json")
    script = ((pkg.get("scripts") or {}).get("test") or "").strip()
    if not script:
        return None
    extra = (m.group("args") or "").strip()
    rewritten = f"{m.group('prefix')}{script}" + (f" {extra}" if extra else "")
    notes.append(f"npm test runs package.json's test script; ran it directly instead: "
                 f"{line.strip()} -> {rewritten.strip()}")
    return rewritten


def _instrument_script(text: str, name: str, repo_dir: str):
    """
    Instrument the runner line in a shell script. Returns
    (new_text, fmt, output_file, runner, notes) or raises if no rule matches.
    """
    lines, joined = _join_continuations(text)
    notes, kept = [], []
    if joined:
        notes.append(f"folded {joined} backslash-continued line(s) into their command")
    for line in lines:
        if _GIT_APPLY_FIX.search(line):
            rewritten, note = _drop_fix_patch(line, name, repo_dir)
            notes.append(note)
            if rewritten is not None:
                kept.append(rewritten)
            continue
        kept.append(line)

    # npm test hides the real runner in package.json; swap it in first so the
    # rules below see, say, mocha rather than npm.
    for i, line in enumerate(kept):
        if line.strip().startswith("#"):
            continue
        if _NPM_TEST.match(line):
            rewritten = _resolve_npm_test(name, repo_dir, line, notes)
            if rewritten:
                kept[i] = rewritten
            break

    for i, line in enumerate(kept):
        if line.strip().startswith("#"):
            continue
        shimmed = _unittest_line(name, line)
        if shimmed:
            kept[i], note = shimmed
            notes.append(note)
            return ("\n".join(kept), "junit_xml", REPORT_XML,
                    "unittest (JUnit XML shim)", notes, "stdout")
        for pattern, instrument, fmt, out, runner, stream in _INSTRUMENT:
            if pattern.search(line):
                kept[i] = instrument(line)
                if runner == "mocha":
                    kept[i], out = _mocha_fix_line(kept[i], name, repo_dir, notes)
                # A script that throws stderr away hides why a run collected
                # nothing (a build failure reads as "no output" otherwise).
                if re.search(r"2>\s*/dev/null", kept[i]):
                    kept[i] = re.sub(r"\s*2>\s*/dev/null", "", kept[i])
                    notes.append("kept stderr: the script discarded it, which hides "
                                 "build failures behind an empty report")
                if kept[i] != line:
                    notes.append(f"instrumented for {fmt}: {line.strip()} -> {kept[i].strip()}")
                else:
                    notes.append(f"{runner} prints {fmt} with no extra flags: {line.strip()}")
                return "\n".join(kept), fmt, out, runner, notes, stream

    ansible = _ansible_script(kept, notes)
    if ansible:
        return ansible, "junit_xml", REPORT_XML, "ansible-playbook (one playbook per test)", \
            notes, "stdout"
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


_MOCHA_FLAG_REJECTED = re.compile(r"unknown option.{0,8}--reporter-option", re.I)


def mocha_rejects_reporter_option(text: str) -> bool:
    """True when mocha refused --reporter-option, a flag it only gained in 6."""
    return bool(_MOCHA_FLAG_REJECTED.search(text or ""))


def _mocha_major(name: str, repo_dir: str):
    """The image's mocha major version, or None when it cannot be asked."""
    r = _run(name, f"cd {shlex.quote(repo_dir)} && npx --no-install mocha --version")
    m = re.search(r"(\d+)\.", r.stdout or "") if r.rc == 0 else None
    return int(m.group(1)) if m else None


def _mocha_report_flags(name: str, repo_dir: str, notes: list) -> tuple:
    """
    (flags, output_file) for mocha's JSON report, on old and new mocha alike.

    --reporter-option arrived in mocha 6. Older mocha does not ignore it, it
    rejects the whole invocation and runs nothing, so there the report is read
    from stdout instead: the suite's own console output may surround the JSON,
    which the mocha_json reader already tolerates.
    """
    major = _mocha_major(name, repo_dir)
    if major is not None and major >= 6:
        notes.append(f"mocha {major}: JSON report written to {REPORT_JSON} "
                     f"with --reporter-option")
        return f"--reporter json --reporter-option output={REPORT_JSON}", REPORT_JSON
    notes.append(f"mocha {major if major is not None else 'version unknown'}: "
                 f"--reporter-option needs mocha 6; read the JSON report from stdout")
    return "--reporter json", ""


def _mocha_fix_line(line: str, name: str, repo_dir: str, notes: list) -> tuple:
    """An instrumented mocha line, with --reporter-option removed if too old."""
    flags, out = _mocha_report_flags(name, repo_dir, notes)
    if out:
        return line, out
    return re.sub(r"\s*--reporter-option\s+output=\S+", "", line), ""


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


def _django_plan(name: str, repo_dir: str, notes: list):
    """
    Django's own test entry point, when the repo is a Django project.

    pytest and plain unittest discovery import the project's modules without
    loading settings, which Django answers with ImproperlyConfigured before a
    single test runs. manage.py test loads them, and at -v 2 it names every
    test, which the unittest_text reader reads. Its report goes to stderr.
    """
    if not file_exists(name, f"{repo_dir}/manage.py"):
        return None
    if _run(name, f"grep -q DJANGO_SETTINGS_MODULE {shlex.quote(repo_dir)}/manage.py").rc != 0:
        return None
    try:
        py = pl0.python_interpreter(name)
    except pl0.L0SetupError:
        return None
    return TestPlan(f"{shlex.quote(py)} manage.py test -v 2", "language_default",
                    "unittest_text", "",
                    notes + ["manage.py names DJANGO_SETTINGS_MODULE: used Django's own "
                             "runner, which loads settings; pytest and unittest discovery "
                             "fail with ImproperlyConfigured"],
                    "manage.py test", stream="both")


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
            mnotes = notes + ["mocha found in package.json"]
            flags, out = _mocha_report_flags(name, repo_dir, mnotes)
            return TestPlan(f"npx --no-install mocha {flags}",
                            "language_default", "mocha_json", out, mnotes, "mocha")
        if ext.startswith(".ts") and _run(name, "command -v deno").rc == 0:
            return TestPlan(f"deno test -A --no-check --junit-path={REPORT_XML}",
                            "language_default", "junit_xml", REPORT_XML,
                            notes + ["no jest/mocha; deno test"], "deno test")
        return TestPlan("node --test --test-reporter=tap", "language_default", "tap",
                        "", notes + ["no jest/mocha in package.json; node --test"], "node --test")

    raise BaselineError(f"no default test command for {ext!r} files ({rel_path})")


def _scoped_plan(plan: TestPlan, rel_path: str) -> TestPlan:
    """
    The same default runner, narrowed to the package or directory holding the
    vulnerable file. The fallback when a repo-wide default cannot produce a
    usable report: one unrelated broken package in the repo would otherwise
    leave the CVE with nothing to judge.
    """
    from posixpath import dirname
    d = dirname(rel_path)
    if not d:
        return None                     # the file is at the repo root: same thing
    if plan.runner == "go test":
        cmd = f"GOPROXY=off go test -json ./{d}/..."
    elif plan.runner == "pytest":
        cmd = f"{plan.command} {shlex.quote(d)}"
    elif plan.runner == "jest":
        cmd = plan.command.replace(" --json", f" {shlex.quote(d)} --json", 1)
    elif plan.runner == "node --test":
        cmd = plan.command.replace("--test", f"--test {shlex.quote(d)}", 1)
    elif plan.runner == "deno test":
        cmd = plan.command.replace("deno test", f"deno test {shlex.quote(d)}", 1)
    else:
        return None                     # mocha and the shim take no directory
    return TestPlan(cmd, plan.source, plan.fmt, plan.output_file,
                    plan.notes + [f"narrowed to the vulnerable file's package: {d}"],
                    plan.runner, scope="package")


def resolve_test_plan(name: str, repo_dir: str, rel_path: str) -> list:
    """
    The test commands to try, best first. A repo's own unit_test.sh is used as
    written; a per-language default is tried repo-wide, then narrowed.
    """
    script_text = ""
    if file_exists(name, UNIT_TEST):
        r = _run(name, f"cat {UNIT_TEST}", what="read unit_test.sh")
        if r.rc != 0:
            raise BaselineError(f"cannot read {UNIT_TEST}: {r.stderr.strip()[:200]}")
        script_text = r.stdout

    # Two images ship an empty unit_test.sh; treat that as having none.
    if not script_text.strip():
        wide = _default_plan(name, repo_dir, rel_path)
        if file_exists(name, UNIT_TEST):
            wide.notes.insert(0, "unit_test.sh exists but is empty; used the language default")
        scoped = _scoped_plan(wide, rel_path)
        candidates = [wide] + ([scoped] if scoped else [])
        # A Django project cannot be tested by the generic default at all, so
        # probe its own runner first.
        django = _django_plan(name, repo_dir, list(wide.notes))
        if django and wide.runner != "manage.py test":
            candidates.insert(0, django)
        return candidates

    script, fmt, out, runner, notes, stream = _instrument_script(script_text, name, repo_dir)
    staged = "/tmp/cweft_unit_test.sh"
    pdock.write_file_bytes(name, staged, script.encode("utf-8"))
    return [TestPlan(f"bash {staged}", "unit_test.sh", fmt, out, notes, runner,
                     scope="as_written", stream=stream)]


def choose_plan(name: str, repo_dir: str, candidates: list) -> tuple:
    """
    Probe each candidate once on the original code and keep the first whose
    report is usable. Returns (plan, probes); probes record what each tried.
    """
    if len(candidates) == 1:
        return candidates[0], []        # nothing to choose between; don't pay for a probe
    probes = []
    for plan in candidates:
        reset_repo(name, repo_dir)
        run = run_tests(name, repo_dir, plan, MAX_TIMEOUT)
        probes.append({"command": plan.command, "scope": plan.scope,
                       "status": run["status"], "message": run["message"][:200],
                       "seconds": run["seconds"], "chosen": run["status"] == ptp.OK})
        if run["status"] == ptp.OK:
            return plan, probes
    return candidates[0], probes


# ── Running the tests ────────────────────────────────────────────────────

def run_tests(name: str, repo_dir: str, plan: TestPlan, timeout: float) -> dict:
    """One test run. Returns the parsed report plus what it took to get it."""
    r = pdock.exec_in(name, f"cd {shlex.quote(repo_dir)} && {plan.command}", timeout=timeout)
    report_from = plan.stream
    if plan.output_file:
        cat = _run(name, f"cat {shlex.quote(plan.output_file)}; "
                         f"rm -f {shlex.quote(plan.output_file)}")
        raw = cat.stdout
        report_from = "file"
        if not raw.strip():
            # Runners older than the flag that writes a report file ignore it
            # and print to stdout instead (mocha gained --reporter-option in 6).
            raw = r.stdout
            report_from = "stdout (the report file was empty)"
    elif plan.stream == "both":
        # unittest writes its report to stderr; scraping it needs both streams.
        raw = r.stdout + "\n" + r.stderr
    else:
        # stdout only: a runner's own progress chatter goes to stderr and
        # would make the report unparsable if mixed in.
        raw = r.stdout
    report = ptp.parse(plan.fmt, raw)
    retried = False
    if (plan.fmt == "mocha_json" and report.status != ptp.OK
            and "--reporter-option" in plan.command
            and mocha_rejects_reporter_option(r.stderr + r.stdout)):
        # The version probe can be wrong: npx may resolve a different mocha, or
        # a wrapper script may shadow it. mocha itself has now said no, so run
        # it again without the flag and read the report from stdout.
        retried = True
        stripped = re.sub(r"\s*--reporter-option\s+output=\S+", "", plan.command)
        r = pdock.exec_in(name, f"cd {shlex.quote(repo_dir)} && {stripped}", timeout=timeout)
        raw = r.stdout
        report_from = "stdout (retried without --reporter-option)"
        report = ptp.parse(plan.fmt, raw)
    result = {
        "rc": r.rc,
        "seconds": r.seconds,
        "timed_out": r.timed_out,
        "timeout_used": int(timeout),
        "report_from": report_from,
        "stderr_tail": r.stderr.strip()[-300:],
        "status": report.status,
        "message": report.message[:300],
        "counts": report.counts,
        "total": report.total,
        "cases": {c.name: c.outcome for c in report.cases},
        "failures": {c.name: c.detail for c in report.cases
                     if c.outcome in (ptp.FAILED, ptp.ERROR)},
    }
    if retried:
        result["retried_without_reporter_option"] = True
    if report.dropped:
        result["dropped_packages"] = list(report.dropped)
    return result


def _trim_runs(runs: list) -> list:
    """
    Keep run 1 in full; for the repeats keep counts and only what differed.
    Three runs of a 1,000-test suite, six times over, would otherwise be most
    of the file, and the differences are the part that says anything.
    """
    if not runs:
        return runs
    first, trimmed = runs[0], [runs[0]]
    for run in runs[1:]:
        diff = {n: o for n, o in run["cases"].items() if first["cases"].get(n) != o}
        diff.update({n: "missing" for n in first["cases"] if n not in run["cases"]})
        slim = {k: v for k, v in run.items() if k != "cases"}
        slim["differences_vs_run_1"] = diff
        trimmed.append(slim)
    return trimmed


def _reason_group(record: dict) -> str:
    """Why a CVE has no judged set, in one of the groups the summary counts."""
    fixed = record.get("reference_fixed_runs") or []
    originals = record.get("original_runs") or []
    if record.get("test_phase_cut_short_by_timeout") or \
            any(r.get("timed_out") for r in fixed + originals):
        return "timeout"

    haystack = " ".join(
        [r.get("message", "") for r in fixed]
        + [r.get("stderr_tail", "") for r in fixed]
        + [d for r in fixed for d in (r.get("failures") or {}).values()]
        + list((record.get("excluded") or {}).values())
    )
    if any(m in haystack for m in NETWORK_MARKERS):
        return "needs_network"

    statuses = {r.get("status") for r in fixed}
    if ptp.COLLECTION_ERROR in statuses:
        return "nothing_collected"
    if ptp.NO_TESTS in statuses:
        return "no_test_suite_found"
    if ptp.UNPARSABLE in statuses:
        return "unreadable_output"
    excluded = record.get("excluded") or {}
    if excluded and all(not v.startswith("mixed") for v in excluded.values()):
        return "all_tests_fail_on_reference"
    return "other"


_OUTCOME_RANK = {ptp.PASSED: 0, ptp.SKIPPED: 1, ptp.FAILED: 2, ptp.ERROR: 3}


def _worse(a: str, b: str) -> str:
    """The worse of two outcomes, so a folded collision never reads as a pass."""
    return a if _OUTCOME_RANK.get(a, 3) >= _OUTCOME_RANK.get(b, 3) else b


def _fold_run(cases: dict) -> dict:
    """One run's cases keyed by name with any per-run timing removed."""
    folded = {}
    for raw_name, outcome in cases.items():
        key = ptp.normalize_case_name(raw_name)
        folded[key] = _worse(folded[key], outcome) if key in folded else outcome
    return folded


def _judge(fixed_runs) -> tuple:
    """
    Judged set: passed in all three reference-fixed runs. Everything else
    that was seen is excluded, with why.
    """
    if not fixed_runs:
        return [], {}, "no reference-fixed run completed"
    unusable = [r for r in fixed_runs if r["status"] != ptp.OK]
    if unusable:
        return [], {}, (f"{len(unusable)} of {len(fixed_runs)} reference runs unusable: "
                        f"{unusable[0]['status']} ({unusable[0]['message'][:120]})")

    # Match tests across runs by name with any per-run timing removed: node-tap
    # prints a name like test/array.test.js # time=66.722ms, so raw names never
    # match from one run to the next and every test would look flaky.
    per_run = [_fold_run(r["cases"]) for r in fixed_runs]
    seen = sorted({n for folded in per_run for n in folded})
    judged, excluded = [], {}
    for n in seen:
        outcomes = [folded.get(n, "missing") for folded in per_run]
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
    tag = entry["docker_image"]
    record = {
        "cve_id": cve,
        "language": entry["prompt_language"],
        "dataset_language": entry["language"],
        "vulnerable_file_path": rel_path,
        "image_tag": tag,
        "started_at": _now(),
        "code_fingerprint": code_fingerprint(),
        "disk_free_gb_before": disk_free_gb(),
        "ok": False,
        "status": ERROR,
        "phase": "frozen_copy",
    }

    name = pdock.container_name("baseline", cve.replace("-", "_"))
    pulled = started = False
    try:
        data = frozen_bytes(cve, entry)
        record["phase"] = "image"
        pulled = pdock.ensure_image(tag)
        record["image_pulled"] = pulled
        digest = pdock.repo_digest(tag)
        record["image_digest"] = digest
        pdock.start_container(name, digest)
        started = True

        record["phase"] = "repo_dir"
        repo_dir = find_repo_dir(name)
        record["repo_dir"] = repo_dir
        record["phase"] = "frozen_file"
        record["frozen_file"] = check_frozen_file(name, repo_dir, rel_path, data)
        record["phase"] = "l0"
        record["l0"] = check_l0(name, repo_dir, rel_path, data)
        record["phase"] = "poc"
        record["poc"] = check_poc_polarity(name, repo_dir)

        record["phase"] = "test_plan"
        candidates = resolve_test_plan(name, repo_dir, rel_path)
        plan, probes = choose_plan(name, repo_dir, candidates)
        record["test_plan"] = plan.as_dict()
        record["test_plan_probes"] = probes

        record["phase"] = "runs"
        # First run sets the timeout for the rest. A run that times out ends
        # the phase: repeating a hung suite cannot make it judgeable, and six
        # capped runs would cost an hour and a half per CVE.
        timeout = MAX_TIMEOUT
        original_runs, fixed_runs, hung = [], [], False
        for _ in range(RUNS):
            reset_repo(name, repo_dir)
            run = run_tests(name, repo_dir, plan, timeout)
            original_runs.append(run)
            if run["timed_out"]:
                hung = True
                break
            timeout = budget(run["seconds"])
        if not hung:
            for _ in range(RUNS):
                reset_repo(name, repo_dir)
                apply_fix(name, repo_dir)
                run = run_tests(name, repo_dir, plan, timeout)
                fixed_runs.append(run)
                if run["timed_out"]:
                    hung = True
                    break
        record["test_phase_cut_short_by_timeout"] = hung
        reset_repo(name, repo_dir)

        record["phase"] = "judge"
        judged, excluded, problem = _judge(fixed_runs)
        record["judged"] = judged
        record["judged_count"] = len(judged)
        record["excluded"] = excluded
        record["durations_seconds"] = {
            "original": [r["seconds"] for r in original_runs],
            "reference_fixed": [r["seconds"] for r in fixed_runs],
            "timeout_after_first_run": timeout,
        }
        # _reason_group reads the full runs, so classify before trimming.
        record["original_runs"] = original_runs
        record["reference_fixed_runs"] = fixed_runs
        if problem:
            record["problem"] = problem
        elif not judged:
            record["problem"] = "no test passed in all three reference-fixed runs"
        if judged:
            record["ok"] = True
            record["status"] = OK
        else:
            record["status"] = NO_JUDGED_SET
            record["reason_group"] = _reason_group(record)
        record["original_runs"] = _trim_runs(original_runs)
        record["reference_fixed_runs"] = _trim_runs(fixed_runs)
        record["runs_note"] = ("run 1 of each set holds every case; the repeats hold "
                              "counts and differences_vs_run_1 only")
        record["phase"] = "done"
    except (BaselineError, pl0.L0SetupError) as e:
        record["problem"] = f"{type(e).__name__}: {e}"
        record["status"] = SETUP_FAILED if record["phase"] in SETUP_PHASES else ERROR
    except Exception as e:                      # Docker, JSON, anything else
        record["problem"] = f"{type(e).__name__}: {e}"
        record["status"] = ERROR
    finally:
        if started:
            pdock.remove_container(name)
        if pulled and not keep_image:
            record["image_removed"] = pdock.remove_image(tag, pulled)
    record["finished_at"] = _now()
    record["disk_free_gb_after"] = disk_free_gb()
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


def select_cves(entries: dict, only=None, language: str = "") -> list:
    cves = list(entries)
    if only:
        cves = [c for c in cves if c in set(only)]
    if language:
        want = language.lower()
        cves = [c for c in cves if entries[c]["language"].lower() == want]
    return cves


def main() -> int:
    ap = argparse.ArgumentParser(description="Baseline PatchEval CVEs (no grading)")
    ap.add_argument("cves", nargs="*", help="CVE ids (default: every manifest entry)")
    ap.add_argument("--only", nargs="+", metavar="CVE",
                    help="same as listing CVEs positionally")
    ap.add_argument("--language", choices=["python", "go", "javascript"],
                    help="only this dataset language (javascript includes the .ts entry)")
    ap.add_argument("--redo", action="store_true",
                    help="re-baseline CVEs already in baseline.json (default: skip them)")
    ap.add_argument("--keep-image", action="store_true",
                    help="keep images this run pulled (default: remove them)")
    args = ap.parse_args()

    entries = manifest()
    only = (args.cves or []) + (args.only or [])
    unknown = [c for c in only if c not in entries]
    if unknown:
        print(f"Not in the manifest: {', '.join(unknown)}", file=sys.stderr)
        return 2

    doc = load_baseline()
    doc.setdefault("entries", {})
    selected = select_cves(entries, only, args.language or "")
    if args.redo:
        todo, done_already = selected, []
    else:
        done_already = [c for c in selected if c in doc["entries"]]
        todo = [c for c in selected if c not in doc["entries"]]

    free_at_start = disk_free_gb()
    print(f"Selected {len(selected)} CVEs  |  already baselined: {len(done_already)}  |  "
          f"to run: {len(todo)}")
    print(f"Disk free: {free_at_start} GB  (stopping below {DISK_FLOOR_GB} GB)")
    if not todo:
        print("Nothing to do.")
        return 0

    batch_started = time.time()
    counts = {OK: 0, NO_JUDGED_SET: 0, SETUP_FAILED: 0, ERROR: 0}
    min_free = free_at_start
    stopped_early = ""

    for i, cve in enumerate(todo, start=1):
        free_before = disk_free_gb()
        if free_before < DISK_FLOOR_GB:
            stopped_early = (f"stopped before {cve}: {free_before} GB free is below the "
                             f"{DISK_FLOOR_GB} GB floor. Free some space, then rerun to "
                             f"carry on from here.")
            print(stopped_early)
            break

        t0 = time.time()
        try:
            record = baseline_cve(cve, entries[cve], keep_image=args.keep_image)
        except BaseException as e:              # keep the batch alive regardless
            record = {
                "cve_id": cve, "language": entries[cve]["prompt_language"],
                "dataset_language": entries[cve]["language"],
                "image_tag": entries[cve]["docker_image"],
                "status": ERROR, "ok": False, "phase": "driver",
                "problem": f"{type(e).__name__}: {e}",
                "started_at": _now(), "finished_at": _now(),
                "disk_free_gb_before": free_before, "disk_free_gb_after": disk_free_gb(),
            }
            pdock.sweep_containers()
        record["elapsed_seconds"] = round(time.time() - t0, 1)
        doc["entries"][cve] = record
        save_baseline(doc)                      # after every CVE: lose at most one

        counts[record["status"]] = counts.get(record["status"], 0) + 1
        free_after = record.get("disk_free_gb_after", disk_free_gb())
        min_free = min(min_free, free_after)
        detail = (f"judged={record.get('judged_count', 0):<4} "
                  f"excl={len(record.get('excluded') or {}):<4}")
        if record["status"] != OK:
            detail = f"{record.get('reason_group', record['status'])}: " \
                     f"{str(record.get('problem', ''))[:70]}"
        print(f"[{i:3}/{len(todo)}] {cve:18} {record['language']:<11} "
              f"{record['status']:<14} {detail}  {record['elapsed_seconds']:>6.0f}s  "
              f"free={free_after}GB", flush=True)

    doc["batch"] = {
        "finished_at": _now(),
        "wall_seconds": round(time.time() - batch_started, 1),
        "counts": counts,
        "disk_free_gb_start": free_at_start,
        "disk_free_gb_min": min_free,
        "peak_disk_used_gb": round(free_at_start - min_free, 1),
        "stopped_early": stopped_early,
    }
    save_baseline(doc)

    left = pdock.sweep_containers()
    if left:
        print(f"Swept leftover containers: {', '.join(left)}")
    print(f"\n{counts}  in {(time.time() - batch_started) / 60:.1f} min  |  "
          f"peak disk used {free_at_start - min_free:.1f} GB")
    print(f"Wrote {BASELINE_PATH}")
    return 1 if (counts[ERROR] or stopped_early) else 0


if __name__ == "__main__":
    sys.exit(main())
