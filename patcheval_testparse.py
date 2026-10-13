"""
Readers that turn a test runner's output into one shape, so the PatchEval
backend can compare a model's run against a baseline run test by test.

Supported: JUnit XML (pytest --junitxml), `go test -json`, `jest --json`,
`mocha --reporter json`, TAP (`node --test --test-reporter=tap`, tape, ava
--tap, tap --reporter=tap), and unittest's own verbose text output, which is
what Django's runtests.py and manage.py test print.

Every reader returns a TestReport whose `status` says whether the results
can be trusted:

    ok                every test that was meant to run reported a result
    no_tests          the runner collected nothing (pytest exit 5, a Go -run
                      regex matching nothing, an empty mocha suite)
    collection_error  an import or build failure, so tests never ran
    unparsable        the output was malformed or cut short

The last three must never be read as "zero failures". Only `ok` means the
case list is complete; `usable` says so in one word.

One qualification on `ok`: a report may also name packages in `dropped`.
`go test ./...` builds each package separately, and one package that will not
build does not stop the others from running. Such a report is `ok` for the
packages that did run, and `dropped` names those that never did, so a single
broken package cannot discard hundreds of real results. A build failure that
leaves nothing usable is still `collection_error`.
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, NamedTuple, Tuple

# statuses
OK = "ok"
NO_TESTS = "no_tests"
COLLECTION_ERROR = "collection_error"
UNPARSABLE = "unparsable"

# outcomes
PASSED = "passed"
FAILED = "failed"
SKIPPED = "skipped"
ERROR = "error"

DETAIL_CHARS = 300

_COLLECTION_MSG = re.compile(r"collection (failure|error)", re.I)
_MODULE_MISSING = re.compile(
    r"Cannot find module|ModuleNotFoundError|ImportError|No module named", re.I)
_GO_BUILD_FAILED = re.compile(r"\[(build|setup) failed\]|^# ", re.M)
# "# github.com/org/repo/pkg [github.com/org/repo/pkg.test]" names the package
# whose test binary failed to build.
_GO_BUILD_PKG = re.compile(r"^#\s+(\S+)")
_GO_NO_TESTS = re.compile(r"no tests to run|no test files", re.I)
_TAP_RESULT = re.compile(r"^(not ok|ok)\s+(\d+)\s*-?\s*(.*)$")
_TAP_PLAN = re.compile(r"^1\.\.(\d+)\s*$")
_TAP_DIRECTIVE = re.compile(r"\s+#\s*(SKIP|TODO)\b(.*)$", re.I)
_FILE_NAME = re.compile(r"\.(js|cjs|mjs|ts|tsx|mts|cts)$", re.I)


class TestCase(NamedTuple):
    name: str
    outcome: str
    detail: str = ""


class TestReport(NamedTuple):
    fmt: str
    status: str
    message: str
    cases: Tuple[TestCase, ...]
    dropped: Tuple[str, ...] = ()      # packages that never built (see module docstring)

    @property
    def usable(self) -> bool:
        """True only when the case list is a complete record of the run."""
        return self.status == OK

    @property
    def counts(self) -> Dict[str, int]:
        c = {PASSED: 0, FAILED: 0, SKIPPED: 0, ERROR: 0}
        for t in self.cases:
            c[t.outcome] += 1
        return c

    @property
    def total(self) -> int:
        return len(self.cases)

    def names(self, *outcomes: str) -> List[str]:
        keep = set(outcomes) or {PASSED, FAILED, SKIPPED, ERROR}
        return [t.name for t in self.cases if t.outcome in keep]


def _detail(text: str) -> str:
    return " ".join((text or "").split())[:DETAIL_CHARS]


# A per-run timing printed as part of a TAP test name: node-tap and tape emit
# `ok 1 - test/array.test.js # time=66.722ms`. The number changes every run, so
# the same test never matches itself across runs and every case looks flaky.
# Only `time=` is stripped: any other `#` comment may be part of the name.
_TIMING_SUFFIX = re.compile(r"\s+#\s*time=[\d.]+\s*(?:ms|s)?\s*$", re.I)


def normalize_case_name(name: str) -> str:
    """A test's name with any per-run timing removed, for cross-run matching."""
    return _TIMING_SUFFIX.sub("", name or "").strip()


def _report(fmt, status, message="", cases=(), dropped=()) -> TestReport:
    return TestReport(fmt, status, message, tuple(cases), tuple(dropped))


# ── JUnit XML (pytest --junitxml) ────────────────────────────────────────

def parse_junit_xml(text: str) -> TestReport:
    fmt = "junit_xml"
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return _report(fmt, UNPARSABLE, f"XML did not parse: {e}")

    cases, collection_msgs = [], []
    for tc in root.iter("testcase"):
        cls, name = tc.get("classname") or "", tc.get("name") or ""
        full = f"{cls}::{name}" if cls else name
        failure, error = tc.find("failure"), tc.find("error")
        skipped = tc.find("skipped")
        if error is not None:
            msg = error.get("message") or ""
            body = _detail(msg + " " + (error.text or ""))
            if _COLLECTION_MSG.search(msg) or _MODULE_MISSING.search(body):
                collection_msgs.append(f"{full}: {body}")
            cases.append(TestCase(full, ERROR, body))
        elif failure is not None:
            cases.append(TestCase(full, FAILED,
                                  _detail((failure.get("message") or "") + " " + (failure.text or ""))))
        elif skipped is not None:
            cases.append(TestCase(full, SKIPPED, _detail(skipped.get("message") or "")))
        else:
            cases.append(TestCase(full, PASSED))

    if collection_msgs:
        return _report(fmt, COLLECTION_ERROR, collection_msgs[0], cases)
    if not cases:
        return _report(fmt, NO_TESTS, "the XML holds no testcase elements")
    return _report(fmt, OK, "", cases)


# ── go test -json ────────────────────────────────────────────────────────

def parse_go_json(text: str) -> TestReport:
    fmt = "go_json"
    events, malformed = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if isinstance(ev, dict):
            events.append(ev)
        else:
            malformed += 1

    if not events:
        return _report(fmt, UNPARSABLE, f"no JSON events ({malformed} unreadable lines)")

    cases, output, package_done, build_failed = [], [], False, False
    failed_pkgs: List[str] = []
    per_test: Dict[Tuple[str, str], List[str]] = {}
    for ev in events:
        action, test = ev.get("Action"), ev.get("Test")
        pkg = ev.get("Package") or ""
        if action in ("output", "build-output"):
            text_out = ev.get("Output") or ""
            if test:
                per_test.setdefault((pkg, test), []).append(text_out)
            else:
                output.append(text_out)
                named = _GO_BUILD_PKG.match(text_out)
                if named and named.group(1) not in failed_pkgs:
                    failed_pkgs.append(named.group(1))
        elif action == "build-fail":
            build_failed = True
            if pkg and pkg not in failed_pkgs:
                failed_pkgs.append(pkg)
        elif test and action in ("pass", "fail", "skip"):
            outcome = {"pass": PASSED, "fail": FAILED, "skip": SKIPPED}[action]
            detail = "" if outcome == PASSED else _detail("".join(per_test.get((pkg, test), [])))
            cases.append(TestCase(f"{pkg}.{test}" if pkg else test, outcome, detail))
        elif not test and action in ("pass", "fail", "skip"):
            package_done = True

    joined = "".join(output)
    if not package_done and not build_failed:
        return _report(fmt, UNPARSABLE, "no package-level result: output looks truncated", cases)
    if build_failed or _GO_BUILD_FAILED.search(joined):
        if cases:
            named = ", ".join(failed_pkgs) if failed_pkgs else "an unnamed package"
            return _report(fmt, OK,
                           f"kept {len(cases)} result(s) from the packages that built; "
                           f"{named} did not: {_detail(joined)}",
                           cases, failed_pkgs or ("unknown",))
        return _report(fmt, COLLECTION_ERROR, _detail(joined), cases, failed_pkgs)
    if not cases:
        why = "no tests matched" if _GO_NO_TESTS.search(joined) else "no test events"
        return _report(fmt, NO_TESTS, why)
    msg = f"{malformed} unreadable lines skipped" if malformed else ""
    return _report(fmt, OK, msg, cases)


# ── jest --json ──────────────────────────────────────────────────────────

_JEST_OUTCOMES = {"passed": PASSED, "failed": FAILED, "pending": SKIPPED,
                  "skipped": SKIPPED, "todo": SKIPPED, "disabled": SKIPPED}


def parse_jest_json(text: str) -> TestReport:
    fmt = "jest_json"
    try:
        data = json.loads(text)
    except ValueError as e:
        return _report(fmt, UNPARSABLE, f"JSON did not parse: {e}")
    if not isinstance(data, dict) or "testResults" not in data:
        return _report(fmt, UNPARSABLE, "not a jest --json report")

    cases, suite_errors = [], []
    for suite in data.get("testResults") or []:
        assertions = suite.get("assertionResults") or []
        if not assertions and (suite.get("status") == "failed" or suite.get("message")):
            suite_errors.append(f"{suite.get('name', '?')}: {_detail(suite.get('message', ''))}")
            continue
        for a in assertions:
            name = a.get("fullName") or " > ".join(
                (a.get("ancestorTitles") or []) + [a.get("title") or ""])
            outcome = _JEST_OUTCOMES.get(a.get("status"), ERROR)
            cases.append(TestCase(name, outcome, _detail(" ".join(a.get("failureMessages") or []))))

    if suite_errors:
        return _report(fmt, COLLECTION_ERROR, suite_errors[0], cases)
    if not cases:
        return _report(fmt, NO_TESTS, "jest reported no tests")
    return _report(fmt, OK, "", cases)


# ── mocha --reporter json ────────────────────────────────────────────────

def parse_mocha_json(text: str) -> TestReport:
    fmt = "mocha_json"
    try:
        data = json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        try:  # mocha sometimes prints warnings before its JSON
            data = json.loads(text[start:end + 1]) if start != -1 < end else None
        except ValueError:
            data = None
    if not isinstance(data, dict) or "stats" not in data:
        # A file that fails to load kills mocha before it prints any JSON.
        if _MODULE_MISSING.search(text):
            return _report(fmt, COLLECTION_ERROR, _detail(text))
        return _report(fmt, UNPARSABLE, "not a mocha --reporter json report")

    def title(t):
        return t.get("fullTitle") or t.get("title") or "?"

    cases = [TestCase(title(t), PASSED) for t in data.get("passes") or []]
    cases += [TestCase(title(t), SKIPPED) for t in data.get("pending") or []]
    load_errors = []
    for t in data.get("failures") or []:
        err = _detail(json.dumps(t.get("err")) if isinstance(t.get("err"), dict) else str(t.get("err")))
        name = title(t)
        if "Uncaught error outside of test suite" in name or _MODULE_MISSING.search(err):
            load_errors.append(f"{name}: {err}")
        cases.append(TestCase(name, FAILED, err))

    if load_errors:
        return _report(fmt, COLLECTION_ERROR, load_errors[0], cases)
    if not cases:
        return _report(fmt, NO_TESTS, "mocha ran no tests")
    return _report(fmt, OK, "", cases)


# ── TAP (node --test --test-reporter=tap) ────────────────────────────────

def parse_tap(text: str) -> TestReport:
    fmt = "tap"
    cases, plan, diagnostics = [], None, []
    for line in text.splitlines():
        if line.startswith("#"):
            diagnostics.append(line[1:].strip())
            continue
        if line[:1].isspace():   # nested subtest body / YAML block
            stripped = line.strip()
            diagnostics.append(stripped)
            if cases and cases[-1].outcome == FAILED and stripped not in ("---", "..."):
                last = cases[-1]
                cases[-1] = last._replace(detail=_detail(f"{last.detail} {stripped}"))
            continue
        m = _TAP_PLAN.match(line)
        if m:
            plan = int(m.group(1))
            continue
        m = _TAP_RESULT.match(line)
        if not m:
            continue
        ok, _, name = m.group(1) == "ok", m.group(2), m.group(3).strip()
        directive = _TAP_DIRECTIVE.search(name)
        if directive:
            name = name[:directive.start()].strip()
            cases.append(TestCase(name, SKIPPED, _detail(directive.group(2))))
        else:
            cases.append(TestCase(name, PASSED if ok else FAILED))

    if plan is None:
        return _report(fmt, UNPARSABLE, "no TAP plan line: output looks truncated", cases)
    if plan == 0 or not cases:
        return _report(fmt, NO_TESTS, "the TAP plan is empty")
    if plan != len(cases):
        return _report(fmt, UNPARSABLE,
                       f"TAP plan says {plan} tests, {len(cases)} reported", cases)

    # node --test names a whole file as one test when the file itself
    # defines no tests, or fails to load. Either way nothing really ran.
    if all(_FILE_NAME.search(t.name) for t in cases):
        blob = " ".join(diagnostics)
        if any(t.outcome == FAILED for t in cases):
            return _report(fmt, COLLECTION_ERROR, _detail(blob) or "test file failed to run", cases)
        return _report(fmt, NO_TESTS, "only whole-file results: the file defines no tests", cases)
    return _report(fmt, OK, "", cases)


# ── unittest text (Django's runtests.py, manage.py test, unittest -v) ────
#
# The only format here that is scraped from prose rather than read from a
# machine-readable report: Django's runner has no JUnit option. It needs
# verbosity 2, which prints one line per test, and the trailing "Ran N tests"
# line is what says the output is complete.

_UT_NAME = re.compile(
    r"^(?P<name>\w+) \((?P<cls>[\w.]+)\)(?P<sub> \[[^\]]*\])?(?P<rest>.*)$")
_UT_OUTCOME = re.compile(
    r"\.\.\.\s*(?P<outcome>ok|FAIL|ERROR|skipped.*|expected failure|unexpected success)\s*$")
_UT_RAN = re.compile(r"^Ran (\d+) tests? in ", re.M)
_UT_DETAIL_HEAD = re.compile(r"^(FAIL|ERROR): (?P<name>\w+) \((?P<cls>[\w.]+)\)")

_UT_OUTCOMES = {"ok": PASSED, "FAIL": FAILED, "ERROR": ERROR,
                "expected failure": PASSED, "unexpected success": FAILED}


def _ut_full_name(cls: str, name: str, sub: str = "") -> str:
    # Python 3.11+ prints (module.Class.method); older prints (module.Class).
    full = cls if cls.endswith("." + name) else f"{cls}::{name}"
    return f"{full}{sub.strip()}" if sub else full


def parse_unittest_text(text: str) -> TestReport:
    fmt = "unittest_text"
    lines = text.splitlines()
    cases, pending = [], None

    for line in lines:
        if pending is not None:
            # A docstring sat between the test's name and its outcome.
            m = _UT_OUTCOME.search(line)
            if m:
                cases.append(TestCase(pending, _ut_outcome(m.group("outcome"))))
                pending = None
                continue
            if _UT_NAME.match(line) is None:
                continue
            pending = None                       # name line with no outcome: give up on it
        m = _UT_NAME.match(line)
        if not m:
            continue
        full = _ut_full_name(m.group("cls"), m.group("name"), m.group("sub") or "")
        outcome = _UT_OUTCOME.search(m.group("rest") or "")
        if outcome:
            cases.append(TestCase(full, _ut_outcome(outcome.group("outcome"))))
        else:
            pending = full

    # Failure and error bodies, from the ==== blocks below the run.
    details, current = {}, None
    for line in lines:
        head = _UT_DETAIL_HEAD.match(line)
        if head:
            current = _ut_full_name(head.group("cls"), head.group("name"))
            details[current] = []
            continue
        if current:
            if line.startswith("===") or _UT_RAN.match(line):
                current = None
            elif not line.startswith("---"):
                details[current].append(line)
    if details:
        cases = [c._replace(detail=_detail(" ".join(details.get(c.name, []))))
                 if c.outcome in (FAILED, ERROR) else c for c in cases]

    ran = _UT_RAN.search(text)
    if ran is None:
        if _MODULE_MISSING.search(text):
            return _report(fmt, COLLECTION_ERROR, _detail(text[-1000:]), cases)
        return _report(fmt, UNPARSABLE,
                       "no 'Ran N tests' line: output truncated, or verbosity below 2", cases)
    if int(ran.group(1)) == 0:
        return _report(fmt, NO_TESTS, "the runner ran 0 tests")
    if not cases:
        return _report(fmt, UNPARSABLE,
                       f"'Ran {ran.group(1)} tests' but no per-test lines: run with -v 2")
    # unittest turns a module that will not import into a passing-looking run
    # of one erroring test called _FailedTest. Nothing really ran.
    load_failures = [c for c in cases
                     if "_FailedTest" in c.name
                     or (c.outcome == ERROR and _MODULE_MISSING.search(c.detail or ""))]
    if load_failures and len(load_failures) == len([c for c in cases if c.outcome == ERROR]):
        return _report(fmt, COLLECTION_ERROR,
                       _detail(load_failures[0].detail or load_failures[0].name), cases)
    return _report(fmt, OK, "", cases)


def _ut_outcome(token: str) -> str:
    token = token.strip()
    if token.startswith("skipped"):
        return SKIPPED
    return _UT_OUTCOMES.get(token, ERROR)


FORMATS = {
    "junit_xml": parse_junit_xml,
    "go_json": parse_go_json,
    "jest_json": parse_jest_json,
    "mocha_json": parse_mocha_json,
    "tap": parse_tap,
    "unittest_text": parse_unittest_text,
}


def parse(fmt: str, text: str) -> TestReport:
    if fmt not in FORMATS:
        raise ValueError(f"unknown test output format {fmt!r}; known: {sorted(FORMATS)}")
    return FORMATS[fmt](text)
