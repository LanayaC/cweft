"""
Tests for the four harness fixes made after the first clean PatchEval pass.

Every fix is pinned against the output that exposed it, captured in
data/patcheval/baseline.json during the pass of 2026-10-13 (see the READMEs
under tests/fixtures/ for provenance), and each has a negative control so a
fix cannot pass by being indiscriminate. Nothing here needs Docker or network.
"""

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import patcheval_baseline as pb        # noqa: E402
import patcheval_testparse as ptp      # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
TESTPARSE = FIXTURES / "testparse"
PLANS = FIXTURES / "plans"


def _result(rc=0, stdout="", stderr=""):
    """What patcheval_docker.exec_in returns, as much of it as these need."""
    return types.SimpleNamespace(rc=rc, stdout=stdout, stderr=stderr,
                                 seconds=0.1, timed_out=False)


# ── 1. mocha older than --reporter-option ────────────────────────────────
#
# CVE-2018-16482, CVE-2020-7674, CVE-2020-7675 and CVE-2021-23384 all died on
# this: mocha rejected the flag, ran nothing, and the empty report read as
# "unparsable output" rather than "that flag does not exist here".

REJECTION = (PLANS / "mocha_reporter_option_rejected.txt").read_text(encoding="utf-8")


def test_mocha_rejection_is_recognised():
    assert pb.mocha_rejects_reporter_option(REJECTION)


@pytest.mark.parametrize("text", [
    "",
    "error: unknown option `--bogus'",          # a different unknown flag
    "3 passing (12ms)",                          # an ordinary successful run
])
def test_other_output_is_not_a_reporter_option_rejection(text):
    assert not pb.mocha_rejects_reporter_option(text)


def test_new_mocha_writes_its_report_to_a_file(monkeypatch):
    monkeypatch.setattr(pb, "_run", lambda *a, **k: _result(stdout="10.2.0\n"))
    notes = []
    flags, out = pb._mocha_report_flags("c", "/repo", notes)
    assert "--reporter-option" in flags
    assert out == pb.REPORT_JSON
    assert any("mocha 10" in n for n in notes), notes


@pytest.mark.parametrize("probe,why", [
    (_result(stdout="3.5.3\n"), "mocha 3 has no such flag"),
    (_result(rc=1, stderr="mocha: not found"), "the version cannot be asked"),
])
def test_old_or_unknown_mocha_reads_its_report_from_stdout(monkeypatch, probe, why):
    monkeypatch.setattr(pb, "_run", lambda *a, **k: probe)
    notes = []
    flags, out = pb._mocha_report_flags("c", "/repo", notes)
    assert flags == "--reporter json", why
    assert out == "", "no report file to read: it comes back on stdout"


def test_an_instrumented_mocha_line_loses_the_flag_on_old_mocha(monkeypatch):
    monkeypatch.setattr(pb, "_run", lambda *a, **k: _result(stdout="3.5.3\n"))
    line = (f"npx --no-install mocha --reporter json "
            f"--reporter-option output={pb.REPORT_JSON}")
    fixed, out = pb._mocha_fix_line(line, "c", "/repo", [])
    assert "--reporter-option" not in fixed
    assert "--reporter json" in fixed
    assert out == ""


def test_an_instrumented_mocha_line_is_untouched_on_new_mocha(monkeypatch):
    monkeypatch.setattr(pb, "_run", lambda *a, **k: _result(stdout="10.2.0\n"))
    line = (f"npx --no-install mocha --reporter json "
            f"--reporter-option output={pb.REPORT_JSON}")
    fixed, out = pb._mocha_fix_line(line, "c", "/repo", [])
    assert fixed == line
    assert out == pb.REPORT_JSON


# ── 2. TAP names carrying a per-run timing ───────────────────────────────
#
# CVE-2019-10795: node-tap named each test file with the duration it took, so
# run 2 never matched run 1 and all four tests were excluded as flaky even
# though every one of them passed in all three runs. These are the timings
# recorded for three of those files (the fourth run-2 timing was cut from the
# stored record, so it is left out rather than invented).

RUN_1 = {"test//array.test.js # time=66.722ms": "passed",
         "test//set.test.js # time=75.306ms": "passed",
         "test//star-rule.test.js # time=75.306ms": "passed"}
RUN_2 = {"test//array.test.js # time=70.871ms": "passed",
         "test//set.test.js # time=74.686ms": "passed",
         "test//star-rule.test.js # time=76.684ms": "passed"}
RUN_3 = {"test//array.test.js # time=67.882ms": "passed",
         "test//set.test.js # time=69.624ms": "passed",
         "test//star-rule.test.js # time=66.853ms": "passed"}


def test_timing_in_a_name_no_longer_reads_as_flakiness():
    judged, excluded, problem = pb._judge([
        {"status": ptp.OK, "cases": RUN_1},
        {"status": ptp.OK, "cases": RUN_2},
        {"status": ptp.OK, "cases": RUN_3},
    ])
    assert not problem
    assert sorted(judged) == ["test//array.test.js", "test//set.test.js",
                              "test//star-rule.test.js"]
    assert excluded == {}


def test_a_genuinely_unstable_test_is_still_excluded():
    runs = [{"status": ptp.OK, "cases": {"suite does a thing": "passed"}},
            {"status": ptp.OK, "cases": {"suite does a thing": "failed"}},
            {"status": ptp.OK, "cases": {"suite does a thing": "passed"}}]
    judged, excluded, _ = pb._judge(runs)
    assert judged == []
    assert "mixed_across_runs" in excluded["suite does a thing"]


def test_a_test_that_fails_on_the_reference_is_still_excluded():
    runs = [{"status": ptp.OK, "cases": {"t # time=1ms": "failed"}} for _ in range(3)]
    judged, excluded, _ = pb._judge(runs)
    assert judged == []
    assert "fails_on_reference" in excluded["t"]


@pytest.mark.parametrize("name", [
    "renders #hash anchors",        # a hash that belongs to the name
    "a # time=zero",                # not a number, so not a timing
    "plain name",
])
def test_names_without_a_timing_are_left_alone(name):
    assert ptp.normalize_case_name(name) == name


def test_different_files_do_not_fold_together():
    a = ptp.normalize_case_name("test//a.test.js # time=1ms")
    b = ptp.normalize_case_name("test//b.test.js # time=1ms")
    assert a != b


def test_folding_a_collision_keeps_the_worse_outcome():
    assert pb._fold_run({"t # time=1ms": "passed",
                         "t # time=2ms": "failed"}) == {"t": "failed"}


# ── 3. Django projects need Django's own runner ──────────────────────────
#
# CVE-2023-33977 failed with ImproperlyConfigured: the generic default imports
# the project without loading settings. manage.py test loads them.

def _django_container(monkeypatch, *, has_manage=True, names_settings=True):
    monkeypatch.setattr(pb, "file_exists",
                        lambda name, path: has_manage and path.endswith("manage.py"))
    monkeypatch.setattr(pb, "_run",
                        lambda *a, **k: _result(rc=0 if names_settings else 1))
    monkeypatch.setattr(pb.pl0, "python_interpreter", lambda name: "/usr/bin/python3")


def test_a_django_project_uses_manage_py_test(monkeypatch):
    _django_container(monkeypatch)
    plan = pb._django_plan("c", "/workspace/app", [])
    assert plan is not None
    assert plan.runner == "manage.py test"
    assert plan.command.endswith("manage.py test -v 2"), plan.command
    assert plan.fmt == "unittest_text"     # Django's runner has no JUnit option
    assert plan.stream == "both"           # and writes its report to stderr


@pytest.mark.parametrize("kwargs,why", [
    ({"has_manage": False}, "not a Django project at all"),
    ({"names_settings": False}, "a manage.py that is not Django's"),
])
def test_other_projects_keep_the_generic_default(monkeypatch, kwargs, why):
    _django_container(monkeypatch, **kwargs)
    assert pb._django_plan("c", "/workspace/app", []) is None, why


def test_django_plan_gives_up_when_no_interpreter_is_found(monkeypatch):
    _django_container(monkeypatch)

    def boom(name):
        raise pb.pl0.L0SetupError("no interpreter")

    monkeypatch.setattr(pb.pl0, "python_interpreter", boom)
    assert pb._django_plan("c", "/workspace/app", []) is None


# ── 4. one package that will not build ──────────────────────────────────
#
# CVE-2024-24579 produced 402 passed and 36 failed in all three runs, but one
# package's test binary did not compile, which marked the whole run a
# collection error and threw every result away.

def test_packages_that_built_are_kept_and_the_broken_one_is_named():
    r = ptp.parse("go_json",
                  (TESTPARSE / "go_json_partial_build_error.jsonl").read_text(encoding="utf-8"))
    assert r.status == ptp.OK and r.usable
    assert r.counts == {ptp.PASSED: 1, ptp.FAILED: 1, ptp.SKIPPED: 1, ptp.ERROR: 0}
    assert r.dropped == ("github.com/anchore/stereoscope/pkg/file",)
    assert "did not" in r.message


def test_a_build_failure_with_nothing_usable_is_still_a_collection_error():
    r = ptp.parse("go_json",
                  (TESTPARSE / "go_json_build_error.jsonl").read_text(encoding="utf-8"))
    assert r.status == ptp.COLLECTION_ERROR
    assert not r.usable
    assert r.dropped == ("example.com/fx",)


def test_a_clean_run_drops_nothing():
    r = ptp.parse("go_json",
                  (TESTPARSE / "go_json_normal.jsonl").read_text(encoding="utf-8"))
    assert r.status == ptp.OK
    assert r.dropped == ()


def test_run_tests_records_which_packages_were_dropped(monkeypatch):
    raw = (TESTPARSE / "go_json_partial_build_error.jsonl").read_text(encoding="utf-8")
    monkeypatch.setattr(pb.pdock, "exec_in",
                        lambda name, cmd, timeout=None: _result(rc=1, stdout=raw))
    plan = pb.TestPlan("GOPROXY=off go test -json ./...", "language_default", "go_json")
    out = pb.run_tests("c", "/repo", plan, 60)
    assert out["status"] == ptp.OK
    assert out["dropped_packages"] == ["github.com/anchore/stereoscope/pkg/file"]


def test_run_tests_says_nothing_about_dropped_packages_when_none_were():
    raw = (TESTPARSE / "go_json_normal.jsonl").read_text(encoding="utf-8")
    plan = pb.TestPlan("GOPROXY=off go test -json ./...", "language_default", "go_json")

    class _Docker:
        @staticmethod
        def exec_in(name, cmd, timeout=None):
            return _result(rc=1, stdout=raw)

    original = pb.pdock.exec_in
    pb.pdock.exec_in = _Docker.exec_in
    try:
        out = pb.run_tests("c", "/repo", plan, 60)
    finally:
        pb.pdock.exec_in = original
    assert "dropped_packages" not in out
