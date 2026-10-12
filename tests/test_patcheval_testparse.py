"""
Tests for patcheval_testparse, against real runner output captured under
tests/fixtures/testparse/ (see its README for how each file was produced).

The point of most of these: "nothing ran", "it never compiled" and "the
output was cut short" must not read as a clean run with zero failures.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patcheval_testparse import (  # noqa: E402
    COLLECTION_ERROR, ERROR, FAILED, NO_TESTS, OK, PASSED, SKIPPED, UNPARSABLE,
    parse,
)

FIXTURES = Path(__file__).parent / "fixtures" / "testparse"

# fmt, fixture file, expected error-outcome count. Every normal fixture runs
# the same three tests (one passes, one fails, one is skipped); the pytest one
# also has a test whose fixture raises, which JUnit reports as an error.
NORMAL = [
    ("junit_xml", "junit_pytest_normal.xml", 1),
    ("go_json", "go_json_normal.jsonl", 0),
    ("jest_json", "jest_json_normal.json", 0),
    ("mocha_json", "mocha_json_normal.json", 0),
    ("tap", "tap_node_normal.tap", 0),
    ("unittest_text", "unittest_text_normal.txt", 1),
]
NO_TESTS_CASES = [
    ("junit_xml", "junit_pytest_no_tests.xml"),
    ("go_json", "go_json_no_tests.jsonl"),
    ("jest_json", "jest_json_no_tests.json"),
    ("mocha_json", "mocha_json_no_tests.json"),
    ("tap", "tap_node_no_tests.tap"),
    ("unittest_text", "unittest_text_no_tests.txt"),
]
COLLECTION_CASES = [
    ("junit_xml", "junit_pytest_collection_error.xml"),
    ("go_json", "go_json_build_error.jsonl"),
    ("jest_json", "jest_json_load_error.json"),
    ("mocha_json", "mocha_json_load_error.json"),
    ("tap", "tap_node_load_error.tap"),
    ("unittest_text", "unittest_text_load_error.txt"),
]
TRUNCATED = [
    ("junit_xml", "junit_pytest_truncated.xml"),
    ("go_json", "go_json_truncated.jsonl"),
    ("jest_json", "jest_json_truncated.json"),
    ("mocha_json", "mocha_json_truncated.json"),
    ("tap", "tap_node_truncated.tap"),
    ("unittest_text", "unittest_text_truncated.txt"),
]


def read(fixture: str) -> str:
    return (FIXTURES / fixture).read_text(encoding="utf-8")


@pytest.mark.parametrize("fmt,fixture,errors", NORMAL)
def test_normal_run_is_usable_and_lists_every_test(fmt, fixture, errors):
    r = parse(fmt, read(fixture))
    assert r.status == OK and r.usable, r.message
    counts = r.counts
    assert counts[PASSED] == 1, counts
    assert counts[FAILED] == 1, counts
    assert counts[SKIPPED] == 1, counts
    assert counts[ERROR] == errors, counts
    assert r.total == 3 + errors
    assert all(t.name for t in r.cases)
    assert r.names(FAILED) and "divides" in r.names(FAILED)[0].lower()


@pytest.mark.parametrize("fmt,fixture,errors", NORMAL)
def test_normal_run_keeps_a_detail_for_the_failure(fmt, fixture, errors):
    r = parse(fmt, read(fixture))
    failed = [t for t in r.cases if t.outcome == FAILED]
    assert failed and failed[0].detail, "a failure should carry some explanation"


@pytest.mark.parametrize("fmt,fixture", NO_TESTS_CASES)
def test_nothing_collected_says_so(fmt, fixture):
    r = parse(fmt, read(fixture))
    assert r.status == NO_TESTS, f"{fmt}: got {r.status} ({r.message})"
    assert not r.usable
    assert r.message
    assert r.counts[FAILED] == 0  # ... which is exactly why status must say no_tests


@pytest.mark.parametrize("fmt,fixture", COLLECTION_CASES)
def test_collection_error_says_so(fmt, fixture):
    r = parse(fmt, read(fixture))
    assert r.status == COLLECTION_ERROR, f"{fmt}: got {r.status} ({r.message})"
    assert not r.usable
    assert r.message


@pytest.mark.parametrize("fmt,fixture", TRUNCATED)
def test_truncated_output_is_not_mistaken_for_a_clean_run(fmt, fixture):
    r = parse(fmt, read(fixture))
    assert r.status == UNPARSABLE, f"{fmt}: got {r.status} ({r.message})"
    assert not r.usable
    assert r.message


@pytest.mark.parametrize("fmt", sorted(["junit_xml", "go_json", "jest_json", "mocha_json", "tap"]))
def test_empty_and_garbage_input_are_unparsable(fmt):
    for text in ("", "   \n", "this is not test output at all", "{{{"):
        r = parse(fmt, text)
        assert r.status == UNPARSABLE, f"{fmt} on {text!r}: {r.status}"
        assert not r.usable


def test_junit_reports_a_fixture_error_as_error_not_failure():
    r = parse("junit_xml", read("junit_pytest_normal.xml"))
    assert r.counts[ERROR] == 1
    assert "fixture" in r.names(ERROR)[0].lower() or r.names(ERROR)


def test_go_subtests_and_package_are_in_the_name():
    r = parse("go_json", read("go_json_normal.jsonl"))
    assert all(n.startswith("example.com/fx.") for n in r.names())


def test_go_no_tests_message_mentions_the_reason():
    r = parse("go_json", read("go_json_no_tests.jsonl"))
    assert "no tests matched" in r.message


def test_tap_whole_file_result_is_not_a_passing_test():
    # node --test reports a file with no tests as one passing test named
    # after the file; counting that as a pass would hide an empty run.
    r = parse("tap", read("tap_node_no_tests.tap"))
    assert r.status == NO_TESTS
    assert r.counts[PASSED] in (0, 1)  # the file-level entry may be listed
    assert not r.usable


def test_names_filters_by_outcome():
    r = parse("junit_xml", read("junit_pytest_normal.xml"))
    assert set(r.names(PASSED)).isdisjoint(r.names(FAILED))
    assert len(r.names()) == r.total


def test_unknown_format_raises():
    with pytest.raises(ValueError):
        parse("nunit", "<x/>")
