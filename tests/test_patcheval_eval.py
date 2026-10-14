"""
Tests for the PatchEval scoring loop in patcheval_eval.

Everything here is the part of scoring that decides a verdict or writes a row;
the container work is exercised by the oracle check, which needs Docker. These
need neither Docker nor a network.
"""

import csv
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import patcheval_eval as pe        # noqa: E402
import patcheval_testparse as ptp  # noqa: E402


# ── the row shape ────────────────────────────────────────────────────────

EXPECTED_COLUMNS = [
    "cve", "language", "cwe", "level", "model_key", "model_id",
    "image_digest", "digest_matches_baseline",
    "l0_checker", "l0_passed", "poc_passed",
    "judged_set_size", "tests_run", "regressions", "n_regressions",
    "flaky_excluded", "trust_level", "error", "timings",
    "code_fingerprint", "timestamp",
]


def test_columns_are_exactly_the_agreed_set():
    assert pe.CSV_FIELDS == EXPECTED_COLUMNS


def test_the_backend_writes_its_own_file_not_the_vul4j_one():
    assert pe.RESULTS_CSV.name == "results_patcheval.csv"


def test_a_row_serialises_its_lists_and_timings(monkeypatch):
    # The CWE comes from the manifest, not the baseline entry, which records
    # what happened in the image rather than the dataset's labels.
    monkeypatch.setattr(pe, "_manifest_entry",
                        lambda cve: {"primary_cwe": "CWE-22",
                                     "cwe_list": ["CWE-22", "CWE-73"]})
    entry = {"language": "Go", "image_digest": "repo@sha256:abc",
             "judged": ["a", "b", "c"]}
    row = pe._row("CVE-1", entry, "L2", "claude", "claude-x",
                  regressions=["t one", "t two"], flaky_excluded=["t three"],
                  timings={"l0": 0.4, "poc": 1.2})
    assert row["cwe"] == "CWE-22"
    assert row["judged_set_size"] == 3
    assert row["regressions"] == "t one;t two"
    assert row["flaky_excluded"] == "t three"
    assert json.loads(row["timings"]) == {"l0": 0.4, "poc": 1.2}
    assert len(row["code_fingerprint"]) == 12
    assert set(row) == set(pe.CSV_FIELDS)


# ── refusing what cannot be scored ───────────────────────────────────────

GOOD = {"status": "ok", "judged": ["t"], "image_digest": "repo@sha256:abc",
        "test_plan": {"command": "pytest -q"}}


def test_a_scorable_entry_is_not_refused():
    assert pe.refusal(GOOD) == ""


@pytest.mark.parametrize("entry,expected", [
    (None, "not in the baseline"),
    ({}, "not in the baseline"),
    ({**GOOD, "status": "no_judged_set"}, "status"),
    ({**GOOD, "status": "setup_failed"}, "status"),
    ({**GOOD, "judged": []}, "judged set"),
    ({**GOOD, "image_digest": ""}, "image digest"),
    ({**GOOD, "test_plan": {}}, "test command"),
])
def test_unscorable_entries_are_refused_with_a_reason(entry, expected):
    why = pe.refusal(entry)
    assert why and expected in why


def test_a_refused_cve_is_scored_as_nothing(tmp_path):
    row = pe.score_candidate("CVE-0", b"x", "L1", "claude",
                             entry={"status": "no_judged_set"})
    assert row["trust_level"] == pe.REFUSED
    assert "no_judged_set" in row["error"]
    assert row["l0_passed"] == "" and row["poc_passed"] == ""


# ── the trust level ──────────────────────────────────────────────────────

@pytest.mark.parametrize("l0,poc,regressions,expected", [
    (False, None, None, "L0"),       # does not parse
    (False, True, 0, "L0"),          # L0 wins even if the rest looks fine
    (True, False, None, "L1"),       # parses, hole still open
    (True, True, 2, "L2"),           # hole closed, judged tests broken
    (True, True, 0, "L3"),           # hole closed, judged set intact
])
def test_trust_level(l0, poc, regressions, expected):
    assert pe.trust_level(l0, poc, regressions) == expected


# ── a failing judged test is rerun before it counts ──────────────────────

JUDGED = ["keeps working", "also keeps working"]


def test_all_passing_is_no_regression():
    first = {"keeps working": ptp.PASSED, "also keeps working": ptp.PASSED}
    assert pe.count_regressions(JUDGED, first, None) == ([], [])


def test_failing_twice_is_a_regression():
    first = {"keeps working": ptp.FAILED, "also keeps working": ptp.PASSED}
    rerun = {"keeps working": ptp.FAILED, "also keeps working": ptp.PASSED}
    regressions, flaky = pe.count_regressions(JUDGED, first, rerun)
    assert regressions == ["keeps working"]
    assert flaky == []


def test_failing_then_passing_is_flaky_not_a_regression():
    first = {"keeps working": ptp.FAILED, "also keeps working": ptp.PASSED}
    rerun = {"keeps working": ptp.PASSED, "also keeps working": ptp.PASSED}
    regressions, flaky = pe.count_regressions(JUDGED, first, rerun)
    assert regressions == []
    assert flaky == ["keeps working"]


def test_a_judged_test_that_vanished_counts_as_a_regression():
    first = {"also keeps working": ptp.PASSED}          # the other is gone
    rerun = {"also keeps working": ptp.PASSED}
    regressions, flaky = pe.count_regressions(JUDGED, first, rerun)
    assert regressions == ["keeps working"]


def test_an_error_outcome_counts_like_a_failure():
    first = {"keeps working": ptp.ERROR, "also keeps working": ptp.PASSED}
    regressions, _ = pe.count_regressions(JUDGED, first, first)
    assert regressions == ["keeps working"]


# ── the CSV: appending, resuming, and leaving results.csv alone ──────────

def _row_for(cve, level="L1", model="claude", trust="L3"):
    return pe._row(cve, {"language": "Go", "judged": ["t"]}, level, model,
                   "model-x", trust_level=trust)


def test_rows_append_under_one_header(tmp_path):
    path = tmp_path / "results_patcheval.csv"
    pe.append_row(_row_for("CVE-1"), path)
    pe.append_row(_row_for("CVE-2"), path)
    text = path.read_text(encoding="utf-8")
    assert text.count("cve,language,cwe") == 1
    with path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert [r["cve"] for r in rows] == ["CVE-1", "CVE-2"]
    assert list(rows[0]) == pe.CSV_FIELDS


def test_writing_a_row_creates_nothing_else(tmp_path):
    path = tmp_path / "results_patcheval.csv"
    pe.append_row(_row_for("CVE-1"), path)
    assert [p.name for p in tmp_path.iterdir()] == ["results_patcheval.csv"]
    assert not (tmp_path / "results.csv").exists()


def test_done_cells_is_keyed_on_cve_level_and_model(tmp_path):
    path = tmp_path / "results_patcheval.csv"
    assert pe.done_cells(path) == set()
    pe.append_row(_row_for("CVE-1", "L1", "claude"), path)
    pe.append_row(_row_for("CVE-1", "L2", "claude"), path)
    pe.append_row(_row_for("CVE-1", "L1", "gpt"), path)
    assert pe.done_cells(path) == {("CVE-1", "L1", "claude"),
                                   ("CVE-1", "L2", "claude"),
                                   ("CVE-1", "L1", "gpt")}


# ── choosing which patch logs to score ───────────────────────────────────

def _args(**kw):
    fields = {"models": None, "levels": None, "vulns": None, "limit": None}
    fields.update(kw)
    return types.SimpleNamespace(**fields)


@pytest.fixture
def logs(tmp_path, monkeypatch):
    for stem in ["CVE-1__L1__claude", "CVE-1__L2__gpt", "CVE-2__L1__claude",
                 "not-a-cell", "CVE-3__L1__gemini"]:
        (tmp_path / f"{stem}.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(pe, "PATCHEVAL_LOGS_DIR", tmp_path)
    return tmp_path


def test_every_well_named_log_is_a_cell(logs):
    assert [p.stem for p in pe._log_cells(_args())] == [
        "CVE-1__L1__claude", "CVE-1__L2__gpt", "CVE-2__L1__claude", "CVE-3__L1__gemini"]


@pytest.mark.parametrize("kw,expected", [
    ({"models": ["claude"]}, ["CVE-1__L1__claude", "CVE-2__L1__claude"]),
    ({"levels": ["L2"]}, ["CVE-1__L2__gpt"]),
    ({"vulns": ["CVE-3"]}, ["CVE-3__L1__gemini"]),
    ({"limit": 2}, ["CVE-1__L1__claude", "CVE-1__L2__gpt"]),
])
def test_cells_can_be_narrowed(logs, kw, expected):
    assert [p.stem for p in pe._log_cells(_args(**kw))] == expected


def test_a_misnamed_log_is_never_a_cell(logs):
    assert all(p.stem != "not-a-cell" for p in pe._log_cells(_args()))


# ── the oracle's own contract ────────────────────────────────────────────

def test_the_oracle_covers_four_distinct_cves():
    assert len(pe.ORACLE_CVES) == 4
    assert len(set(pe.ORACLE_CVES)) == 4


def test_the_oracle_expects_l3_from_the_fix_and_l1_from_the_bug():
    # The synthetic models are named in the rows they write, so a later reader
    # can tell an oracle row from a model's.
    assert len({pe.ORACLE_REFERENCE, pe.ORACLE_VULNERABLE, pe.ORACLE_REGRESSION}) == 3
    assert pe.ORACLE_LEVEL == "oracle"


# ── the L2 oracle: a break that fails one judged test ────────────────────

BREAK = {"cve": "CVE-X", "replace": {"old": "do_thing()", "new": "pass"}}


def test_a_break_replaces_its_one_match():
    assert pe.apply_break(b"def f():\n    do_thing()\n", BREAK) == b"def f():\n    pass\n"


@pytest.mark.parametrize("source,why", [
    (b"def f():\n    other()\n", "matches nothing"),
    (b"do_thing()\ndo_thing()\n", "matches twice"),
])
def test_a_break_that_matches_other_than_once_is_refused(source, why):
    with pytest.raises(pe.Refused):
        pe.apply_break(source, BREAK)


def test_no_break_is_recorded_for_a_cve_without_one():
    assert pe.load_break("CVE-0000-0000") is None


def test_the_shipped_break_names_a_test_that_is_really_judged():
    recipe = pe.load_break("CVE-2022-39286")
    assert recipe is not None
    assert recipe["expected_trust_level"] == "L2"
    assert recipe["replace"]["old"] and recipe["replace"]["new"]
    assert recipe["model_id"]
    # The break is pointless if the test it breaks is not in the judged set.
    judged = pe.load_baseline()["CVE-2022-39286"]["judged"]
    assert recipe["expected_regression"] in judged
