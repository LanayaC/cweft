"""
The Vul4J grader: PoV from Vul4J's failing_tests, judged set from the reference
fix's baseline runs, regressions counted only among judged tests - the same
rules as the PatchEval grader. Offline: test results are built as vul4j's
testing_results.json would hold them.

Covers the three cases that broke the old grader, plus the normal case:
  * VUL4J-77, whose test_cmd PoV was the wildcard "io.swagger.parser.util.*"
  * VUL4J-40/61, Gradle projects whose test names carry "()"
  * VUL4J-61, whose suite has failures that are there before any patch
"""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import evaluate  # noqa: E402
import regrade_published_vul4j as rg  # noqa: E402
import vul4j_grading as vg  # noqa: E402
import vuln_data  # noqa: E402

MANIFEST = {e["vul_id"]: e for e in
            json.loads((PROJECT_ROOT / "data" / "vul4j" / "manifest.json")
                       .read_text(encoding="utf-8"))["entries"]}


def results(passing=(), failing=(), skipped=()):
    """A testing_results.json as `vul4j test` writes it."""
    return {"tests": {
        "overall_metrics": {},
        "passing_tests": list(passing),
        "skipping_tests": list(skipped),
        "failures": [{"test_class": n.split("#")[0], "test_method": n.split("#")[1],
                      "failure_name": "AssertionError", "is_error": False} for n in failing],
    }}


def entry_from(pov_raw, reference_runs):
    """A baseline entry built the way vul4j_baseline.py builds one."""
    runs = [vg.fold_results(r) for r in reference_runs]
    observed = set().union(*runs)
    pov, unresolved, _ = vg.resolve_pov(pov_raw, observed)
    assert not unresolved
    judged, excluded = vg.judged_set(runs, pov)
    return {"status": "ok", "pov": pov, "judged": judged, "judged_count": len(judged),
            "excluded": excluded}


def grade(entry, first, rerun=None):
    first = vg.fold_results(first)
    out = evaluate.classify(True, first, None, entry)
    if out["pov_passed"] and vg.needs_rerun(entry["judged"], first):
        out = evaluate.classify(True, first, vg.fold_results(rerun) if rerun else {}, entry)
    return out


# ── VUL4J-77: the wildcard ───────────────────────────────────────────────

CVE77 = "io.swagger.parser.util.SwaggerDeserializerTest#testCVE_2017_1000207"
OTHER77 = ["io.swagger.parser.SwaggerResolverTest#testA", "io.swagger.parser.AnchorTest#testB"]


def test_vul4j_77_pov_is_the_named_test_not_the_wildcard():
    e = MANIFEST["VUL4J-77"]
    assert e["failing_tests"] == [CVE77]
    assert e["failing_tests_source"] == "vul4j_failing_tests"
    assert e["failing_tests_from_test_cmd"] == ['"io.swagger.parser.util.*"']


def test_vul4j_77_cve_test_failing_is_l1_not_l2():
    """Tonight's Granite cell: only the CVE's own test failed. That is the hole still open."""
    entry = entry_from([CVE77], [results(passing=OTHER77 + [CVE77])] * 3)
    out = grade(entry, results(passing=OTHER77, failing=[CVE77]))
    assert out["trust"] == "L1" and out["pov_passed"] is False


def test_vul4j_77_cve_test_passing_is_l3():
    entry = entry_from([CVE77], [results(passing=OTHER77 + [CVE77])] * 3)
    assert grade(entry, results(passing=OTHER77 + [CVE77]))["trust"] == "L3"


# ── VUL4J-40/61: Gradle names with brackets ──────────────────────────────

POV40 = ("org.cloudfoundry.identity.uaa.security.ScimUserSelfUpdateAllowedTest"
         "$WithInternalUserStoreEnabled$WhenAttemptingToUpdateAFieldThatIsNotAllowedToBeUpdated"
         "$WhenUpdatingTheEmailField#isNotAllowedToUpdateField")
SIBLING40 = ("org.cloudfoundry.identity.uaa.security.ScimUserSelfUpdateAllowedTest"
             "$WithInternalUserStoreEnabled$WhenScimUserDoesNotExist#isAllowed()")


def test_canonical_drops_parameter_lists():
    assert vg.canonical(POV40 + "()") == POV40
    assert vg.canonical("a.B$C#happyCase(List)[1]") == "a.B$C#happyCase[1]"
    assert vg.canonical("a.B") == "a.B"


def test_vul4j_40_pov_with_brackets_failing_is_l1():
    entry = entry_from([POV40], [results(passing=[POV40 + "()", SIBLING40])] * 3)
    assert entry["pov"] == [POV40]
    out = grade(entry, results(passing=[SIBLING40], failing=[POV40 + "()"]))
    assert out["trust"] == "L1"


def test_vul4j_40_pov_passing_but_sibling_broken_is_l2():
    entry = entry_from([POV40], [results(passing=[POV40 + "()", SIBLING40])] * 3)
    out = grade(entry, results(passing=[POV40 + "()"], failing=[SIBLING40]),
                rerun=results(passing=[POV40 + "()"], failing=[SIBLING40]))
    assert out["trust"] == "L2"
    assert out["regressions"] == [vg.canonical(SIBLING40)]


# ── VUL4J-61: failures that are there before any patch ───────────────────

POV61 = "apoc.load.XmlTest#testLoadXmlPreventXXEVulnerabilityThrowsQueryExecutionException"
LDAP61 = "apoc.load.LoadLdapTest#testLoadLDAP"          # needs a network
GEO61 = "apoc.spatial.GeocodeTest#testGeocodeOSM"       # needs a network
FINE61 = ["apoc.load.XmlTest#testLoadXml", "apoc.path.PathTest#testExpand"]


def test_vul4j_61_pre_existing_failures_are_not_judged():
    entry = entry_from([POV61], [results(passing=FINE61 + [POV61], failing=[LDAP61, GEO61])] * 3)
    assert LDAP61 not in entry["judged"] and GEO61 not in entry["judged"]
    assert entry["excluded"][LDAP61] == "failed on the reference fix"
    out = grade(entry, results(passing=FINE61 + [POV61], failing=[LDAP61, GEO61]))
    assert out["trust"] == "L3" and out["regressions"] == []


def test_a_test_flaky_on_the_reference_is_not_judged():
    runs = [results(passing=FINE61 + [POV61, LDAP61]),
            results(passing=FINE61 + [POV61], failing=[LDAP61]),
            results(passing=FINE61 + [POV61, LDAP61])]
    entry = entry_from([POV61], runs)
    assert LDAP61 not in entry["judged"]
    assert entry["excluded"][LDAP61].startswith("inconsistent")


# ── The normal case ──────────────────────────────────────────────────────

POV = "org.foo.BarTest#testCve"
JUDGED = ["org.foo.BarTest#testOk", "org.foo.BazTest#testAlsoOk"]


@pytest.fixture
def normal():
    return entry_from([POV], [results(passing=JUDGED + [POV])] * 3)


def test_normal_pov_failing_is_l1(normal):
    assert grade(normal, results(passing=JUDGED, failing=[POV]))["trust"] == "L1"


def test_normal_clean_pass_is_l3(normal):
    assert grade(normal, results(passing=JUDGED + [POV]))["trust"] == "L3"


def test_normal_regression_confirmed_on_rerun_is_l2(normal):
    broken = results(passing=[POV, JUDGED[0]], failing=[JUDGED[1]])
    out = grade(normal, broken, rerun=broken)
    assert out["trust"] == "L2" and out["regressions"] == [JUDGED[1]]


def test_normal_failure_that_passes_on_rerun_is_flaky_not_a_regression(normal):
    out = grade(normal, results(passing=[POV, JUDGED[0]], failing=[JUDGED[1]]),
                rerun=results(passing=JUDGED + [POV]))
    assert out["trust"] == "L3" and out["flaky"] == [JUDGED[1]]


def test_a_judged_test_that_did_not_run_counts_as_a_regression(normal):
    out = grade(normal, results(passing=[POV, JUDGED[0]]), rerun=results(passing=[POV, JUDGED[0]]))
    assert out["trust"] == "L2" and out["regressions"] == [JUDGED[1]]


def test_a_pov_test_that_did_not_run_is_not_a_pass(normal):
    out = grade(normal, results(passing=JUDGED))
    assert out["trust"] == "L1" and "did not run" in out["note"]


def test_no_compile_is_l0(normal):
    assert evaluate.classify(False, None, None, normal)["trust"] == "L0"


def test_no_test_results_is_l1(normal):
    out = evaluate.classify(True, None, None, normal)
    assert out["trust"] == "L1" and "no results" in out["note"]


# ── PoV resolution and the baseline gate ─────────────────────────────────

def test_pov_resolves_ignoring_case_when_vul4j_has_the_case_wrong():
    pov, unresolved, notes = vg.resolve_pov(
        ["org.OWASP.esapi.codecs.CodecImmunityTest#testImmuneEncode[PercentCodec %De]"],
        ["org.owasp.esapi.codecs.CodecImmunityTest#testImmuneEncode[PercentCodec %De]"])
    assert pov == ["org.owasp.esapi.codecs.CodecImmunityTest#testImmuneEncode[PercentCodec %De]"]
    assert not unresolved and notes


def test_an_unknown_pov_is_unresolved():
    _, unresolved, _ = vg.resolve_pov(["a.B#c"], ["a.B#d"])
    assert unresolved == ["a.B#c"]


@pytest.mark.parametrize("entry,expect", [
    (None, "not in data/vul4j/baseline.json"),
    ({"status": "pov_not_found"}, "baseline status"),
    ({"status": "ok", "pov": [], "judged": ["x"]}, "no PoV"),
    ({"status": "ok", "pov": ["x"], "judged": []}, "no judged"),
])
def test_grade_refuses_without_a_usable_baseline(entry, expect, monkeypatch):
    monkeypatch.setattr(evaluate, "fresh_checkout",
                        lambda v: pytest.fail("must refuse before touching the container"))
    out = evaluate.grade("VUL4J-1", "A.java", lambda w, f: None, entry)
    assert out["trust"] == "refused" and expect in out["error"]


def test_the_test_cmd_parser_is_only_a_logged_fallback(capsys):
    tests, source = vuln_data.pov_tests("VUL4J-0", {"failing_tests": "a.B#c, a.B#d"},
                                        {"test_cmd": "mvn -Dtest=x.Y"})
    assert (tests, source) == (["a.B#c", "a.B#d"], "vul4j_failing_tests")
    assert capsys.readouterr().err == ""
    tests, source = vuln_data.pov_tests("VUL4J-0", {"failing_tests": ""},
                                        {"test_cmd": "mvn -Dtest=x.Y"})
    assert (tests, source) == (["x.Y"], "test_cmd")
    assert "WARNING" in capsys.readouterr().err


def test_every_exported_entry_takes_its_pov_from_vul4j():
    assert {e["failing_tests_source"] for e in MANIFEST.values()} == {"vul4j_failing_tests"}
    assert all(e["failing_tests"] for e in MANIFEST.values())


# ── Re-grading a published row ───────────────────────────────────────────

def _row(trust, pov_passed, regressions=""):
    return {"trust_level": trust, "pov_passed": pov_passed, "regressions": regressions}


def test_regrade_77_l2_with_the_cve_test_failing_becomes_l1():
    entry = {"status": "ok", "pov": [CVE77], "judged": OTHER77}
    r = rg.regrade_row(_row("L2", "True", CVE77), ['"io.swagger.parser.util.*"'], entry)
    assert (r["new"], r["basis"]) == ("L1", rg.EXACT)


def test_regrade_40_pov_with_brackets_among_regressions_becomes_l1():
    entry = {"status": "ok", "pov": [POV40], "judged": [vg.canonical(SIBLING40)]}
    r = rg.regrade_row(_row("L2", "True", POV40 + "()"), [], entry)
    assert r["new"] == "L1"


def test_regrade_61_pre_existing_failures_only_becomes_l3():
    entry = {"status": "ok", "pov": [POV61], "judged": FINE61}
    r = rg.regrade_row(_row("L2", "True", f"{LDAP61};{GEO61}"), [], entry)
    assert (r["new"], r["basis"]) == ("L3", rg.EXACT)


def test_regrade_class_level_old_l1_is_undetermined():
    entry = {"status": "ok", "pov": [POV], "judged": JUDGED}
    r = rg.regrade_row(_row("L1", "False"), ["org.foo.BarTest"], entry)
    assert r["basis"] == rg.UNDETERMINED and r["possible"][0] == "L1"


def test_regrade_method_level_old_l1_stays_l1():
    entry = {"status": "ok", "pov": [POV], "judged": JUDGED}
    r = rg.regrade_row(_row("L1", "False"), [POV], entry)
    assert (r["new"], r["basis"]) == ("L1", rg.EXACT)


def test_regrade_l0_is_unchanged():
    r = rg.regrade_row(_row("L0", ""), [], {"status": "ok", "pov": [POV], "judged": JUDGED})
    assert r["new"] == "L0"


# ── Resuming the baseline ────────────────────────────────────────────────

def test_resume_redoes_only_what_the_current_code_did_not_build():
    import run_vul4j_validation as run
    entries = {
        "A": {"status": "ok", "code_fingerprint": "new"},
        "B": {"status": "ok", "code_fingerprint": "old"},
        "C": {"status": "error", "code_fingerprint": "new"},
        "D": {"status": "no_judged_set", "code_fingerprint": "new"},
    }
    assert run.stale(entries, ["A", "B", "C", "D", "E"], "new") == ["B", "C", "E"]
