"""
Grading rules for Vul4J cells, the same rules the PatchEval grader uses.

Kept free of Docker so every decision can be tested offline. The Docker side
(running `vul4j test`) lives in vul4j_baseline.py and evaluate.py.

  * The PoV tests are Vul4J's own `failing_tests` column, resolved once against
    the tests that really ran (vul4j_baseline.py) and stored in the baseline.
    The PoV passes only if every PoV test ran AND passed: a PoV test that did
    not run cannot show the hole is closed.
  * The judged set is the tests that passed in ALL of the reference fix's
    baseline runs, PoV tests excluded. Anything that fails on the reference,
    or disagrees across runs, is excluded, so a failure that was already there
    before the patch is never counted against it.
  * Regressions are judged tests that did not pass. A judged test that did not
    pass gets one rerun before it counts, so one flake does not read as a
    broken patch.

Test names are compared in canonical form: Gradle/JUnit 5 report a method as
`name()` or `name(String)[1]`, Vul4J's metadata as `name`, so parameter lists
in parentheses are dropped on both sides.
"""

import re
from typing import Dict, Iterable, List, Optional, Tuple

PASSED, FAILED, SKIPPED, MISSING = "passed", "failed", "skipped", "missing"
L0, L1, L2, L3 = "L0", "L1", "L2", "L3"

_PARAMS = re.compile(r"\([^()]*\)")


def canonical(name: str) -> str:
    """`pkg.Class#method(args)[i]` -> `pkg.Class#method[i]`; class part unchanged."""
    name = name.strip()
    if "#" not in name:
        return name
    cls, method = name.split("#", 1)
    return f"{cls}#{_PARAMS.sub('', method)}"


def parse_failing_tests(field: str) -> List[str]:
    """Vul4J's `failing_tests` CSV cell: comma-separated `Class#method` names."""
    return [t.strip() for t in (field or "").split(",") if t.strip()]


def fold_results(testing_results: Optional[dict]) -> Dict[str, str]:
    """
    One status per canonical test name from vul4j's testing_results.json.

    A test reported more than once (some projects write two XML reports per
    class) is failed if any report failed it, else passed if any passed it.
    """
    if not testing_results:
        return {}
    t = testing_results.get("tests", testing_results)
    out: Dict[str, str] = {}
    for name in t.get("skipping_tests") or []:
        out.setdefault(canonical(name), SKIPPED)
    for name in t.get("passing_tests") or []:
        out[canonical(name)] = PASSED
    for f in t.get("failures") or []:
        out[canonical(f"{f.get('test_class', '')}#{f.get('test_method', '')}")] = FAILED
    return out


def resolve_pov(pov: Iterable[str], observed: Iterable[str]) -> Tuple[List[str], List[str], List[str]]:
    """
    (resolved, unresolved, notes): each PoV name matched to a test that ran.

    Exact canonical match first; failing that, a case-insensitive match (Vul4J's
    metadata has at least one package name in the wrong case). Anything still
    unmatched is unresolved and makes the entry unusable.
    """
    observed = list(observed)
    by_lower: Dict[str, List[str]] = {}
    for name in observed:
        by_lower.setdefault(name.lower(), []).append(name)
    resolved, unresolved, notes = [], [], []
    seen = set(observed)
    for raw in pov:
        name = canonical(raw)
        if name in seen:
            resolved.append(name)
        elif len(by_lower.get(name.lower(), [])) == 1:
            match = by_lower[name.lower()][0]
            resolved.append(match)
            notes.append(f"{raw} matched {match} ignoring case")
        else:
            unresolved.append(raw)
    return sorted(set(resolved)), unresolved, notes


def judged_set(reference_runs: List[Dict[str, str]], pov: Iterable[str]) -> Tuple[List[str], Dict[str, str]]:
    """
    (judged, excluded): tests that passed in every reference run, PoV excluded,
    and why each other test seen in those runs was left out.
    """
    pov = set(pov)
    names = set()
    for run in reference_runs:
        names.update(run)
    judged, excluded = [], {}
    for name in sorted(names):
        if name in pov:
            continue
        statuses = [run.get(name, MISSING) for run in reference_runs]
        if all(s == PASSED for s in statuses):
            judged.append(name)
        elif all(s == statuses[0] for s in statuses):
            excluded[name] = f"{statuses[0]} on the reference fix"
        else:
            excluded[name] = "inconsistent on the reference fix: " + ",".join(statuses)
    return judged, excluded


def pov_outcome(pov: Iterable[str], run: Dict[str, str]) -> Tuple[bool, str]:
    """(passed, note): every PoV test must have run and passed."""
    pov = list(pov)
    if not pov:
        return False, "no PoV tests"
    missing = [p for p in pov if run.get(p, MISSING) == MISSING]
    if missing:
        return False, "PoV test did not run: " + ", ".join(missing)
    failing = [p for p in pov if run[p] != PASSED]
    if failing:
        return False, ""
    return True, ""


def count_regressions(judged: List[str], first: Dict[str, str],
                      rerun: Optional[Dict[str, str]]) -> Tuple[List[str], List[str]]:
    """(regressions, flaky): judged tests not passing, after one rerun."""
    regressions, flaky = [], []
    for name in judged:
        if first.get(name, MISSING) == PASSED:
            continue
        second = first.get(name, MISSING) if rerun is None else rerun.get(name, MISSING)
        if second == PASSED:
            flaky.append(name)
        else:
            regressions.append(name)
    return regressions, flaky


def needs_rerun(judged: List[str], first: Dict[str, str]) -> bool:
    return any(first.get(n, MISSING) != PASSED for n in judged)


def trust_level(compiled: bool, pov_passed: Optional[bool], n_regressions: Optional[int]) -> str:
    if not compiled:
        return L0
    if not pov_passed:
        return L1
    return L2 if n_regressions else L3
