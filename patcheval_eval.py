"""
PatchEval scoring backend, reached via `python evaluate.py --dataset patcheval`.

Scores one candidate file for one CVE against that CVE's baseline entry, and
appends a row to results/results_patcheval.csv. results/results.csv belongs to
the Vul4J backend and is never opened here.

A trust level, decided in this order and stopping at the first answer:

    L0  the candidate does not parse (the image's own checker, per language)
    L1  it parses, but vul-run.sh still fails: the hole is still open
    L2  the hole is closed, but a test in the baseline's judged set now fails
    L3  the hole is closed and the whole judged set still passes

The judged set comes from the baseline, never from this run, and a CVE is
refused unless its baseline entry is `ok`, has a judged set, and its image
digest still matches the one that was baselined. A candidate that cannot be
scored is refused rather than scored badly: the row carries trust_level
`refused` and the reason in `error`.

Two conservative choices, both recorded rather than hidden:

  - A judged test that fails is run a second time before it counts, since the
    baseline only judges a test that agreed across its three runs. Failing
    twice is a regression; failing then passing is flaky, and is excluded
    rather than counted.
  - If the candidate's test run is unusable at all (it broke collection, say),
    every judged test counts as a regression, because none of them passed. An
    unusable report must never read as zero failures.

    python evaluate.py --dataset patcheval              # score the patch logs
    python patcheval_eval.py --oracle                   # the synthetic check
    python patcheval_eval.py --oracle --cves CVE-2022-2900
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import shlex
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from config import PATCHEVAL_DIR, PATCHEVAL_LOGS_DIR, PROJECT_ROOT, RESULTS_DIR
import patcheval_baseline as pb
import patcheval_docker as pdock
import patcheval_l0 as pl0
import patcheval_testparse as ptp


BASELINE_PATH = PATCHEVAL_DIR / "baseline.json"
# This backend's own file. results/results.csv is Vul4J's and is never touched.
RESULTS_CSV = RESULTS_DIR / "results_patcheval.csv"

L0, L1, L2, L3 = "L0", "L1", "L2", "L3"
REFUSED = "refused"          # not a trust level: nothing was scored

CSV_FIELDS = [
    "cve", "language", "cwe", "level", "model_key", "model_id",
    "image_digest", "digest_matches_baseline",
    "l0_checker", "l0_passed", "poc_passed",
    "judged_set_size", "tests_run", "regressions", "n_regressions",
    "flaky_excluded", "trust_level", "error", "timings",
    "code_fingerprint", "timestamp",
]

# The modules a verdict depends on: the judged set and its reader come from the
# first two, the scoring from this one.
FINGERPRINTED = ("patcheval_baseline.py", "patcheval_testparse.py", "patcheval_eval.py")

ORACLE_LEVEL = "oracle"
ORACLE_REFERENCE = "oracle_reference"
ORACLE_VULNERABLE = "oracle_vulnerable"
# One per language, including the single TypeScript entry. All four are `ok`
# with small judged sets, and none uses mocha, whose recorded command predates
# the mocha fix and would rightly be refused.
ORACLE_CVES = ["CVE-2022-39286", "CVE-2024-5138", "CVE-2022-2900", "CVE-2025-23221"]


class Refused(RuntimeError):
    """The CVE or the candidate cannot be scored, so nothing is scored."""


def code_fingerprint() -> str:
    """Short hash of the modules a row's verdict depends on."""
    h = hashlib.sha256()
    for mod in FINGERPRINTED:
        h.update((PROJECT_ROOT / mod).read_bytes())
    return h.hexdigest()[:12]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_baseline() -> dict:
    if not BASELINE_PATH.exists():
        raise Refused(f"no baseline at {BASELINE_PATH}")
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8")).get("entries") or {}


# ── Decisions, kept clear of Docker so they can be tested offline ────────

def refusal(entry: Optional[dict]) -> str:
    """Why this CVE cannot be scored, or "" when it can."""
    if not entry:
        return "not in the baseline"
    if entry.get("status") != pb.OK:
        return f"baseline status is {entry.get('status')!r}, not {pb.OK!r}"
    if not entry.get("judged"):
        return "baseline entry has no judged set"
    if not entry.get("image_digest"):
        return "baseline entry records no image digest"
    if not (entry.get("test_plan") or {}).get("command"):
        return "baseline entry records no test command"
    return ""


def count_regressions(judged: List[str], first: Dict[str, str],
                      rerun: Optional[Dict[str, str]]) -> Tuple[List[str], List[str]]:
    """
    (regressions, flaky_excluded) among the judged tests.

    A judged test that did not pass gets a second run before it counts, so one
    flake does not read as a broken patch. `rerun` is None when no rerun was
    needed because everything passed first time.
    """
    regressions, flaky = [], []
    for name in judged:
        if first.get(name, "missing") == ptp.PASSED:
            continue
        second = first.get(name, "missing") if rerun is None else rerun.get(name, "missing")
        if second == ptp.PASSED:
            flaky.append(name)
        else:
            regressions.append(name)
    return regressions, flaky


def trust_level(l0_passed: bool, poc_passed: Optional[bool],
                n_regressions: Optional[int]) -> str:
    """The trust level, from the three things that decide it."""
    if not l0_passed:
        return L0
    if not poc_passed:
        return L1
    return L2 if n_regressions else L3


# ── The CSV ──────────────────────────────────────────────────────────────

def done_cells(path: Path = None) -> set:
    """(cve, level, model_key) already scored, so a rerun can skip them."""
    path = path or RESULTS_CSV
    if not path.exists():
        return set()
    with path.open(encoding="utf-8", newline="") as f:
        return {(r["cve"], r["level"], r["model_key"]) for r in csv.DictReader(f)}


def append_row(row: dict, path: Path = None) -> None:
    path = path or RESULTS_CSV
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="raise")
        if new:
            w.writeheader()
        w.writerow(row)


_MANIFEST: Optional[dict] = None


def _manifest_entry(cve: str) -> dict:
    """The CVE's manifest entry, which is where its CWE labels live: the
    baseline records what happened in the image, not the dataset's labels."""
    global _MANIFEST
    if _MANIFEST is None:
        try:
            _MANIFEST = pb.manifest()
        except Exception:
            _MANIFEST = {}
    return _MANIFEST.get(cve) or {}


def _row(cve: str, entry: Optional[dict], level: str, model_key: str,
         model_id: str, **kw) -> dict:
    entry = entry or {}
    man = _manifest_entry(cve)
    row = {
        "cve": cve,
        "language": entry.get("language") or man.get("prompt_language", ""),
        "cwe": man.get("primary_cwe") or ";".join(man.get("cwe_list") or []),
        "level": level,
        "model_key": model_key,
        "model_id": model_id,
        "image_digest": entry.get("image_digest", ""),
        "digest_matches_baseline": "",
        "l0_checker": "",
        "l0_passed": "",
        "poc_passed": "",
        "judged_set_size": len(entry.get("judged") or []),
        "tests_run": "",
        "regressions": "",
        "n_regressions": "",
        "flaky_excluded": "",
        "trust_level": "",
        "error": "",
        "timings": "",
        "code_fingerprint": code_fingerprint(),
        "timestamp": _now(),
    }
    row.update(kw)
    if isinstance(row.get("timings"), dict):
        row["timings"] = json.dumps(row["timings"], separators=(",", ":"))
    for key in ("regressions", "flaky_excluded"):
        if isinstance(row.get(key), (list, tuple)):
            row[key] = ";".join(row[key])
    return row


# ── Container-side scoring ───────────────────────────────────────────────

def _plan_from_baseline(name: str, repo_dir: str, rel_path: str, entry: dict) -> pb.TestPlan:
    """
    The baseline's test command, rebuilt in this container.

    The command is re-resolved rather than taken on trust, because a plan can
    involve a script staged in /tmp that a fresh container does not have. If
    what comes back does not match what the baseline recorded, the judged set
    was defined under a different command, and this CVE is refused instead of
    being scored against tests it was not judged on.
    """
    want = (entry.get("test_plan") or {}).get("command")
    candidates = [p for p in pb.resolve_test_plan(name, repo_dir, rel_path) if p]
    for plan in candidates:
        if plan.command == want:
            return plan
    raise Refused(f"cannot reproduce the baseline test command {want!r}; "
                  f"this container offers {[p.command for p in candidates]}")


def _poc_timeout(entry: dict) -> float:
    return ((entry.get("poc") or {}).get("fix_run") or {}).get("timeout_used") or pb.MAX_TIMEOUT


def _tests_timeout(entry: dict) -> float:
    return (entry.get("durations_seconds") or {}).get("timeout_after_first_run") or pb.MAX_TIMEOUT


def _write_candidate(name: str, repo_dir: str, rel_path: str, candidate: bytes) -> None:
    """
    A clean tree with the candidate in place, byte for byte.

    git reset is what the baseline does between runs, and it would take the
    candidate with it, so the candidate goes back afterwards. write_file_bytes
    overwrites in place, so the file keeps its owner and mode, and it verifies
    the sha256 it wrote.
    """
    pb.reset_repo(name, repo_dir)
    pdock.write_file_bytes(name, f"{repo_dir}/{rel_path}", candidate)


def score_candidate(cve: str, candidate: bytes, level: str, model_key: str,
                    model_id: str = "", entry: dict = None,
                    keep_image: bool = True) -> dict:
    """Score one candidate file for one CVE. Returns the CSV row."""
    entry = entry or load_baseline().get(cve)
    why = refusal(entry)
    if why:
        return _row(cve, entry, level, model_key, model_id,
                    trust_level=REFUSED, error=why)

    digest = entry["image_digest"]
    tag = entry["image_tag"]
    rel_path = entry["vulnerable_file_path"]
    judged = list(entry["judged"])
    timings: Dict[str, float] = {}
    matches = None

    pulled = pdock.ensure_image(digest)
    current = pdock.repo_digest(tag) if pdock.image_present(tag) else digest
    matches = current == digest
    if not matches:
        return _row(cve, entry, level, model_key, model_id,
                    digest_matches_baseline=False, trust_level=REFUSED,
                    error=f"image digest {current} is not the baselined {digest}")

    name = pdock.container_name("eval", cve.replace("-", "_"), model_key)
    started = False
    try:
        pdock.start_container(name, digest)          # by digest, --network none
        started = True
        repo_dir = entry.get("repo_dir") or pb.find_repo_dir(name)
        _write_candidate(name, repo_dir, rel_path, candidate)

        t0 = time.time()
        l0 = pl0.check_l0(name, repo_dir, rel_path)
        timings["l0"] = round(time.time() - t0, 1)
        if not l0.passed:
            return _row(cve, entry, level, model_key, model_id,
                        digest_matches_baseline=True, l0_checker=l0.checker,
                        l0_passed=False, trust_level=L0, timings=timings,
                        error=l0.error_tail[:300])

        t0 = time.time()
        vul = pdock.exec_in(name, f"bash {pb.VUL_RUN}", timeout=_poc_timeout(entry))
        timings["poc"] = round(time.time() - t0, 1)
        # vul-run.sh fails while the bug is reachable, so it passing is the
        # candidate having closed the hole.
        poc_passed = vul.rc == 0 and not vul.timed_out
        if not poc_passed:
            return _row(cve, entry, level, model_key, model_id,
                        digest_matches_baseline=True, l0_checker=l0.checker,
                        l0_passed=True, poc_passed=False, trust_level=L1,
                        timings=timings,
                        error="vul-run.sh timed out" if vul.timed_out else "")

        plan = _plan_from_baseline(name, repo_dir, rel_path, entry)
        timeout = _tests_timeout(entry)

        _write_candidate(name, repo_dir, rel_path, candidate)
        t0 = time.time()
        first = pb.run_tests(name, repo_dir, plan, timeout)
        timings["tests"] = round(time.time() - t0, 1)

        note = ""
        if first["status"] != ptp.OK:
            note = (f"candidate test run unusable ({first['status']}): "
                    f"{first['message'][:200]}")
            regressions, flaky = list(judged), []
        else:
            folded = pb._fold_run(first["cases"])
            rerun_folded = None
            if any(folded.get(n, "missing") != ptp.PASSED for n in judged):
                _write_candidate(name, repo_dir, rel_path, candidate)
                t0 = time.time()
                second = pb.run_tests(name, repo_dir, plan, timeout)
                timings["tests_rerun"] = round(time.time() - t0, 1)
                if second["status"] == ptp.OK:
                    rerun_folded = pb._fold_run(second["cases"])
                else:
                    rerun_folded = {}
                    note = (f"rerun unusable ({second['status']}): "
                            f"{second['message'][:150]}")
            regressions, flaky = count_regressions(judged, folded, rerun_folded)

        return _row(cve, entry, level, model_key, model_id,
                    digest_matches_baseline=True, l0_checker=l0.checker,
                    l0_passed=True, poc_passed=True, tests_run=first["total"],
                    regressions=regressions, n_regressions=len(regressions),
                    flaky_excluded=flaky,
                    trust_level=trust_level(True, True, len(regressions)),
                    timings=timings, error=note)
    except Refused as e:
        return _row(cve, entry, level, model_key, model_id,
                    digest_matches_baseline=matches, trust_level=REFUSED,
                    error=str(e), timings=timings)
    except (pb.BaselineError, pl0.L0SetupError) as e:
        return _row(cve, entry, level, model_key, model_id,
                    digest_matches_baseline=matches, trust_level=REFUSED,
                    error=f"{type(e).__name__}: {e}", timings=timings)
    finally:
        if started:
            pdock.remove_container(name)
        if pulled and not keep_image:
            pdock.remove_image(digest, pulled)


# ── The oracle check ─────────────────────────────────────────────────────

def reference_fixed_bytes(cve: str, entry: dict) -> bytes:
    """The file as the reference fix leaves it, read out of the image."""
    digest, rel_path = entry["image_digest"], entry["vulnerable_file_path"]
    pdock.ensure_image(digest)
    name = pdock.container_name("ref", cve.replace("-", "_"))
    try:
        pdock.start_container(name, digest)
        repo_dir = entry.get("repo_dir") or pb.find_repo_dir(name)
        pb.reset_repo(name, repo_dir)
        pb.apply_fix(name, repo_dir)
        target = shlex.quote(f"{repo_dir}/{rel_path}")
        r = pdock.exec_in(name, f"base64 -w0 -- {target}", timeout=120)
        if r.rc != 0:
            raise Refused(f"cannot read the fixed {rel_path}: {r.stderr[-200:]}")
        return base64.b64decode(r.stdout.strip())
    finally:
        pdock.remove_container(name)


def oracle(cves: List[str]) -> int:
    """
    Score two synthetic models per CVE and check the verdicts are forced.

    The reference-fixed file must come out L3: it closes the hole, and it is
    what the judged set was derived from. The untouched vulnerable file must
    come out L1: it parses, and the PoC still shows the bug. Returns how many
    verdicts came out wrong.
    """
    entries = load_baseline()
    man = pb.manifest()
    wrong = 0
    already = done_cells()
    for cve in cves:
        entry = entries.get(cve)
        why = refusal(entry)
        if why:
            print(f"{cve:18s} refused: {why}", flush=True)
            wrong += 1
            continue
        plans = [
            (ORACLE_REFERENCE, L3, "reference fix (fix.patch applied)",
             lambda e=entry, c=cve: reference_fixed_bytes(c, e)),
            (ORACLE_VULNERABLE, L1, "unpatched vulnerable file (frozen copy)",
             lambda c=cve: pb.frozen_bytes(c, man[c])),
        ]
        for model_key, expected, model_id, get_bytes in plans:
            if (cve, ORACLE_LEVEL, model_key) in already:
                print(f"{cve:18s} {model_key:18s} already scored, skipped", flush=True)
                continue
            try:
                row = score_candidate(cve, get_bytes(), ORACLE_LEVEL, model_key,
                                      model_id, entry=entry)
            except Exception as e:                   # keep the oracle going
                row = _row(cve, entry, ORACLE_LEVEL, model_key, model_id,
                           trust_level=REFUSED, error=f"{type(e).__name__}: {e}")
            append_row(row)
            got = row["trust_level"]
            ok = got == expected
            wrong += 0 if ok else 1
            print(f"{cve:18s} {model_key:18s} expected {expected}  got {got:8s} "
                  f"{'OK' if ok else 'WRONG'}  judged={row['judged_set_size']} "
                  f"regressions={row['n_regressions']} {str(row['error'])[:70]}",
                  flush=True)
    return wrong


# ── Scoring the patch logs ───────────────────────────────────────────────

def _log_cells(args) -> List[Path]:
    def keep(p: Path) -> bool:
        parts = p.stem.split("__")
        if len(parts) != 3:
            return False
        cve, level, model = parts
        if getattr(args, "vulns", None) and cve not in args.vulns:
            return False
        if getattr(args, "levels", None) and level not in args.levels:
            return False
        if getattr(args, "models", None) and model not in args.models:
            return False
        return True

    kept = [p for p in sorted(PATCHEVAL_LOGS_DIR.glob("*.json")) if keep(p)]
    limit = getattr(args, "limit", None)
    return kept[:limit] if limit else kept


def main(args) -> None:
    """The backend evaluate.py calls for --dataset patcheval."""
    cells = _log_cells(args)
    if not cells:
        print(f"No PatchEval patch logs in {PATCHEVAL_LOGS_DIR}")
        print("Generate some with: python generate.py --dataset patcheval")
        return
    already = done_cells()
    counts: Dict[str, int] = {}
    for i, path in enumerate(cells, start=1):
        cve, level, model_key = path.stem.split("__")
        if (cve, level, model_key) in already:
            continue
        log = json.loads(path.read_text(encoding="utf-8"))
        row = score_candidate(cve, (log.get("response") or "").encode("utf-8"),
                              level, model_key, log.get("model_id", ""))
        append_row(row)
        counts[row["trust_level"]] = counts.get(row["trust_level"], 0) + 1
        print(f"[{i}/{len(cells)}] {cve:18s} {level:5s} {model_key:10s} "
              f"{row['trust_level']:8s} {str(row['error'])[:60]}", flush=True)
    print(f"\n{counts}  ->  {RESULTS_CSV}")


def _cli(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score PatchEval candidate patches")
    ap.add_argument("--oracle", action="store_true",
                    help="score the two synthetic models per CVE and check the verdicts")
    ap.add_argument("--cves", nargs="+", default=None,
                    help=f"CVEs for --oracle (default: {' '.join(ORACLE_CVES)})")
    ap.add_argument("--models", nargs="+", default=None)
    ap.add_argument("--levels", nargs="+", default=None)
    ap.add_argument("--vulns", nargs="+", default=None)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)
    if args.oracle:
        wrong = oracle(args.cves or ORACLE_CVES)
        print(f"\n{'all verdicts as expected' if not wrong else str(wrong) + ' WRONG'}")
        return 1 if wrong else 0
    main(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
