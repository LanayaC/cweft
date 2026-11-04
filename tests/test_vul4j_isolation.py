"""
Vul4J containers are network-isolated, and a Vul4J row says which code graded it.

A test that reaches the network can pass all three reference runs, enter the
judged set, and then fail during grading for a reason that has nothing to do
with the patch - that is how a parallel run turned an L3 into an L2. So every
Vul4J container now runs with --network none, the baseline's and grading's
alike, and the fingerprint in each row says which code the verdict came from.

Offline: Docker is never called, only the argv that would have been.
"""

import csv
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import evaluate  # noqa: E402
import patcheval_docker as pdock  # noqa: E402
import vul4j_baseline as vb  # noqa: E402
import vuln_data  # noqa: E402


@pytest.fixture
def docker(monkeypatch):
    """Record every docker argv and answer as a healthy daemon would."""
    calls = []

    def sh(args, timeout=None):
        calls.append(list(args))
        return pdock.ExecResult(0, "oom_kill 0\n", "", 0.1, False)

    monkeypatch.setattr(pdock, "sh", sh)
    monkeypatch.setattr(pdock, "image_present", lambda ref: True)
    monkeypatch.setattr(vb, "CONTAINER_NAME", vb.CONTAINER_NAME)
    monkeypatch.setattr(vuln_data, "CONTAINER_NAME", vuln_data.CONTAINER_NAME)
    return calls


def _run_argv(calls):
    return next(c for c in calls if c[:2] == ["docker", "run"])


# ── the container ────────────────────────────────────────────────────────

def test_a_container_runs_with_no_network(docker):
    with vb.container():
        pass
    argv = _run_argv(docker)
    assert "--network" in argv
    assert argv[argv.index("--network") + 1] == "none"


def test_no_container_is_put_on_a_network_by_another_name(docker):
    # The negative control for the test above: not just "a --network flag is
    # there", but that nothing puts this container on a reachable network.
    with vb.container():
        pass
    argv = _run_argv(docker)
    for reachable in ("host", "bridge", "default"):
        assert reachable not in argv
    assert "--net" not in argv              # the old spelling, which --network does not cover


def test_a_container_can_resolve_its_own_name_on_loopback(docker):
    # With --network none Docker writes no /etc/hosts line for the container's
    # own name, InetAddress.getLocalHost() throws, and everything that serves
    # from inside the container dies on startup - which cost VUL4J-66 88% of
    # its judged set and VUL4J-45 its place in the subset.
    with vb.container() as name:
        pass
    argv = _run_argv(docker)
    assert argv[argv.index("--hostname") + 1] == name
    assert argv[argv.index("--add-host") + 1] == f"{name}:127.0.0.1"


def test_the_only_address_a_container_is_given_is_loopback(docker):
    # The negative control for the mapping above: giving the name back must not
    # give an address anything can be reached on.
    with vb.container():
        pass
    argv = _run_argv(docker)
    host, _, addr = argv[argv.index("--add-host") + 1].partition(":")
    assert addr == vb.LOOPBACK == "127.0.0.1"
    assert argv[argv.index("--network") + 1] == "none"


def test_the_commands_in_the_block_go_to_the_new_container(docker):
    with vb.container() as name:
        assert name.startswith(vb.VUL4J_PREFIX)
        assert vb.CONTAINER_NAME == vuln_data.CONTAINER_NAME == name
        assert name != vb.SOURCE_CONTAINER


def test_vul4j_alldeps_is_the_container_again_afterwards(docker):
    with vb.container():
        pass
    assert vb.CONTAINER_NAME == vuln_data.CONTAINER_NAME == vb.SOURCE_CONTAINER


def test_the_container_is_removed_even_when_the_block_raises(docker):
    with pytest.raises(RuntimeError, match="the entry blew up"):
        with vb.container() as name:
            raise RuntimeError("the entry blew up")
    assert docker[-1] == ["docker", "rm", "-f", name]


def test_vul4j_alldeps_is_never_removed_or_reconfigured(docker):
    with vb.container():
        pass
    for argv in docker:
        if argv[:3] == ["docker", "rm", "-f"] or argv[:2] in (["docker", "update"],
                                                              ["docker", "network"]):
            assert vb.SOURCE_CONTAINER not in argv


def test_what_must_be_read_out_is_read_before_the_container_goes(docker):
    seen = []

    def before_remove(name):
        seen.append([c for c in docker if c[:3] == ["docker", "rm", "-f"]])

    with vb.container(before_remove=before_remove):
        pass
    assert seen == [[]]                     # nothing had been removed yet


def test_a_container_that_will_not_start_is_not_silently_ignored(monkeypatch):
    monkeypatch.setattr(pdock, "image_present", lambda ref: True)
    monkeypatch.setattr(pdock, "sh",
                        lambda args, timeout=None: pdock.ExecResult(1, "", "no such image", 0.1, False))
    with pytest.raises(RuntimeError, match="no such image"):
        with vb.container():
            pass


# ── the image the containers come from ───────────────────────────────────

def test_the_baseline_may_build_the_image_it_is_about_to_record(monkeypatch):
    # The baseline cannot be asked to match the image the baseline records.
    monkeypatch.setattr(pdock, "image_present", lambda ref: True)
    monkeypatch.setattr(pdock, "sh",
                        lambda args, timeout=None: pdock.ExecResult(0, "sha256:whatever\n", "", 0.1, False))
    assert vb.ensure_grader_image() == vb.GRADER_IMAGE


def test_grading_still_refuses_an_image_built_on_another_one(monkeypatch):
    monkeypatch.setattr(pdock, "image_present", lambda ref: True)
    monkeypatch.setattr(pdock, "sh",
                        lambda args, timeout=None: pdock.ExecResult(0, "sha256:other\n", "", 0.1, False))
    with pytest.raises(RuntimeError, match="sha256:other"):
        vb.ensure_grader_image("sha256:baselined")


# ── the fingerprint in a row ─────────────────────────────────────────────

GRADED = {"trust": "L3", "compiled": True, "pov_passed": True, "regressions": [],
          "flaky": [], "tests_run": 151, "error": ""}


def test_a_row_says_which_code_graded_it():
    row = evaluate._row({"vul_id": "VUL4J-77", "level": "L1", "model_key": "m"},
                        GRADED, {"judged_count": 150}, "2026-01-01T00:00:00+00:00")
    assert row["code_fingerprint"] == vb.code_fingerprint()
    assert len(row["code_fingerprint"]) == 12
    assert set(row) == set(evaluate.CSV_FIELDS)


def test_the_fingerprint_is_the_one_the_baseline_records():
    # A row and a baseline entry are only comparable when both came from the
    # same code, so they must not be fingerprinted by different rules.
    assert "vul4j_baseline.py" in vb.FINGERPRINTED
    assert "vul4j_grading.py" in vb.FINGERPRINTED
    assert evaluate.CSV_FIELDS.index("code_fingerprint") == len(evaluate.CSV_FIELDS) - 2


# ── an entry that leaves the subset says why ─────────────────────────────

TIKA_LOG = (
    "[INFO] Building Apache Tika parsers\n"
    "[ERROR] Failed to execute goal org.codehaus.gmaven:groovy-maven-plugin:2.0:execute "
    "(testSetup) on project tika-parsers: Execution testSetup failed: "
    "java.net.UnknownHostException: opennlp.sourceforge.net -> [Help 1]\n"
    "[ERROR] Re-run Maven using the -X switch to enable full debug logging.\n")


def test_a_failed_compile_records_the_line_that_says_why(monkeypatch):
    # VUL4J-36 spent an afternoon being diagnosed by hand because the file said
    # only 'compile_failed_original'. The cause is in the log the build wrote.
    monkeypatch.setattr(vb, "_exec",
                        lambda *a, **k: SimpleNamespace(stdout=TIKA_LOG, returncode=1))
    why = vb.compile_failure_reason("/tmp/cweft/VUL4J-36")
    assert "opennlp.sourceforge.net" in why
    assert why.startswith("[ERROR] Failed to execute goal")
    assert len(why) <= 400


def test_a_compile_log_with_nothing_to_say_gives_an_empty_reason(monkeypatch):
    monkeypatch.setattr(vb, "_exec",
                        lambda *a, **k: SimpleNamespace(stdout="[INFO] all good\n", returncode=0))
    assert vb.compile_failure_reason("/tmp/x") == ""


# ── not corrupting a file written by older code ──────────────────────────

OLD_ORACLE_HEADER = [c for c in evaluate.ORACLE_FIELDS if c != "code_fingerprint"]


def _write_oracle(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def test_an_oracle_csv_from_older_code_is_refused_not_appended_to(tmp_path):
    path = tmp_path / evaluate.ORACLE_CSV_NAME
    _write_oracle(path, OLD_ORACLE_HEADER, [{"vul_id": "VUL4J-77", "model_key": "oracle_reference"}])
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="older header"):
        evaluate.oracle(["VUL4J-77"], tmp_path)
    assert path.read_bytes() == before       # left exactly as it was


def test_todays_oracle_csv_is_accepted(tmp_path):
    # The positive control: same call, current header. Every cell is already
    # there, so it needs no Docker and must reach the summary.
    path = tmp_path / evaluate.ORACLE_CSV_NAME
    rows = [{"vul_id": "VUL4J-77", "model_key": k, "expected": e, "trust_level": e,
             "as_expected": "True", "regressions": "", "error": ""}
            for k, e in [(evaluate.ORACLE_VULNERABLE, "L1"), (evaluate.ORACLE_REFERENCE, "L3")]]
    _write_oracle(path, evaluate.ORACLE_FIELDS, rows)
    assert evaluate.oracle(["VUL4J-77"], tmp_path) == 0
    assert (tmp_path / "oracle_summary.txt").exists()
