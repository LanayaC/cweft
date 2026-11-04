"""
parallel_grading: rows reach the parent, load-suspect cells are graded again
alone, workers cannot collide on container names, and nothing here needs Docker.
"""

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import parallel_grading as pg  # noqa: E402
import patcheval_docker as pdock  # noqa: E402
import vul4j_baseline as vb  # noqa: E402
import vuln_data  # noqa: E402


def _echo(n):
    return {"n": n, "pid": os.getpid(), "error": ""}


def _times_out_when_not_alone(n, marker):
    # Timed out the first time, fine the second: the row an overloaded machine gives.
    if not Path(marker).exists():
        Path(marker).write_text("seen")
        return {"n": n, "error": "timed out: vul4j test"}
    return {"n": n, "error": ""}


def _always_times_out(n):
    return {"n": n, "error": "timed out: vul4j test"}


def _boom(n):
    raise ValueError("no such cell")


def test_every_row_reaches_the_parent_from_several_processes():
    rows = []
    failed = pg.run_cells(_echo, [(i,) for i in range(6)], 2, rows.append)
    assert failed == [] and sorted(r["n"] for r in rows) == list(range(6))
    assert os.getpid() not in {r["pid"] for r in rows}


def test_a_timeout_under_load_is_not_recorded_and_is_graded_again(tmp_path):
    rows = []
    failed = pg.run_cells(_times_out_when_not_alone, [(1, str(tmp_path / "m"))], 2, rows.append)
    assert failed == [] and rows == [{"n": 1, "error": ""}]


def test_a_timeout_on_its_own_is_the_real_result():
    rows = []
    assert pg.run_cells(_always_times_out, [(1,)], 2, rows.append) == []
    assert rows == [{"n": 1, "error": "timed out: vul4j test"}]


def test_a_cell_that_crashes_gets_no_row_and_is_reported():
    rows = []
    assert pg.run_cells(_boom, [(1,)], 2, rows.append, log=lambda s: None) == [(1,)]
    assert rows == []


@pytest.mark.parametrize("row,oom,why", [
    ({"error": ""}, 0, ""),
    ({"error": "PoV test did not run: x"}, 0, ""),
    ({"error": ""}, 1, pg.OOM),
    ({"error": "timed out: vul4j test"}, 0, pg.TIMEOUT),
    ({"error": "vul-run.sh timed out"}, 0, pg.TIMEOUT),
    ({"error": "candidate test run unusable (timeout): x"}, 0, pg.TIMEOUT),
    ({"error": "timed out"}, 2, pg.OOM),
])
def test_load_suspicion(row, oom, why):
    assert pg.load_suspicion(row, oom) == why


def test_parse_oom_kills():
    assert pg.parse_oom_kills("low 0\nhigh 0\nmax 0\noom 1\noom_kill 3\noom_group_kill 0\n") == 3
    assert pg.parse_oom_kills("low 0\noom_group_kill 2\n") == 0
    assert pg.parse_oom_kills("") == 0


def test_workers_get_different_patcheval_container_names(monkeypatch):
    monkeypatch.setattr(pdock, "container_name", pdock.container_name)
    monkeypatch.setattr(pdock, "remove_container", pdock.remove_container)
    pg._init_worker()
    name = pdock.container_name("eval", "cve_1", "m")
    assert name == f"cweft_pe_eval_cve_1_m_{os.getpid()}"


def test_a_vul4j_cell_gets_its_own_container_and_it_is_always_removed(monkeypatch):
    calls = []

    def sh(args, timeout=None):
        calls.append(args)
        return pdock.ExecResult(0, "oom_kill 2\n", "", 0.1, False)

    monkeypatch.setattr(pdock, "sh", sh)
    monkeypatch.setattr(pdock, "image_present", lambda ref: True)
    monkeypatch.setattr(vb, "CONTAINER_NAME", vb.CONTAINER_NAME)
    monkeypatch.setattr(vuln_data, "CONTAINER_NAME", vuln_data.CONTAINER_NAME)
    monkeypatch.setattr(pg, "_oom_kills_seen", 0)
    with pytest.raises(RuntimeError):
        with pg.vul4j_container() as name:
            assert vb.CONTAINER_NAME == vuln_data.CONTAINER_NAME == name
            raise RuntimeError("the cell blew up")
    # A cell's container is isolated like the baseline's; test_vul4j_isolation
    # covers that rule, this covers that a worker's container obeys it too.
    run = next(c for c in calls if c[:2] == ["docker", "run"])
    assert run[run.index("--network") + 1] == "none"
    assert calls[-1] == ["docker", "rm", "-f", name]
    assert pg._oom_kills_seen == 2


def test_a_grader_image_built_on_another_image_is_refused(monkeypatch):
    monkeypatch.setattr(pdock, "image_present", lambda ref: True)
    monkeypatch.setattr(pdock, "sh",
                        lambda args, timeout=None: pdock.ExecResult(0, "sha256:other\n", "", 0.1, False))
    with pytest.raises(RuntimeError, match="sha256:other"):
        pg.ensure_grader_image("sha256:baselined")
    assert pg.ensure_grader_image("sha256:other") == pg.GRADER_IMAGE
