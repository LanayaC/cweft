"""
vul4j_baseline.docker_run: a timeout must stop the whole process tree inside
the container, not just the `docker exec` client on this side.

That is what went wrong on the first baseline run: VUL4J-24's compile hit its
limit, the client was killed, and Maven carried on inside the container for
another 43 minutes. These tests run real commands in the vul4j-alldeps
container and check nothing is left behind; they skip when it is not running.
"""

import subprocess
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import vul4j_baseline as vb  # noqa: E402
from config import CONTAINER_NAME  # noqa: E402


def _container_up() -> bool:
    try:
        out = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
                             capture_output=True, text=True, timeout=20)
    except Exception:
        return False
    return out.stdout.strip() == "true"


pytestmark = pytest.mark.skipif(not _container_up(), reason=f"{CONTAINER_NAME} not running")


def _count(pattern: str) -> int:
    out = vb.docker_run(["sh", "-c", f"ps -eo args | grep -c '^{pattern}' || true"], 30)
    return int(out.stdout.strip() or 0)


def test_a_timeout_kills_the_children_too():
    start = time.time()
    with pytest.raises(subprocess.TimeoutExpired):
        vb.docker_run(["sh", "-c", "sleep 317 & sleep 317 & wait"], 3)
    assert time.time() - start < 20
    assert _count("sleep 317") == 0


def test_a_child_that_ignores_term_is_killed_after_the_grace(monkeypatch):
    monkeypatch.setattr(vb, "KILL_GRACE", 2)
    start = time.time()
    with pytest.raises(subprocess.TimeoutExpired):
        vb.docker_run(["sh", "-c", "trap '' TERM; sleep 318 & wait"], 3)
    assert time.time() - start < 25
    assert _count("sleep 318") == 0


def test_a_normal_command_returns_its_exit_code_and_output():
    res = vb.docker_run(["sh", "-c", "echo hi; exit 3"], 30)
    assert res.returncode == 3 and res.stdout.strip() == "hi"


def test_input_reaches_the_command_unchanged():
    res = vb.docker_run(["cat"], 30, input_text="a\nb\n")
    assert res.stdout == "a\nb\n"


def test_make_offline_writes_o_once_for_maven_and_leaves_gradle_alone():
    root = "/tmp/cweft_test_offline"
    try:
        vb.docker_run(["sh", "-c", f"rm -rf {root}; mkdir -p {root}/mvn {root}/gradle; "
                                   f"touch {root}/mvn/pom.xml {root}/gradle/build.gradle"], 30)
        assert vb.make_offline(f"{root}/mvn") is True
        assert vb.make_offline(f"{root}/mvn") is True
        conf = vb.docker_run(["cat", f"{root}/mvn/.mvn/maven.config"], 30).stdout
        assert conf.split() == ["-o"]
        assert vb.make_offline(f"{root}/gradle") is False
        assert vb.docker_run(["test", "-e", f"{root}/gradle/.mvn"], 30).returncode != 0
    finally:
        vb.docker_run(["rm", "-rf", root], 30)
