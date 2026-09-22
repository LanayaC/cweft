"""
Docker helpers for the PatchEval backend: one image per CVE, pulled on
demand, run by digest with no network, removed afterwards if we pulled it.

Ported from cweft-dataset analysis/gate6.py (commit ed30652663):
  - sh()              <- gate6.sh(): run a command, bytes out, decode with "replace"
  - exec_in()         <- gate6.dexec(): docker exec ... bash -lc CMD
  - image_present()   <- gate6.run_one(): `docker image inspect` presence check
  - pull_image()      <- gate6.run_one(): `docker pull -q`
  - repo_digest()     <- gate6.run_one(): {{json .RepoDigests}}
  - start_container() <- gate6.run_one(): `docker run -d --name N IMAGE sleep infinity`
  - remove_container(), remove_image() <- gate6.run_one()'s finally block
New here: --network none and --pull never on start, the in-container
timeout, write_file_bytes(), file_sha256() and sweep_containers().

No grading logic lives here.
"""

import hashlib
import json
import os
import shlex
import subprocess
import tempfile
import time
import uuid
from typing import List, NamedTuple, Optional


CONTAINER_PREFIX = "cweft_pe_"
PULL_TIMEOUT = 1800
DEFAULT_EXEC_TIMEOUT = 600


class ExecResult(NamedTuple):
    rc: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool


def sh(args: List[str], timeout: Optional[float] = None) -> ExecResult:
    t0 = time.time()
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout)
        return ExecResult(p.returncode, p.stdout.decode("utf-8", "replace"),
                          p.stderr.decode("utf-8", "replace"),
                          round(time.time() - t0, 1), False)
    except subprocess.TimeoutExpired as e:
        return ExecResult(124, (e.stdout or b"").decode("utf-8", "replace"),
                          "TIMEOUT", round(time.time() - t0, 1), True)


# ── Images ───────────────────────────────────────────────────────────────

def image_present(ref: str) -> bool:
    return sh(["docker", "image", "inspect", ref]).rc == 0


def pull_image(ref: str, timeout: float = PULL_TIMEOUT) -> None:
    r = sh(["docker", "pull", "-q", ref], timeout=timeout)
    if r.rc != 0:
        raise RuntimeError(f"docker pull {ref} failed: {r.stderr[-500:]}")


def repo_digest(ref: str) -> str:
    """The `repo@sha256:...` digest of a local image, for the repo `ref` names."""
    r = sh(["docker", "image", "inspect", ref, "--format", "{{json .RepoDigests}}"])
    if r.rc != 0:
        raise RuntimeError(f"docker image inspect {ref} failed: {r.stderr[-500:]}")
    digests = json.loads(r.stdout) or []
    repo = ref.split("@", 1)[0]
    head, _, last = repo.rpartition("/")
    if ":" in last:  # drop the tag, not a registry port
        repo = f"{head}/{last.split(':', 1)[0]}"
    matching = [d for d in digests if d.split("@", 1)[0] == repo]
    if not matching:
        raise RuntimeError(f"{ref} has no repo digest for {repo}: {digests}")
    return matching[0]


def image_size_bytes(ref: str) -> int:
    r = sh(["docker", "image", "inspect", ref, "--format", "{{.Size}}"])
    if r.rc != 0:
        raise RuntimeError(f"docker image inspect {ref} failed: {r.stderr[-500:]}")
    return int(r.stdout.strip())


def ensure_image(ref: str) -> bool:
    """Pull `ref` unless it is already local. Returns True if we pulled it."""
    if image_present(ref):
        return False
    pull_image(ref)
    return True


def remove_image(ref: str, pulled: bool) -> bool:
    """Remove `ref` only if we pulled it. Returns True if it was removed."""
    if not pulled:
        return False
    return sh(["docker", "rmi", ref]).rc == 0


# ── Containers ───────────────────────────────────────────────────────────

def container_name(*parts: str) -> str:
    return CONTAINER_PREFIX + "_".join(p.lower() for p in parts)


def start_container(name: str, image_ref: str) -> None:
    """Start `image_ref` (ideally a repo@sha256 digest) detached, with no network."""
    if not name.startswith(CONTAINER_PREFIX):
        raise ValueError(f"container name must start with {CONTAINER_PREFIX!r}: {name}")
    sh(["docker", "rm", "-f", name])
    r = sh(["docker", "run", "-d", "--name", name, "--network", "none",
            "--pull", "never", image_ref, "sleep", "infinity"], timeout=300)
    if r.rc != 0:
        raise RuntimeError(f"docker run {image_ref} failed: {r.stderr[-500:]}")


def exec_in(name: str, cmd: str, timeout: float = DEFAULT_EXEC_TIMEOUT) -> ExecResult:
    """
    Run `cmd` with bash -lc inside the container. `timeout` is enforced inside
    the container too, so a hung command does not keep running after we give up.
    """
    inner = f"timeout -k 10 {int(timeout)} bash -lc {shlex.quote(cmd)}"
    r = sh(["docker", "exec", name, "bash", "-c", inner], timeout=timeout + 30)
    if r.rc == 124 and not r.timed_out:
        r = r._replace(timed_out=True)
    return r


def write_file_bytes(name: str, container_path: str, data: bytes) -> str:
    """
    Put `data` at `container_path` byte for byte. docker cp lands it in /tmp,
    then `cat >` overwrites the target in place, so an existing file keeps its
    owner and mode. Returns the sha256, checked against the in-container file.
    """
    fd, host_tmp = tempfile.mkstemp(prefix="cweft_pe_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        staged = f"/tmp/cweft_in_{uuid.uuid4().hex}"
        r = sh(["docker", "cp", host_tmp, f"{name}:{staged}"], timeout=120)
        if r.rc != 0:
            raise RuntimeError(f"docker cp into {name} failed: {r.stderr[-500:]}")
    finally:
        os.remove(host_tmp)
    q_staged, q_target = shlex.quote(staged), shlex.quote(container_path)
    r = exec_in(name, f"cat {q_staged} > {q_target}; rc=$?; rm -f {q_staged}; exit $rc", timeout=120)
    if r.rc != 0:
        raise RuntimeError(f"writing {container_path} in {name} failed: {r.stderr[-500:]}")
    expected = hashlib.sha256(data).hexdigest()
    actual = file_sha256(name, container_path)
    if actual != expected:
        raise RuntimeError(f"{container_path} in {name} has sha256 {actual}, wrote {expected}")
    return actual


def file_sha256(name: str, container_path: str) -> str:
    r = exec_in(name, f"sha256sum -- {shlex.quote(container_path)}", timeout=120)
    if r.rc != 0:
        raise RuntimeError(f"sha256sum {container_path} in {name} failed: {r.stderr[-500:]}")
    return r.stdout.split()[0]


def remove_container(name: str) -> bool:
    return sh(["docker", "rm", "-f", name]).rc == 0


def sweep_containers() -> List[str]:
    """Remove every leftover container named cweft_pe_*. Returns the names removed."""
    r = sh(["docker", "ps", "-a", "--filter", f"name=^{CONTAINER_PREFIX}",
            "--format", "{{.Names}}"])
    names = [n for n in r.stdout.split() if n.startswith(CONTAINER_PREFIX)]
    for n in names:
        remove_container(n)
    return names
