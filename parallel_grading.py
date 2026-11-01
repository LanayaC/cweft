"""
Grade several cells at once (evaluate.py --workers N). No grading logic lives
here: each worker process runs the same code as sequential grading, one cell
at a time, in a container of its own that is thrown away afterwards.

  Vul4J       The Maven and Gradle caches live in the vul4j-alldeps container,
              not in its image, so that container is committed once to
              GRADER_IMAGE and each cell gets a new container from it, with the
              same (bridge) network as vul4j-alldeps. Delete the image with
              `docker rmi` after changing the caches, and the next run commits
              a new one.
  PatchEval   Already one container per cell, but its name leaves out the
              prompt level, so two levels of a CVE would collide. Each worker
              adds its process id to the names.

Only the parent process writes the CSV, one row as each cell finishes, so an
interrupted run resumes as usual. Rows land in the order cells finish, not the
sequential order.

Load must not change a verdict, so a cell whose result could be an effect of
it is not recorded the first time. A cell that hit a timeout, or had a process
killed for lack of memory, is graded again on its own after the others. If it
still runs out of memory alone, it is left out of the CSV and reported, and the
next run tries it again.

One parallel run at a time: each run starts by removing containers an
interrupted one left behind.
"""

import json
import multiprocessing
import os
import subprocess
import uuid
from concurrent.futures import ProcessPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from config import CONTAINER_NAME
import patcheval_docker as pdock
import patcheval_eval as pe
import vul4j_baseline as vb
import vuln_data

GRADER_IMAGE = "cweft/vul4j-grader:latest"
BASE_IMAGE_LABEL = "cweft.base_image"
VUL4J_PREFIX = "cweft_v4_"
COMMIT_TIMEOUT = 3600

OOM, TIMEOUT = "out of memory", "timeout"

_oom_kills_seen = 0       # in this worker, during the cell in flight


# ── Containers ───────────────────────────────────────────────────────────

def ensure_grader_image(baselined_image: str) -> str:
    """
    GRADER_IMAGE, committed from vul4j-alldeps if it is not there yet. Refuses
    an image built on anything other than the image the baseline recorded.
    """
    def label() -> str:
        r = pdock.sh(["docker", "image", "inspect", GRADER_IMAGE, "--format",
                      "{{index .Config.Labels \"" + BASE_IMAGE_LABEL + "\"}}"])
        return r.stdout.strip() if r.rc == 0 else ""

    if not pdock.image_present(GRADER_IMAGE):
        base = pdock.sh(["docker", "inspect", "-f", "{{.Image}}", CONTAINER_NAME]).stdout.strip()
        print(f"Committing {CONTAINER_NAME} to {GRADER_IMAGE} (once; this takes a few minutes)",
              flush=True)
        r = pdock.sh(["docker", "commit", "--change", f"LABEL {BASE_IMAGE_LABEL}={base}",
                      CONTAINER_NAME, GRADER_IMAGE], timeout=COMMIT_TIMEOUT)
        if r.rc != 0:
            raise RuntimeError(f"docker commit failed: {r.stderr[-500:]}")
    if label() != baselined_image:
        raise RuntimeError(f"{GRADER_IMAGE} is built on {label() or 'an unknown image'}, but "
                           f"data/vul4j/baseline.json recorded {baselined_image}")
    return GRADER_IMAGE


def sweep_vul4j_containers() -> List[str]:
    """Remove leftover per-cell Vul4J containers. Returns the names removed."""
    r = pdock.sh(["docker", "ps", "-a", "--filter", f"name=^{VUL4J_PREFIX}",
                  "--format", "{{.Names}}"])
    names = [n for n in r.stdout.split() if n.startswith(VUL4J_PREFIX)]
    for n in names:
        pdock.sh(["docker", "rm", "-f", n])
    return names


def parse_oom_kills(memory_events: str) -> int:
    """oom_kill from a cgroup memory.events file; it counts system-wide OOM kills too."""
    for line in memory_events.splitlines():
        key, _, value = line.partition(" ")
        if key == "oom_kill" and value.strip().isdigit():
            return int(value)
    return 0


def _oom_kills(name: str) -> int:
    r = pdock.sh(["docker", "exec", name, "cat", "/sys/fs/cgroup/memory.events"], timeout=60)
    return parse_oom_kills(r.stdout) if r.rc == 0 else 0


@contextmanager
def vul4j_container() -> Iterator[str]:
    """
    A new container for one Vul4J cell. vul4j_baseline and vuln_data read
    CONTAINER_NAME on every call, so in this worker process they now talk to it.
    """
    global _oom_kills_seen
    name = f"{VUL4J_PREFIX}{os.getpid()}_{uuid.uuid4().hex[:8]}"
    r = pdock.sh(["docker", "run", "-d", "--name", name, "--pull", "never", GRADER_IMAGE,
                  "tail", "-f", "/dev/null"], timeout=300)
    if r.rc != 0:
        raise RuntimeError(f"docker run {GRADER_IMAGE} failed: {r.stderr[-500:]}")
    vb.CONTAINER_NAME = vuln_data.CONTAINER_NAME = name
    try:
        yield name
    finally:
        _oom_kills_seen += _oom_kills(name)
        pdock.sh(["docker", "rm", "-f", name])


def _init_worker() -> None:
    """Give this worker's PatchEval containers names no other worker uses, and
    read each one's OOM count before it is removed."""
    make_name, remove = pdock.container_name, pdock.remove_container
    pid = str(os.getpid())

    def named(*parts: str) -> str:
        return make_name(*parts, pid)

    def counted_remove(name: str) -> bool:
        global _oom_kills_seen
        _oom_kills_seen += _oom_kills(name)
        return remove(name)

    pdock.container_name, pdock.remove_container = named, counted_remove


# ── The pool ─────────────────────────────────────────────────────────────

def load_suspicion(row: Dict, oom_kills: int) -> str:
    """Why this row may be an effect of machine load, or "" when it cannot be."""
    if oom_kills:
        return OOM
    error = str(row.get("error") or "").lower()
    return TIMEOUT if "timed out" in error or "timeout" in error else ""


def _cell(fn: Callable, cell: Tuple, own_vul4j_container: bool) -> Tuple[Dict, str]:
    """In a worker: grade one cell. Returns (row, load suspicion)."""
    global _oom_kills_seen
    _oom_kills_seen = 0
    if own_vul4j_container:
        with vul4j_container():
            row = fn(*cell)
    else:
        row = fn(*cell)
    return row, load_suspicion(row, _oom_kills_seen)


def run_cells(fn: Callable, cells: List[Tuple], workers: int,
              on_row: Callable[[Dict], None], own_vul4j_container: bool = False,
              log: Callable[[str], None] = print) -> List[Tuple]:
    """
    Call fn(*cell) for every cell across `workers` processes, passing each
    finished row to on_row in this process. `fn` must be a module-level function.
    Returns the cells that produced no row, which the next run will try again.
    """
    failed: List[Tuple] = []
    todo, width = list(cells), workers
    context = multiprocessing.get_context("spawn")
    while todo:
        retry: List[Tuple] = []
        with ProcessPoolExecutor(max_workers=width, mp_context=context,
                                 initializer=_init_worker) as pool:
            futures = {pool.submit(_cell, fn, c, own_vul4j_container): c for c in todo}
            for fut in as_completed(futures):
                cell = futures[fut]
                try:
                    row, suspicion = fut.result()
                except Exception as e:
                    log(f"  NOT RECORDED {cell}: {type(e).__name__}: {e}")
                    failed.append(cell)
                    continue
                if suspicion and width > 1:
                    log(f"  {cell}: {suspicion} under load; will grade it again on its own")
                    retry.append(cell)
                elif suspicion == OOM:
                    log(f"  NOT RECORDED {cell}: out of memory even on its own")
                    failed.append(cell)
                else:
                    on_row(row)
        todo, width = retry, 1
    return failed


# ── PatchEval cells ──────────────────────────────────────────────────────

def _patcheval_log_cell(path: str) -> Dict:
    """The body of patcheval_eval.main's loop, for one log."""
    cve, level, model_key = Path(path).stem.split("__")
    log = json.loads(Path(path).read_text(encoding="utf-8"))
    row = pe.score_candidate(cve, (log.get("response") or "").encode("utf-8"),
                             level, model_key, log.get("model_id", ""))
    row["truncated"] = bool(log.get("truncated"))
    row["stop_reason"] = log.get("stop_reason", "")
    return row


def patcheval_logs(args, workers: int) -> int:
    """evaluate.py --dataset patcheval --workers N. Returns the cells left without a row."""
    cells = pe._log_cells(args)
    already = pe.done_cells()
    todo = [(str(p),) for p in cells if tuple(p.stem.split("__")) not in already]
    print(f"{len(todo)} PatchEval cells to grade, {workers} workers", flush=True)
    pdock.sweep_containers()
    counts: Dict[str, int] = {}

    def on_row(row: Dict) -> None:
        pe.append_row(row)
        counts[row["trust_level"]] = counts.get(row["trust_level"], 0) + 1
        print(f"[{sum(counts.values())}/{len(todo)}] {row['cve']:18s} {row['level']:5s} "
              f"{row['model_key']:10s} {row['trust_level']:8s} {str(row['error'])[:60]}", flush=True)

    failed = run_cells(_patcheval_log_cell, todo, workers, on_row)
    print(f"\n{counts}  ->  {pe.RESULTS_CSV}", flush=True)
    return len(failed)


def _patcheval_oracle_cell(cve: str, model_key: str, model_id: str, expected: str,
                           expect_regression: Optional[str]) -> Dict:
    """One synthetic candidate of patcheval_eval.oracle, with its verdict checked."""
    entry = pe.load_baseline().get(cve)
    try:
        if model_key == pe.ORACLE_VULNERABLE:
            candidate = pe.pb.frozen_bytes(cve, pe.pb.manifest()[cve])
        else:
            candidate = pe.reference_fixed_bytes(cve, entry)
            if model_key == pe.ORACLE_REGRESSION:
                candidate = pe.apply_break(candidate, pe.load_break(cve))
        row = pe.score_candidate(cve, candidate, pe.ORACLE_LEVEL, model_key, model_id, entry=entry)
    except Exception as e:                   # keep the oracle going
        row = pe._row(cve, entry, pe.ORACLE_LEVEL, model_key, model_id,
                      trust_level=pe.REFUSED, error=f"{type(e).__name__}: {e}")
    return row


def patcheval_oracle_cells(cves: List[str]) -> Tuple[List[Tuple], int]:
    """patcheval_eval.oracle's plans, as cells; and how many CVEs it would refuse."""
    entries = pe.load_baseline()
    already = pe.done_cells()
    cells, refused = [], 0
    for cve in cves:
        why = pe.refusal(entries.get(cve))
        if why:
            print(f"{cve:18s} refused: {why}", flush=True)
            refused += 1
            continue
        plans = [(pe.ORACLE_REFERENCE, "reference fix (fix.patch applied)", pe.L3, None),
                 (pe.ORACLE_VULNERABLE, "unpatched vulnerable file (frozen copy)", pe.L1, None)]
        recipe = pe.load_break(cve)
        if recipe:
            plans.append((pe.ORACLE_REGRESSION, recipe["model_id"],
                          recipe["expected_trust_level"], recipe["expected_regression"]))
        cells += [(cve, *p) for p in plans if (cve, pe.ORACLE_LEVEL, p[0]) not in already]
    return cells, refused


def patcheval_oracle(cves: List[str], workers: int) -> int:
    """patcheval_eval.oracle across workers. Returns how many verdicts came out wrong."""
    cells, wrong = patcheval_oracle_cells(cves)
    expected = {(c[0], c[1]): (c[3], c[4]) for c in cells}
    pdock.sweep_containers()
    bad = [wrong]

    def on_row(row: Dict) -> None:
        pe.append_row(row)
        want, regression = expected[(row["cve"], row["model_key"])]
        named_right = regression is None or row["regressions"] == regression
        ok = row["trust_level"] == want and named_right
        bad[0] += 0 if ok else 1
        print(f"{row['cve']:18s} {row['model_key']:18s} expected {want:3s} got "
              f"{row['trust_level']:8s} {'OK' if ok else 'WRONG'}  "
              f"judged={row['judged_set_size']} nreg={row['n_regressions']} "
              f"{str(row['regressions'])[:58]} {str(row['error'])[:50]}", flush=True)

    failed = run_cells(_patcheval_oracle_cell, cells, workers, on_row)
    return bad[0] + len(failed)
