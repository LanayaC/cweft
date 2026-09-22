"""
L0 checks for the PatchEval backend: does the file parse? One check per
language, run inside the bug's container with the image's own toolchain.

  .py              ast.parse, with the repo's interpreter named in fix-run.sh
                   (e.g. /workspace/PoC_env/<CVE>/bin/python; some are
                   Python 2), never the image's default python
  .js .mjs .cjs    node --check
  .ts .tsx .mts    deno fmt on stdin: Deno's parser, syntax only, offline.
                   `node --experimental-strip-types --check` was rejected:
                   it exits 0 on a deliberately broken .ts file.
  .go              gofmt -e decides L0 (syntax only, the same bar as the
                   others). go_build() also builds the file's package
                   offline, recorded separately; it does not decide L0.

The file's extension picks the check, not PatchEval's language label (its
one .ts entry is labelled JavaScript).

A check whose tool or interpreter is missing raises L0SetupError instead of
reporting a failed parse, so a broken image can't be scored as an L0 patch.
"""

import re
import shlex
from posixpath import dirname, splitext
from typing import NamedTuple

from patcheval_docker import exec_in


FIX_RUN = "/workspace/fix-run.sh"
CHECK_TIMEOUT = 120
GO_BUILD_TIMEOUT = 600
ERROR_TAIL_CHARS = 600

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_PY_INTERPRETER = re.compile(r"(/\S*/bin/python[0-9.]*)(?=\s|$)")

# go build errors that mean "needed the network", not "the code is wrong"
_GO_OFFLINE_MARKERS = (
    "GOPROXY=off", "module lookup disabled", "dial tcp", "no such host",
    "cannot find module providing package", "missing go.sum entry",
)


class L0SetupError(RuntimeError):
    """The checker itself could not run (missing tool or interpreter)."""


class L0Result(NamedTuple):
    passed: bool
    checker: str       # what ran, e.g. "ast.parse (/workspace/PoC_env/X/bin/python)"
    version: str       # tool version, e.g. "2.7.18", "v22.14.0", "go1.24.1"
    error_tail: str    # last ERROR_TAIL_CHARS of the checker's output; "" on pass


class GoBuildResult(NamedTuple):
    passed: bool
    offline_blocked: bool  # failed because it needed the network
    command: str
    version: str
    error_tail: str


def _tail(text: str) -> str:
    return _ANSI.sub("", text).strip()[-ERROR_TAIL_CHARS:]


def _run(name: str, cmd: str, timeout: float = CHECK_TIMEOUT):
    r = exec_in(name, cmd, timeout=timeout)
    if r.timed_out:
        raise L0SetupError(f"timed out after {timeout}s: {cmd}")
    return r


def _require_tool(name: str, tool: str) -> None:
    if _run(name, f"command -v {shlex.quote(tool)}").rc != 0:
        raise L0SetupError(f"{tool} not found in container {name}")


def _result(r, checker: str, version: str) -> L0Result:
    passed = r.rc == 0
    return L0Result(passed, checker, version, "" if passed else _tail(r.stdout + r.stderr))


# ── Python ───────────────────────────────────────────────────────────────

def python_interpreter(name: str) -> str:
    """The interpreter fix-run.sh runs the PoC with."""
    r = _run(name, f"cat {FIX_RUN}")
    if r.rc != 0:
        raise L0SetupError(f"cannot read {FIX_RUN}: {r.stderr.strip()}")
    found = _PY_INTERPRETER.findall(r.stdout)
    if not found:
        raise L0SetupError(f"{FIX_RUN} names no .../bin/python interpreter")
    py = found[-1]
    if _run(name, f"test -x {shlex.quote(py)}").rc != 0:
        raise L0SetupError(f"interpreter {py} from {FIX_RUN} is not executable")
    return py


def check_python(name: str, path: str) -> L0Result:
    py = python_interpreter(name)
    qpy = shlex.quote(py)
    # Written to run under Python 2 and 3 alike.
    version = _run(name, f"{qpy} -c \"import sys; print('%d.%d.%d' % sys.version_info[:3])\"").stdout.strip()
    code = "import ast,sys; ast.parse(open(sys.argv[1],'rb').read(), sys.argv[1])"
    r = _run(name, f"{qpy} -c {shlex.quote(code)} {shlex.quote(path)}")
    return _result(r, f"ast.parse ({py})", version)


# ── JavaScript / TypeScript ──────────────────────────────────────────────

def check_javascript(name: str, path: str) -> L0Result:
    _require_tool(name, "node")
    version = _run(name, "node --version").stdout.strip()
    r = _run(name, f"node --check {shlex.quote(path)}")
    return _result(r, "node --check", version)


def check_typescript(name: str, path: str) -> L0Result:
    _require_tool(name, "deno")
    version = _run(name, "deno --version").stdout.split("\n", 1)[0].strip()
    ext = splitext(path)[1].lstrip(".")
    # Formatting from stdin only parses and prints, so style differences
    # never fail it; a syntax error does. Output is discarded.
    r = _run(name, f"cd {shlex.quote(dirname(path))} && NO_COLOR=1 "
                   f"deno fmt --ext={ext} - < {shlex.quote(path)} > /dev/null")
    return _result(r, f"deno fmt --ext={ext} (stdin, syntax only)", version)


# ── Go ───────────────────────────────────────────────────────────────────

def _go_version(name: str) -> str:
    _require_tool(name, "go")
    return _run(name, "go version").stdout.strip().split(" ")[2]


def check_go(name: str, path: str) -> L0Result:
    _require_tool(name, "gofmt")
    version = _go_version(name)
    r = _run(name, f"gofmt -e -l {shlex.quote(path)} > /dev/null")
    return _result(r, "gofmt -e", version)


def go_build(name: str, repo_dir: str, rel_path: str) -> GoBuildResult:
    """
    Build the package holding `rel_path`, offline (GOPROXY=off; the container
    has no network anyway). Recorded alongside L0, never deciding it.
    """
    version = _go_version(name)
    pkg = "./" + (dirname(rel_path) or ".")
    cmd = f"GOPROXY=off go build -o /dev/null {shlex.quote(pkg)}"
    r = _run(name, f"cd {shlex.quote(repo_dir)} && {cmd}", timeout=GO_BUILD_TIMEOUT)
    out = r.stdout + r.stderr
    passed = r.rc == 0
    blocked = not passed and any(m in out for m in _GO_OFFLINE_MARKERS)
    return GoBuildResult(passed, blocked, cmd, version, "" if passed else _tail(out))


# ── Dispatch ─────────────────────────────────────────────────────────────

_CHECKS = {
    ".py": check_python,
    ".js": check_javascript, ".mjs": check_javascript, ".cjs": check_javascript,
    ".ts": check_typescript, ".tsx": check_typescript,
    ".mts": check_typescript, ".cts": check_typescript,
    ".go": check_go,
}


def check_l0(name: str, repo_dir: str, rel_path: str) -> L0Result:
    """Run the L0 check for `repo_dir/rel_path`, chosen by file extension."""
    ext = splitext(rel_path)[1]
    if ext not in _CHECKS:
        raise L0SetupError(f"no L0 check for {ext!r} files ({rel_path})")
    return _CHECKS[ext](name, f"{repo_dir}/{rel_path}")
