# Test-output fixtures

Real output from real runners, captured for `tests/test_patcheval_testparse.py`.
Nothing here is hand-written. Local paths were replaced with `/fixtures` and the
JUnit `hostname` attribute with `fixture-host`; the files are otherwise verbatim.

Each format has four cases: a normal run (one pass, one failure, one skip), a
run that collected nothing, an import or build failure, and a truncated file
(the normal one cut mid-way).

| Format | Runner | Where it ran |
|---|---|---|
| `junit_pytest_*.xml` | pytest 9.0.3, `--junitxml` | this machine, Python 3.13 |
| `tap_node_*.tap` | `node --test --test-reporter=tap`, Node v22.2.0 | this machine |
| `go_json_*.jsonl` | `go test -json`, go1.24.1 | PatchEval image `cve-2023-24623` |
| `mocha_json_*.json` | `mocha --reporter json`, Node v22.14.0 | PatchEval image `cve-2022-29822` |
| `jest_json_*.json` | `jest --json`, Node v22.14.0 | PatchEval image `cve-2021-23376` |
| `unittest_text_*.txt` | `python -m unittest -v`, Python 3.13.1 | this machine |

Two quirks these fixtures exist to pin down:

- `node --test` reports a file that defines no tests as one **passing** test
  named after the file. Counted naively, an empty run looks like a green one.
- A mocha file that fails to load prints no JSON at all: the error goes to
  stderr and the process dies, so the reader has to recognise it from the text.

`mocha_json_load_error.json` therefore holds stdout and stderr combined, which
is what the evaluator captures. The others hold stdout only.

`unittest_text_*.txt` hold stderr, where unittest writes its report; the
evaluator captures both streams for that format. unittest also turns a module
that will not import into one erroring test named `_FailedTest`, so an import
failure otherwise looks like a run with a single error rather than nothing at all.

## Added after the clean pass of 2026-10-13

`go_json_partial_build_error.jsonl` is the one file here that is assembled
rather than captured whole, because no complete capture of that run was kept.
Its `build-output` and `build-fail` events carry the compiler error recorded
verbatim for `CVE-2024-24579` in `data/patcheval/baseline.json`; the test
events after them are the ones from `go_json_normal.jsonl`. Together they
reproduce what that CVE hit: one package whose test binary will not build
while other packages run to completion. That must leave the passing results
usable and name the dropped package, rather than discard the whole run.

See also `../plans/`, which holds what a runner says when it refuses to run at
all, and which the plan builder reads to decide a runner's flags.
