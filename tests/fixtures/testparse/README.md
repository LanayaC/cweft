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

Two quirks these fixtures exist to pin down:

- `node --test` reports a file that defines no tests as one **passing** test
  named after the file. Counted naively, an empty run looks like a green one.
- A mocha file that fails to load prints no JSON at all: the error goes to
  stderr and the process dies, so the reader has to recognise it from the text.

`mocha_json_load_error.json` therefore holds stdout and stderr combined, which
is what the evaluator captures. The others hold stdout only.
