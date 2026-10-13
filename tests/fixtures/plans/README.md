# Test-plan fixtures

Real output from real runners, captured for `tests/test_patcheval_fixes.py`.
These are not test *reports* (those live in `../testparse/`): they are what a
runner said when it refused to run at all, which is how the plan builder
decides which flags an image's runner understands.

| Fixture | Where it came from |
|---|---|
| `mocha_reporter_option_rejected.txt` | Verbatim `stderr` recorded for `CVE-2018-16482` in `data/patcheval/baseline.json` during the clean pass of 2026-10-13. The same line was recorded for CVE-2020-7674, CVE-2020-7675 and CVE-2021-23384. |

`--reporter-option` arrived in mocha 6. Older mocha does not ignore the flag,
it rejects the whole invocation, so the suite never runs and nothing is
written to the report file: the run looks like an unreadable report rather
than a refused command. That is why the plan builder asks mocha its version
first, and why `run_tests` retries without the flag if mocha rejects it anyway.
