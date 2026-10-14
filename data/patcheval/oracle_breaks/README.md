# Oracle breaks

One file per CVE, read by `patcheval_eval.py --oracle`.

The oracle scores synthetic models whose verdict is forced in advance, so a
wrong verdict is a bug in the scoring loop rather than a judgement call. Two
of them need no data: the reference-fixed file must come out **L3**, and the
untouched vulnerable file must come out **L1**.

**L2** cannot be reached that way. It needs a candidate that closes the hole
*and* breaks a test in the judged set, which neither of those two does. A file
here describes how to build one, as a single literal replacement applied to the
reference-fixed file:

| Field | Meaning |
|---|---|
| `cve` | the CVE it applies to |
| `model_id` | recorded in the row, so the candidate can be identified later |
| `expected_trust_level` | the verdict the loop must return |
| `expected_regression` | the judged test that must be named as the regression |
| `why` | why this break fails exactly that test and nothing else |
| `replace.old` / `replace.new` | the replacement, applied to the reference-fixed file |

`replace.old` must appear **exactly once** in the reference-fixed file, or the
oracle refuses rather than scoring something it cannot describe. The
replacement must be valid code, otherwise the candidate would stop at L0, and
it must stay clear of the security fix, otherwise it would stop at L1.
