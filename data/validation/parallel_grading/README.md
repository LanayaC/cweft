# Parallel grading validation

Evidence that `evaluate.py --workers N` (commit `addc955`) gives the same results as sequential grading. All 17 cells in the proof matched at 1, 4 and 8 workers, and all 8 cells in the speed test matched the sequential oracle at 4 and 8 workers.

## What was compared

**Proof (`proof/`):** the same 17 cells were graded at 1, 4 and 8 workers. Workers = 1 is the sequential path, run in `vul4j-alldeps` for Vul4J.

| Sample | Cells | What |
|---|---|---|
| `vul4j_oracle` | 6 | VUL4J-29, 36, 40: original file and reference fix |
| `vul4j_logs` | 6 | VUL4J-41, the first 6 published patches (prompts L1 and L2; claude, gemini, gpt) |
| `patcheval_oracle` | 4 | CVE-2022-2900, CVE-2024-5138: reference fix and vulnerable file |
| `patcheval_logs` | 1 | CVE-2022-1992, prompt L1, granite-8b-bf16 |

- **Fields compared:** every CSV column except the two below, including level, compiled/PoV outcome, regressions, flaky exclusions, error text and code fingerprint. Cells were matched by ID, prompt level and model, because parallel runs write rows in the order cells finish.
- **Fields ignored:** `timestamp` and `timings`, which differ on every run.

**Speed test (`balanced/`):** 8 oracle cells of similar length (VUL4J-29, 30, 33, 34) were graded at 4 and 8 workers. Only `trust_level` and `regressions` were compared, against the sequential results in `results/oracle_vul4j/oracle.csv`.

## Result

- **Proof:** no differences in any compared field at 4 or 8 workers.
- **Speed test:** no differences at 4 or 8 workers.
- **Re-grades:** no cell needed re-grading because of load.

These cells test the parallel path against the sequential one. The `vul4j_logs` levels come from the current grader and do not replace any published result.

## Timing

Speed test, the fairest measure of speed-up because the cells are similar in length:

| Workers | Time | Speed-up | Peak memory (of about 16 GB) | Peak CPU (2000% = all 20 threads) |
|---|---|---|---|---|
| 1 | 871 s | – | – | – |
| 4 | 265 s | 3.3× | 8,982 MiB | 1132% |
| 8 | 228 s | 3.8× | 15,211 MiB | 2032% |

The 1-worker time is the sum of these cells' times in `results/oracle_vul4j/run.log`, not a new run, so memory and CPU were not sampled for it.

Proof samples, in seconds. Extra workers cannot shorten a single long cell, so these understate the speed-up:

| Sample | 1 worker | 4 workers | 8 workers |
|---|---|---|---|
| `vul4j_oracle` | 1146.8 | 520.8 | 467.4 |
| `vul4j_logs` | 89.9 | 59.4 | 46.9 |
| `patcheval_oracle` | 677.6 | 668.7 | 660.2 |
| `patcheval_logs` | 38.3 | 40.2 | 38.6 |

PatchEval's speed-up is not established here: one 10-minute cell dominates its oracle sample, and its other sample is a single cell.

## Limits

- This is 25 cells out of the 2,416 in one pass of the 4 open-weight models.
- VUL4J-61, likely the heaviest entry on memory, was not in the sample.
- A timing-sensitive test could fail under load without timing out, and the re-grade would not catch that.

## Files

- `proof/w{1,4,8}/<sample>/`: the result CSVs and console output for each run.
- `proof/timing.json`: the proof times above.
- `proof/samples_w{1,4,8}.jsonl`: `docker stats` and `free -m` readings taken during each proof run, about every 15 s.
- `balanced/w{4,8}/`: the speed test's result CSVs and console output. Its peak memory and CPU figures were recorded only in the table above.

Paths in the console output are from the machine that ran the tests.
