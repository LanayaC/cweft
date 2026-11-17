# Bigger-model mini-pilot, t0.0/r1

Nine vulnerabilities (Vul4J: VUL4J-1, -48, -50, -61, -77; PatchEval: CVE-2022-1992,
CVE-2022-2900, CVE-2022-39286, CVE-2024-5138) x four prompt levels = 36 cells per
model: 5 Vul4J and 4 PatchEval cells per level. Each cell's trust level L0-L3 is
the grade; "echo" counts cells whose response is identical to the original file
after removing all whitespace.

All grading ran under the network-isolated baseline: Vul4J fingerprint
d9fc5b9a52fa, PatchEval fingerprint 93e7d8be280f, every PatchEval image digest
matching the baseline. gemma12b, granite30b and gemma31b were graded on
2026-11-17 with `--workers 4`. granite8b comes from
`granite8b_isolated/t0.0/r1/results.csv` (Vul4J) and
`granite8b/t0.0/r1/results_patcheval.csv` (PatchEval; its fingerprint was
unchanged by the Vul4J isolation commit).

| Model | Level | Vul4J L0 | L1 | L2 | L3 | echo | PatchEval L0 | L1 | L2 | L3 | echo |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| granite8b | L1 | 1 | 4 | 0 | 0 | 3 | 0 | 4 | 0 | 0 | 2 |
| granite8b | L2 | 1 | 4 | 0 | 0 | 3 | 0 | 4 | 0 | 0 | 2 |
| granite8b | L3a | 3 | 2 | 0 | 0 | 2 | 0 | 4 | 0 | 0 | 2 |
| granite8b | L3b | 1 | 4 | 0 | 0 | 1 | 0 | 4 | 0 | 0 | 2 |
| gemma12b | L1 | 0 | 3 | 0 | 2 | 1 | 0 | 4 | 0 | 0 | 0 |
| gemma12b | L2 | 0 | 2 | 0 | 3 | 1 | 0 | 3 | 0 | 1 | 1 |
| gemma12b | L3a | 0 | 2 | 0 | 3 | 0 | 1 | 2 | 0 | 1 | 0 |
| gemma12b | L3b | 0 | 2 | 0 | 3 | 0 | 0 | 4 | 0 | 0 | 2 |
| granite30b | L1 | 1 | 4 | 0 | 0 | 1 | 0 | 4 | 0 | 0 | 0 |
| granite30b | L2 | 1 | 2 | 0 | 2 | 0 | 0 | 4 | 0 | 0 | 0 |
| granite30b | L3a | 2 | 2 | 0 | 1 | 0 | 0 | 4 | 0 | 0 | 0 |
| granite30b | L3b | 4 | 0 | 0 | 1 | 0 | 0 | 4 | 0 | 0 | 1 |
| gemma31b | L1 | 0 | 3 | 0 | 2 | 0 | 0 | 4 | 0 | 0 | 0 |
| gemma31b | L2 | 0 | 2 | 0 | 3 | 0 | 0 | 4 | 0 | 0 | 0 |
| gemma31b | L3a | 0 | 2 | 0 | 3 | 0 | 0 | 4 | 0 | 0 | 0 |
| gemma31b | L3b | 0 | 2 | 0 | 3 | 0 | 0 | 4 | 0 | 0 | 0 |

No cell graded as an error or refusal: every row is L0-L3.

## Copied file markers

No cell failed because the model copied the `--- BEGIN FILE ---` /
`--- END FILE ---` markers. None of the 144 responses (four models x 36)
contains either marker, a looser variant (`BEGIN FILE`, `END FILE`, a
`File path:` line) or a leading code fence, and every response stopped with
`stop` (none truncated). Per-cell flags are in each model's `echo_cells.csv`
(`file_markers_copied` column).

The L0 cells are genuine failures:
- granite30b, 8 Vul4J cells (VUL4J-1 L3b, VUL4J-48 L3b, VUL4J-50 L3a/L3b,
  VUL4J-77 all four levels): complete Java files, no placeholders, that do not
  compile.
- gemma12b, CVE-2022-2900 L3a: `await` added inside a non-async function
  (`SyntaxError: Unexpected reserved word`).

## L3 cells

| Model | Vul4J L3 | PatchEval L3 |
|---|---|---|
| granite8b | none | none |
| gemma12b | VUL4J-50 (all 4), VUL4J-61 (all 4), VUL4J-77 (L2, L3a, L3b) | CVE-2022-1992 (L2, L3a) |
| granite30b | VUL4J-50 (L2), VUL4J-61 (L2, L3a, L3b) | none |
| gemma31b | VUL4J-50 (all 4), VUL4J-61 (L2, L3a, L3b), VUL4J-77 (all 4) | none |

## Files

- `<model>/t0.0/r1/results.csv`, `results_patcheval.csv`: graded cells
- `<model>/echo_cells.csv`: echo and marker flags, response SHA-256 prefix
- `<model>/grading_times.txt`, `grading_vul4j.log`, `grading_patcheval.log`
