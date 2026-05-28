# CWEFT: CWE-aware Evaluation of Free-text vs. Typed Prompts

CWEFT is a controlled ablation study testing whether the **format** of vulnerability
repair knowledge injected into an LLM prompt — free-text prose vs. a typed schema —
affects automated vulnerability repair quality when the **content** is held constant.

This repository contains the full pipeline: subset derivation, prompt construction,
patch generation across three frontier LLMs, and a reproducible Docker-based
evaluation harness, plus the complete results.

---

## Research questions

- **RQ1** — Does enriching prompts with vulnerability-type-specific fix knowledge
  improve patch quality over an unenriched baseline?
- **RQ2** — Does the *representational format* (free-text vs. typed schema) of that
  knowledge produce a measurable difference in patch quality when content is held
  constant? *(central question)*
- **RQ3** — How does single-shot LLM repair compare across models?
- **RQ4** — Under a multi-level trustworthiness hierarchy, what are the dominant
  failure modes, and where do they concentrate?

## Experimental design

**Four prompt conditions** (an ablation; each adds one factor over the previous):

| Level | Content |
|-------|---------|
| **L1** | Vulnerable code only (baseline) |
| **L2** | + CWE name and description |
| **L3a** | + free-text prose fix guidance |
| **L3b** | + the *same* guidance as a 4-field typed schema (Root Cause, Canonical Repair, Constraints, What to Avoid) |

L3a and L3b encode **identical underlying knowledge** drawn from APR4Vul's mined
fix patterns, differing only in form — this isolates format from content.

**Three models** (one per lab, for external validity):
`claude-sonnet-4-5`, `gpt-5`, `gemini-2.5-pro`.

**Trustworthiness levels** (output classification, adapted from APR4Vul):

| Level | Meaning |
|-------|---------|
| **L0** | Patch does not compile |
| **L1** | Compiles, but the PoV test still fails (vulnerability not fixed) |
| **L2** | PoV test passes, but other tests regress |
| **L3** | PoV test passes and all tests pass (correct fix) |

**Scale:** 42 vulnerabilities × 4 prompt levels × 3 models = **504 cells**.

## Dataset and subset derivation

We draw from [Vul4J](https://github.com/tuhh-softsec/vul4j), a benchmark of real,
reproducible Java CVEs. The 42-vulnerability subset is derived by applying, in order:

1. **Reproducibility filter** — keep vulnerabilities Vul4J marks as reproducible.
2. **Single-file filter** — keep vulnerabilities whose human patch touches one file
   (required for the method's single-file repair scope).
3. **CWE-mapping filter** — drop entries without a CWE label (the L2/L3a/L3b
   conditions cannot be constructed without one).
4. **Buildability filter** — drop entries whose vulnerable revision does **not**
   build cleanly in our evaluation container with no patch applied. This removed
   **VUL4J-15, VUL4J-23, VUL4J-35, VUL4J-39**; the first three are flagged by the
   Vul4J maintainers' own reproduction status as non-compilable or requiring manual
   modification, and the fourth fails to build in our environment despite being
   marked reproducible upstream.

The final 42-vulnerability subset spans **17 CWE classes**.

## Repository layout

```
cweft/
├── config.py          # Subset, models, prompt levels, paths, container settings
├── vuln_data.py       # Vul4J integration: checkout, file paths, PoV test extraction
├── schemas.py         # Per-CWE repair knowledge (prose for L3a + schema for L3b)
├── prompts.py         # Builds the four prompt variants from a shared scaffold
├── models.py          # Unified call_model() wrapper for the three LLM providers
├── generate.py        # Patch-generation loop (resumable; caches per-cell logs)
├── evaluate.py        # Apply → compile → test → classify into L0–L3 (resumable)
├── analyze.py         # Produces all paper tables + McNemar test for L3a vs L3b
├── monitor.py         # Live progress dashboard (read-only; safe to run alongside)
├── spotcheck.py       # Inspect a single cell: LLM patch vs. human patch + verdict
├── results/
│   └── results.csv     # All 504 per-cell outcomes (the headline data)
├── requirements.txt
├── .env.example        # Copy to .env and add your API keys
└── README.md
```

## Setup

### Prerequisites
- Python 3.10+
- Docker, with the Vul4J "all-dependencies" image:
  ```bash
  docker pull bqcuongas/vul4j:alldeps
  docker run -d --name vul4j-alldeps bqcuongas/vul4j:alldeps tail -f /dev/null
  ```
  (This pre-cached image is used because public Maven mirrors changed in 2023 and
  vanilla Vul4J checkouts no longer resolve all dependencies.)

### Install
```bash
python -m venv cweft-venv
source cweft-venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then edit .env and add your three API keys
```

## Reproduce

```bash
# 0. Sanity-check the configuration (prints subset size, cell count)
python config.py

# 1. Generate patches (resumable; skips cells already logged)
python generate.py

# 2. Evaluate every patch in the Docker harness (resumable)
python evaluate.py

# 3. Produce all tables + statistics
python analyze.py

# Optional: live progress while (1) or (2) runs, in a second terminal
python monitor.py
```

Both generation and evaluation are **resumable** — cells whose artifact already
exists are skipped, so partial re-runs do not re-incur API cost or recompute.

To inspect any single cell (e.g. to verify a verdict):
```bash
python spotcheck.py VUL4J-45 L2 gemini
python spotcheck.py --list-l3        # list all correct-fix cells
```

## Results summary

Over 504 cells (ERROR-free, fully classified):

- Overall: **L0 22.8%, L1 54.6%, L2 6.2%, L3 16.5%** (compile rate 77.2%).
- **RQ2 (headline):** L3a and L3b reach an *identical* 16.7% L3 rate. McNemar's
  test on paired L3a-vs-L3b outcomes finds no significant difference
  (pooled p = 1.0) — prompt **format does not measurably affect repair quality**
  when content is held constant.
- Naming the CWE (L2, 19.8%) outperforms both elaborate-enrichment conditions
  (L3a/L3b, 16.7%) and the baseline (L1, 12.7%).
- Repair rate tracks CWE specificity: concrete classes (e.g. CWE-74 injection)
  are repaired far more often than abstract ones (e.g. CWE-20 input validation).

See `analyze.py` output and `results/` for the full tables.

## Citing

A `CITATION.cff` will be added on acceptance. Until then, please cite the
artifact's archived release (see Data Availability statement in the paper).

## License

Apache-2.0. See [LICENSE](LICENSE).
