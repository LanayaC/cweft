# Data Availability Statement

The complete CWEFT artifact is publicly available and supports full reproduction
of every result reported in the paper.

## What is included in this repository

- **Pipeline code** — subset derivation, prompt construction, patch generation for
  all three LLM providers, the Docker-based evaluation harness, the L0–L3 classifier,
  and the analysis scripts (`analyze.py`, `spotcheck.py`, `monitor.py`).
- **Headline results** — `results/results.csv`, containing all 504 per-cell outcomes:
  vulnerability ID, CVE, CWE, prompt level, model, compile status, PoV-pass status,
  regressions, and the assigned trustworthiness level (L0–L3).
- **Per-CWE repair knowledge** — `schemas.py`, the prose (L3a) and typed-schema
  (L3b) encodings, which share identical content.
- **Configuration** — the exact 42-vulnerability subset and its derivation
  (`config.py`), with the four buildability exclusions documented.

## What is archived separately

The raw per-call generation logs (one JSON per cell: full prompt, raw model
response, model ID, timing) total several hundred files and are archived to
**Zenodo** with a permanent DOI rather than committed to the repository, to keep
the repository readable. The Zenodo archive also contains cached model responses,
enabling **cost-free re-evaluation** without re-invoking paid APIs.

> Zenodo DOI: *to be minted prior to camera-ready.*

## Reproduction cost

Full regeneration on the 42-vulnerability subset costs approximately:
GPT-5 ≈ \$30, Claude Sonnet 4.5 ≈ \$30, Gemini 2.5 Pro ≈ \$10 (rates at time of
writing). Re-evaluation from cached responses is free.

## Environment

Evaluation runs inside the `bqcuongas/vul4j:alldeps` Docker image, which pre-caches
Maven dependencies for all Vul4J projects. This image is required because public
Maven mirrors changed in 2023 and vanilla Vul4J checkouts no longer resolve all
dependencies. The README documents the one-command container setup.

## Anonymization note (for double-blind review)

For review, the repository is mirrored at an anonymized URL with all
author-identifying information removed. The non-anonymized version will be linked
and archived to Zenodo upon acceptance.
