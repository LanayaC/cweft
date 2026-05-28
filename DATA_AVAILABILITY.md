# Data Availability Statement

The complete CWEFT artifact is publicly available and reproduces every result in the paper.

## In this repository

The repository holds the full pipeline: subset derivation, prompt construction, patch generation for all three LLM providers, the Docker-based evaluation harness, the L0–L3 classifier, and the analysis scripts (`analyze.py`, `spotcheck.py`, `monitor.py`). The headline data lives in `results/results.csv`, which has all 504 per-cell outcomes (vulnerability ID, CVE, CWE, prompt level, model, compile status, PoV-pass status, regressions, and the assigned L0–L3 level). The per-CWE repair knowledge is in `schemas.py`, with the prose (L3a) and typed-schema (L3b) encodings sharing identical content. The exact 42-vulnerability subset and its derivation, including the four buildability exclusions, are defined in `config.py`.

## Archived separately

The raw per-call generation logs (one JSON per cell, with the full prompt, raw model response, model ID, and timing) come to several hundred files, so we archive them to Zenodo with a permanent DOI rather than committing them, which keeps the repository readable. The Zenodo archive also includes cached model responses, so the pipeline can be re-evaluated without paying for new API calls.

> Zenodo DOI: to be minted prior to camera-ready.

## Reproduction cost

Regenerating all patches on the 42-vulnerability subset costs roughly \$30 for GPT-5, \$30 for Claude Sonnet 4.5, and \$10 for Gemini 2.5 Pro at current rates. Re-evaluating from cached responses is free.

## Environment

Evaluation runs inside the `bqcuongas/vul4j:alldeps` Docker image, which pre-caches Maven dependencies for every Vul4J project. The image is necessary because public Maven mirrors changed in 2023 and a vanilla Vul4J checkout no longer resolves all of them. The README has the one-command container setup.

## Anonymization (double-blind review)

For review, the repository is mirrored at an anonymized URL with author-identifying information removed. The non-anonymized version will be linked and archived to Zenodo on acceptance.
