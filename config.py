"""
CWEFT experiment configuration.

Single source of truth for: vulnerability subset, models, prompt levels,
paths, and Docker container settings. Imported by everything else.
"""

from pathlib import Path


# ──────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).parent.resolve()
LOGS_DIR = PROJECT_ROOT / "logs"          # per-cell patch JSONs (one per LLM call)
RESULTS_DIR = PROJECT_ROOT / "results"    # results.csv, intermediate aggregates
PROMPTS_DIR = PROJECT_ROOT / "prompts"    # prompt template .py files
SCHEMAS_DIR = PROJECT_ROOT / "schemas"    # per-CWE repair knowledge

# Create dirs if they don't exist (no-op on rerun)
for d in (LOGS_DIR, RESULTS_DIR):
    d.mkdir(parents=True, exist_ok=True)


# ──────────────────────────────────────────────────────────────────────
# Docker / Vul4J container
# ──────────────────────────────────────────────────────────────────────

CONTAINER_NAME = "vul4j-alldeps"
CONTAINER_WORK_DIR = "/tmp/cweft"   # where checkouts live INSIDE the container
DOCKER_EXEC_TIMEOUT = 900           # 15 min per compile/test command


# ──────────────────────────────────────────────────────────────────────
# Models — three frontier coding LLMs from three labs.
# Keys: short identifier used in filenames + CSV columns.
# Values: the actual API model string each provider expects.
# ──────────────────────────────────────────────────────────────────────

MODELS = {
    "claude":  "claude-sonnet-4-5-20250929",      # Anthropic
    "gpt":     "gpt-5",                            # OpenAI
    "gemini":  "gemini-2.5-pro",                   # Google
}


# ──────────────────────────────────────────────────────────────────────
# Prompt levels (the four conditions in the ablation)
# ──────────────────────────────────────────────────────────────────────

PROMPT_LEVELS = ["L1", "L2", "L3a", "L3b"]


# ──────────────────────────────────────────────────────────────────────
# Vulnerability subset.
#
# Derived from `vul4j verify --id VUL4J-1 ... VUL4J-79` inside the
# `bqcuongas/vul4j:alldeps` Docker image (see verify_all.log).
#
# Filter chain:
#   79 total in Vul4J
#   → 63 reproduced (vulnerable build fails PoV, human patch passes it)
#   → 56 after dropping multi-file fixes (single-file subset)
#   → 46 after dropping entries with CWE = "Not Mapping"
# ──────────────────────────────────────────────────────────────────────

SUBSET = [
    "VUL4J-1",  "VUL4J-2",  "VUL4J-6",  "VUL4J-7",  "VUL4J-8",  "VUL4J-10",
    "VUL4J-13", "VUL4J-14", "VUL4J-16", "VUL4J-18", "VUL4J-22", "VUL4J-24",
    "VUL4J-25", "VUL4J-26", "VUL4J-29", "VUL4J-30", "VUL4J-33", "VUL4J-34",
    "VUL4J-36", "VUL4J-40", "VUL4J-41", "VUL4J-43", "VUL4J-44", "VUL4J-45",
    "VUL4J-47", "VUL4J-48", "VUL4J-49", "VUL4J-50", "VUL4J-52", "VUL4J-53",
    "VUL4J-55", "VUL4J-57", "VUL4J-59", "VUL4J-60", "VUL4J-61", "VUL4J-62",
    "VUL4J-66", "VUL4J-75", "VUL4J-76", "VUL4J-77", "VUL4J-78", "VUL4J-79",
]

# Quick sanity: experiment size
TOTAL_CELLS = len(SUBSET) * len(PROMPT_LEVELS) * len(MODELS)


# ──────────────────────────────────────────────────────────────────────
# Run as `python config.py` to print a quick sanity summary
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Project root:       {PROJECT_ROOT}")
    print(f"Container:          {CONTAINER_NAME}")
    print(f"Vulnerabilities:    {len(SUBSET)}")
    print(f"Prompt levels:      {len(PROMPT_LEVELS)}  ({', '.join(PROMPT_LEVELS)})")
    print(f"Models:             {len(MODELS)}  ({', '.join(MODELS.keys())})")
    print(f"Total cells:        {TOTAL_CELLS}")
    print(f"Logs dir:           {LOGS_DIR}")
    print(f"Results dir:        {RESULTS_DIR}")