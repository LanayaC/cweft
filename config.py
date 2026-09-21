"""
CWEFT experiment configuration.

Single source of truth for: vulnerability subset, models, prompt levels,
paths, and Docker container settings. Imported by everything else.
"""

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.resolve()
LOGS_DIR = PROJECT_ROOT / "logs"          # per-cell patch JSONs (one per LLM call)
RESULTS_DIR = PROJECT_ROOT / "results"    # results.csv, intermediate aggregates
PROMPTS_DIR = PROJECT_ROOT / "prompts"    # prompt template .py files
SCHEMAS_DIR = PROJECT_ROOT / "schemas"    # per-CWE repair knowledge
PATCHEVAL_DIR = PROJECT_ROOT / "data" / "patcheval"   # frozen PatchEval sources + manifest

for d in (LOGS_DIR, RESULTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

CONTAINER_NAME = "vul4j-alldeps"
CONTAINER_WORK_DIR = "/tmp/cweft"   # where checkouts live INSIDE the container
DOCKER_EXEC_TIMEOUT = 900           # 15 min per compile/test command


# Ollama serves the local models. Base URL, context window and per-call
# timeout live here so the whole pipeline has one place to point at a
# different host or shrink the window for a smaller GPU.
OLLAMA_BASE_URL  = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_NUM_CTX   = 40960    # total window: prompt + regenerated file. See models.py.
OLLAMA_KEEP_ALIVE = "30m"   # keep weights resident across the 168 cells per model
OLLAMA_TIMEOUT   = 1800     # 30 min; a 30B q8 regenerating a whole file is slow


CLOUD_MODELS = {
    "claude":  "claude-sonnet-4-5-20250929",      # Anthropic
    "gpt":     "gpt-5",                            # OpenAI
    "gemini":  "gemini-2.5-pro",                   # Google
}

# Served locally by Ollama. The dict KEY is a filesystem-safe handle and the
# VALUE is the Ollama model id. They differ on purpose: the ids contain a
# colon, and generate.py:41 interpolates the key into a log filename, where a
# colon silently becomes an NTFS alternate data stream on Windows (the write
# succeeds, but the file lands without a .json extension and evaluate.py:300
# never globs it).
LOCAL_MODELS = {
    "granite-8b":  "granite4.1:8b-q8_0",
    "granite-30b": "granite4.1:30b-q8_0",
    "gemma-12b":   "gemma4:12b-it-q8_0",
    "gemma-31b":   "gemma4:31b-it-q8_0",
}

MODELS = {**CLOUD_MODELS, **LOCAL_MODELS}


PROMPT_LEVELS = ["L1", "L2", "L3a", "L3b"]

SUBSET = [
    "VUL4J-1",  "VUL4J-2",  "VUL4J-6",  "VUL4J-7",  "VUL4J-8",  "VUL4J-10",
    "VUL4J-13", "VUL4J-14", "VUL4J-16", "VUL4J-18", "VUL4J-22", "VUL4J-24",
    "VUL4J-25", "VUL4J-26", "VUL4J-29", "VUL4J-30", "VUL4J-33", "VUL4J-34",
    "VUL4J-36", "VUL4J-40", "VUL4J-41", "VUL4J-43", "VUL4J-44", "VUL4J-45",
    "VUL4J-47", "VUL4J-48", "VUL4J-49", "VUL4J-50", "VUL4J-52", "VUL4J-53",
    "VUL4J-55", "VUL4J-57", "VUL4J-59", "VUL4J-60", "VUL4J-61", "VUL4J-62",
    "VUL4J-66", "VUL4J-75", "VUL4J-76", "VUL4J-77", "VUL4J-78", "VUL4J-79",
]

TOTAL_CELLS = len(SUBSET) * len(PROMPT_LEVELS) * len(MODELS)

if __name__ == "__main__":
    print(f"Project root:       {PROJECT_ROOT}")
    print(f"Container:          {CONTAINER_NAME}")
    print(f"Vulnerabilities:    {len(SUBSET)}")
    print(f"Prompt levels:      {len(PROMPT_LEVELS)}  ({', '.join(PROMPT_LEVELS)})")
    print(f"Models:             {len(MODELS)}  ({', '.join(MODELS.keys())})")
    print(f"Total cells:        {TOTAL_CELLS}")
    print(f"Logs dir:           {LOGS_DIR}")
    print(f"Results dir:        {RESULTS_DIR}")
