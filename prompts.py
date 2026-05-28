"""
Prompt construction for the four ablation conditions.

L1  — Baseline:        vulnerable code only, generic repair instruction.
L2  — CWE-Named:       L1 + CWE identifier and one-sentence description.
L3a — Free-Text:       L2 + prose paragraph of how this CWE is typically fixed.
L3b — Structured:      L2 + same fix knowledge as L3a, but as a typed schema.

L3a and L3b encode IDENTICAL underlying repair knowledge, sourced from
APR4Vul's mined fix-pattern tables. The L3a vs. L3b comparison is the
central experimental contrast: only the *representational format* varies.

All four conditions share the same:
  - vulnerable file content (whole file, not method snippet)
  - target file path hint
  - output instruction (return complete modified file, code only)

so any outcome differences must come from the single factor that varies
between adjacent levels.
"""

from typing import Dict


# ──────────────────────────────────────────────────────────────────────
# Shared scaffolding — identical across all four levels.
# Any change here must apply uniformly to L1-L3b or it breaks the ablation.
# ──────────────────────────────────────────────────────────────────────

_TASK_PREAMBLE = (
    "The following Java source file contains a security vulnerability. "
    "Your task is to produce a patched version of the file that closes "
    "the vulnerability while preserving all other functionality."
)

_OUTPUT_INSTRUCTION = (
    "Return the complete modified Java file. Preserve the original "
    "package declaration, all imports needed for the patched code, the "
    "class structure, and the signatures of all methods that the patch "
    "does not need to change. If your patch requires a new import, "
    "include it in the import block at the top of the file. Output ONLY "
    "the complete Java source — no markdown fences, no explanation, no "
    "before-or-after commentary."
)


def _file_block(file_path: str, file_content: str) -> str:
    """Render the vulnerable file with a path hint above it."""
    return (
        f"File path: {file_path}\n"
        f"--- BEGIN FILE ---\n"
        f"{file_content}\n"
        f"--- END FILE ---"
    )


# ──────────────────────────────────────────────────────────────────────
# Per-level prompt builders
# ──────────────────────────────────────────────────────────────────────

def _build_l1(vuln_info: Dict, file_block: str) -> str:
    """L1 — Baseline. No vulnerability-specific information."""
    return (
        f"{_TASK_PREAMBLE}\n\n"
        f"{file_block}\n\n"
        f"{_OUTPUT_INSTRUCTION}"
    )


def _build_l2(vuln_info: Dict, file_block: str) -> str:
    """L2 — L1 + CWE identifier and short description."""
    cwe_id = vuln_info["cwe_id"]
    cwe_name = vuln_info["cwe_name"]
    return (
        f"{_TASK_PREAMBLE}\n\n"
        f"Vulnerability classification:\n"
        f"  - {cwe_id}: {cwe_name}\n\n"
        f"{file_block}\n\n"
        f"{_OUTPUT_INSTRUCTION}"
    )


def _build_l3a(vuln_info: Dict, file_block: str) -> str:
    """L3a — L2 + free-text fix-pattern guidance."""
    cwe_id = vuln_info["cwe_id"]
    cwe_name = vuln_info["cwe_name"]
    prose = vuln_info["repair_prose"]
    return (
        f"{_TASK_PREAMBLE}\n\n"
        f"Vulnerability classification:\n"
        f"  - {cwe_id}: {cwe_name}\n\n"
        f"Typical repair pattern for this vulnerability class:\n"
        f"{prose}\n\n"
        f"{file_block}\n\n"
        f"{_OUTPUT_INSTRUCTION}"
    )


def _build_l3b(vuln_info: Dict, file_block: str) -> str:
    """L3b — L2 + same fix knowledge as L3a, as a typed schema."""
    cwe_id = vuln_info["cwe_id"]
    cwe_name = vuln_info["cwe_name"]
    schema = vuln_info["repair_schema"]
    schema_block = (
        f"  Root Cause:      {schema['root_cause']}\n"
        f"  Canonical Repair: {schema['canonical_repair']}\n"
        f"  Constraints:     {schema['constraints']}\n"
        f"  What to Avoid:   {schema['what_to_avoid']}"
    )
    return (
        f"{_TASK_PREAMBLE}\n\n"
        f"Vulnerability classification:\n"
        f"  - {cwe_id}: {cwe_name}\n\n"
        f"Repair specification for this vulnerability class:\n"
        f"{schema_block}\n\n"
        f"{file_block}\n\n"
        f"{_OUTPUT_INSTRUCTION}"
    )


# ──────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────

_BUILDERS = {
    "L1":  _build_l1,
    "L2":  _build_l2,
    "L3a": _build_l3a,
    "L3b": _build_l3b,
}


def build_prompt(level: str, vuln_info: Dict, file_path: str, file_content: str) -> str:
    """
    Build the user prompt for one (level, vulnerability) cell.

    Args:
        level:        "L1" | "L2" | "L3a" | "L3b"
        vuln_info:    dict with keys depending on level:
                        L1:  (none required from vuln_info)
                        L2:  cwe_id, cwe_name
                        L3a: cwe_id, cwe_name, repair_prose
                        L3b: cwe_id, cwe_name, repair_schema (dict with
                             root_cause, canonical_repair, constraints,
                             what_to_avoid)
        file_path:    relative path of the vulnerable file inside its project
        file_content: full source of the vulnerable Java file

    Returns:
        The complete prompt string to send to the LLM.
    """
    if level not in _BUILDERS:
        raise ValueError(f"Unknown level: {level!r}. Use one of {list(_BUILDERS)}.")

    file_block = _file_block(file_path, file_content)
    return _BUILDERS[level](vuln_info, file_block)


# ──────────────────────────────────────────────────────────────────────
# Smoke test: python prompts.py
# Builds all four prompts for a fake CWE-22 path traversal case so you
# can read them side-by-side and confirm the ablation looks right.
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    fake_vuln = {
        "cwe_id":   "CWE-22",
        "cwe_name": "Path Traversal",
        "repair_prose": (
            "Path traversal vulnerabilities are typically fixed by canonicalizing "
            "user-supplied paths with File.getCanonicalPath() and verifying the "
            "result remains within an allowed base directory before any file "
            "operation."
        ),
        "repair_schema": {
            "root_cause":       "Untrusted path fragment used in file resolution without normalization.",
            "canonical_repair": "Canonicalize via getCanonicalPath() and verify startsWith(base).",
            "constraints":      "Preserve original method signature; do not alter exception types.",
            "what_to_avoid":    "String.contains(\"..\") checks; these bypass via encoded variants.",
        },
    }

    fake_file = (
        "package org.example;\n"
        "public class Loader {\n"
        "    public byte[] read(String name) throws IOException {\n"
        "        return Files.readAllBytes(Paths.get(BASE, name));\n"
        "    }\n"
        "}"
    )

    for level in ("L1", "L2", "L3a", "L3b"):
        print("\n" + "=" * 72)
        print(f"  PROMPT — {level}")
        print("=" * 72)
        print(build_prompt(level, fake_vuln, "src/main/java/org/example/Loader.java", fake_file))