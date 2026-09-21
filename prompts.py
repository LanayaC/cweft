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


# Per-language scaffolding. Java is the text the published Vul4J cells were
# generated with and must never change (tests/test_prompt_regression.py).
# Every other language gets the same preamble with its name swapped in, and
# an output instruction rewritten for its own file structure; within one
# language both are identical across L1-L3b, as the ablation requires.

def _preamble(language: str) -> str:
    return (
        f"The following {language} source file contains a security vulnerability. "
        "Your task is to produce a patched version of the file that closes "
        "the vulnerability while preserving all other functionality."
    )


_OUTPUT_TAIL = "no markdown fences, no explanation, no before-or-after commentary."

_TASK_PREAMBLES = {
    "Java":       _TASK_PREAMBLE,
    "Go":         _preamble("Go"),
    "JavaScript": _preamble("JavaScript"),
    "TypeScript": _preamble("TypeScript"),
    "Python":     _preamble("Python"),
}

_OUTPUT_INSTRUCTIONS = {
    "Java": _OUTPUT_INSTRUCTION,
    "Go": (
        "Return the complete modified Go file. Preserve the original "
        "package clause, all imports needed for the patched code, the type "
        "and function declarations, and the signatures of all functions and "
        "methods that the patch does not need to change. If your patch "
        "requires a new import, include it in the import block at the top "
        "of the file. Output ONLY the complete Go source — " + _OUTPUT_TAIL
    ),
    "JavaScript": (
        "Return the complete modified JavaScript file. Preserve the original "
        "module format (require/module.exports or import/export), all "
        "imports needed for the patched code, the exported names, and the "
        "signatures of all functions and methods that the patch does not "
        "need to change. If your patch requires a new import, add it "
        "alongside the existing require or import statements at the top of "
        "the file. Output ONLY the complete JavaScript source — " + _OUTPUT_TAIL
    ),
    "TypeScript": (
        "Return the complete modified TypeScript file. Preserve the original "
        "imports needed for the patched code, the exported names, the type "
        "annotations, and the signatures of all functions and methods that "
        "the patch does not need to change. If your patch requires a new "
        "import, add it alongside the existing import statements at the top "
        "of the file. Output ONLY the complete TypeScript source — " + _OUTPUT_TAIL
    ),
    "Python": (
        "Return the complete modified Python file. Preserve the original "
        "imports needed for the patched code, the class and function "
        "structure, and the signatures of all functions and methods that the "
        "patch does not need to change. If your patch requires a new import, "
        "include it with the imports at the top of the file. Output ONLY the "
        "complete Python source — " + _OUTPUT_TAIL
    ),
}

LANGUAGES = tuple(_TASK_PREAMBLES)


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

def _build_l1(vuln_info: Dict, file_block: str, preamble: str, instruction: str) -> str:
    """L1 — Baseline. No vulnerability-specific information."""
    return (
        f"{preamble}\n\n"
        f"{file_block}\n\n"
        f"{instruction}"
    )


def _build_l2(vuln_info: Dict, file_block: str, preamble: str, instruction: str) -> str:
    """L2 — L1 + CWE identifier and short description."""
    cwe_id = vuln_info["cwe_id"]
    cwe_name = vuln_info["cwe_name"]
    return (
        f"{preamble}\n\n"
        f"Vulnerability classification:\n"
        f"  - {cwe_id}: {cwe_name}\n\n"
        f"{file_block}\n\n"
        f"{instruction}"
    )


def _build_l3a(vuln_info: Dict, file_block: str, preamble: str, instruction: str) -> str:
    """L3a — L2 + free-text fix-pattern guidance."""
    cwe_id = vuln_info["cwe_id"]
    cwe_name = vuln_info["cwe_name"]
    prose = vuln_info["repair_prose"]
    return (
        f"{preamble}\n\n"
        f"Vulnerability classification:\n"
        f"  - {cwe_id}: {cwe_name}\n\n"
        f"Typical repair pattern for this vulnerability class:\n"
        f"{prose}\n\n"
        f"{file_block}\n\n"
        f"{instruction}"
    )


def _build_l3b(vuln_info: Dict, file_block: str, preamble: str, instruction: str) -> str:
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
        f"{preamble}\n\n"
        f"Vulnerability classification:\n"
        f"  - {cwe_id}: {cwe_name}\n\n"
        f"Repair specification for this vulnerability class:\n"
        f"{schema_block}\n\n"
        f"{file_block}\n\n"
        f"{instruction}"
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


def build_prompt(
    level: str,
    vuln_info: Dict,
    file_path: str,
    file_content: str,
    language: str = "Java",
) -> str:
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
        file_content: full source of the vulnerable file
        language:     one of LANGUAGES; selects the preamble and output
                      instruction. The default is what the Vul4J cells used.

    Returns:
        The complete prompt string to send to the LLM.
    """
    if level not in _BUILDERS:
        raise ValueError(f"Unknown level: {level!r}. Use one of {list(_BUILDERS)}.")
    if language not in _TASK_PREAMBLES:
        raise ValueError(f"Unknown language: {language!r}. Use one of {list(LANGUAGES)}.")

    file_block = _file_block(file_path, file_content)
    return _BUILDERS[level](
        vuln_info, file_block, _TASK_PREAMBLES[language], _OUTPUT_INSTRUCTIONS[language]
    )


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