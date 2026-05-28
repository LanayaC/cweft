"""
Unified LLM wrappers for the three providers.

Exposes one function: call_model(model_key, prompt) -> (response_text, usage_dict)
where model_key is "claude" | "gpt" | "gemini".

All API differences live here. The rest of the pipeline calls this once
per cell and doesn't care which provider it's talking to.
"""

import os
import re
import time
from typing import Tuple

from dotenv import load_dotenv

from config import MODELS

load_dotenv()


# ──────────────────────────────────────────────────────────────────────
# Lazy client init — only construct a client when first used,
# so missing API keys for unused providers don't crash startup.
# ──────────────────────────────────────────────────────────────────────

_clients = {}


def _get_anthropic():
    if "anthropic" not in _clients:
        from anthropic import Anthropic
        _clients["anthropic"] = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    return _clients["anthropic"]


def _get_openai():
    if "openai" not in _clients:
        from openai import OpenAI
        _clients["openai"] = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    return _clients["openai"]


def _get_gemini():
    if "gemini" not in _clients:
        from google import genai
        _clients["gemini"] = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])
    return _clients["gemini"]


# ──────────────────────────────────────────────────────────────────────
# Output sanitization
# ──────────────────────────────────────────────────────────────────────

_FENCE_RE = re.compile(r"^```(?:java|json|xml)?\s*\n?|\n?```\s*$", re.MULTILINE)


def _strip_markdown_fences(text: str) -> str:
    """
    Remove ```java ... ``` style fences if a model added them despite
    being told not to. Idempotent: no-op if there are no fences.
    """
    return _FENCE_RE.sub("", text).strip()


# ──────────────────────────────────────────────────────────────────────
# System prompt — identical across providers
# ──────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a deterministic Java automated program repair tool. "
    "Return ONLY the complete modified Java source file with the security "
    "repair applied. Do NOT wrap the code in markdown fences such as "
    "```java. Do NOT add explanations, comments about your changes, or "
    "any text before or after the file. Your entire response must be "
    "valid Java source code that can be saved directly to a .java file "
    "and compiled."
)


# ──────────────────────────────────────────────────────────────────────
# Per-provider call functions. Each returns the same shape:
#   (response_text: str, usage: dict)
# ──────────────────────────────────────────────────────────────────────

def _call_claude(prompt: str) -> Tuple[str, dict]:
    client = _get_anthropic()
    response = client.messages.create(
        model=MODELS["claude"],
        max_tokens=8192,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text
    usage = {
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
    }
    return text, usage


def _call_gpt(prompt: str) -> Tuple[str, dict]:
    client = _get_openai()
    response = client.chat.completions.create(
        model=MODELS["gpt"],
        max_completion_tokens=8192,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    text = response.choices[0].message.content
    usage = {
        "input_tokens": response.usage.prompt_tokens,
        "output_tokens": response.usage.completion_tokens,
    }
    return text, usage


def _call_gemini(prompt: str) -> Tuple[str, dict]:
    client = _get_gemini()
    from google.genai import types
    response = client.models.generate_content(
        model=MODELS["gemini"],
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            max_output_tokens=32768,
            thinking_config=types.ThinkingConfig(thinking_budget=512),
        ),
    )
    text = response.text
    if text is None:
        finish = response.candidates[0].finish_reason if response.candidates else "unknown"
        raise RuntimeError(f"Gemini returned no text (finish_reason={finish})")
    usage = {
        "input_tokens": getattr(response.usage_metadata, "prompt_token_count", 0),
        "output_tokens": getattr(response.usage_metadata, "candidates_token_count", 0),
    }
    return text, usage
# ──────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────

_DISPATCH = {
    "claude": _call_claude,
    "gpt": _call_gpt,
    "gemini": _call_gemini,
}


def call_model(model_key: str, prompt: str) -> Tuple[str, dict]:
    """
    Call the named model with the given prompt.

    Args:
        model_key: "claude" | "gpt" | "gemini"
        prompt:    full user prompt text

    Returns:
        (response_text, usage_dict)
        usage_dict has keys: input_tokens, output_tokens, latency_s
    """
    if model_key not in _DISPATCH:
        raise ValueError(f"Unknown model_key: {model_key!r}. Use one of {list(_DISPATCH)}.")

    start = time.time()
    text, usage = _DISPATCH[model_key](prompt)
    usage["latency_s"] = round(time.time() - start, 2)
    return _strip_markdown_fences(text), usage


# ──────────────────────────────────────────────────────────────────────
# Smoke test: python models.py
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_prompt = (
        "Return a one-line Java method called add that takes two ints and "
        "returns their sum. Just the method, no class wrapper, no commentary."
    )

    for key in MODELS:
        print(f"\n--- {key} ({MODELS[key]}) ---")
        try:
            text, usage = call_model(key, test_prompt)
            print(f"Latency: {usage['latency_s']}s")
            print(f"Tokens:  in={usage['input_tokens']}  out={usage['output_tokens']}")
            print(f"Output:  {text.strip()[:200]}")
        except Exception as e:
            print(f"ERROR: {type(e).__name__}: {e}")