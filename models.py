"""
Unified LLM wrappers for the cloud providers, local Ollama models, and
models served by vLLM.

Exposes one function: call_model(model_key, prompt, language="Java")
-> (response_text, usage_dict), where model_key is any key of config.MODELS.

All API differences live here. The rest of the pipeline calls this once
per cell and doesn't care which provider it's talking to.
"""

import os
import re
import time
from functools import partial
from typing import Tuple

from dotenv import load_dotenv

from config import (
    MODELS, LOCAL_MODELS,
    OLLAMA_BASE_URL, OLLAMA_NUM_CTX, OLLAMA_KEEP_ALIVE, OLLAMA_TIMEOUT,
    VLLM_MODELS, VLLM_BASE_URL, VLLM_MAX_MODEL_LEN, VLLM_MAX_OUTPUT_TOKENS,
    VLLM_TOKEN_MARGIN, VLLM_TIMEOUT, VLLM_PLACEHOLDER,
)

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


def _get_vllm():
    if "vllm" not in _clients:
        from openai import OpenAI
        # vLLM ignores the key but the client requires one. No client-side
        # retries: generate.run_cell already retries, and a retried timeout
        # here would silently repeat a half-hour generation.
        _clients["vllm"] = OpenAI(base_url=VLLM_BASE_URL, api_key="EMPTY",
                                  timeout=VLLM_TIMEOUT, max_retries=0)
    return _clients["vllm"]


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


def _strip_outer_fence(text: str) -> str:
    """
    Remove one markdown fence wrapped around the WHOLE response, if present.

    Used for every language except Java. _FENCE_RE works line by line, so it
    would also delete ``` lines inside the file itself (Python docstrings and
    JS template literals often hold markdown), and its (?:java|...) label
    leaves "script" behind on a ```javascript fence. Only the first and last
    lines are touched here. Java keeps _FENCE_RE so its outputs are cleaned
    exactly as the published cells were.
    """
    text = text.strip()
    lines = text.split("\n")
    if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].strip() == "```":
        text = "\n".join(lines[1:-1])
    elif lines[0].startswith("```") and lines[0].strip() != "```" and " " not in lines[0].strip():
        text = "\n".join(lines[1:])  # opening fence only, closing one cut off
    return text.strip()


# ──────────────────────────────────────────────────────────────────────
# System prompt — identical across providers, one per source language
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


def _system_prompt(language: str, fence: str, extension: str, check: str) -> str:
    return (
        f"You are a deterministic {language} automated program repair tool. "
        f"Return ONLY the complete modified {language} source file with the security "
        f"repair applied. Do NOT wrap the code in markdown fences such as "
        f"```{fence}. Do NOT add explanations, comments about your changes, or "
        f"any text before or after the file. Your entire response must be "
        f"valid {language} source code that can be saved directly to a {extension} file "
        f"and {check}."
    )


# Java is the published SYSTEM_PROMPT itself, never a rebuilt copy of it.
SYSTEM_PROMPTS = {
    "Java":       SYSTEM_PROMPT,
    "Go":         _system_prompt("Go", "go", ".go", "compiled"),
    "JavaScript": _system_prompt("JavaScript", "javascript", ".js", "run"),
    "TypeScript": _system_prompt("TypeScript", "typescript", ".ts", "compiled"),
    "Python":     _system_prompt("Python", "python", ".py", "run"),
}


# ──────────────────────────────────────────────────────────────────────
# Truncation detection
#
# Every provider says why it stopped, but each uses its own field and its own
# vocabulary. The value is recorded verbatim as `stop_reason`, and the one
# value per provider that means "I ran out of output budget" sets `truncated`:
#
#   claude   response.stop_reason                  "max_tokens"
#   gpt      choices[0].finish_reason              "length"
#   gemini   candidates[0].finish_reason           "MAX_TOKENS" (an enum)
#   ollama   done_reason                           "length"
#   vllm     choices[0].finish_reason              "length"
#
# A truncated response is a file cut off mid-write. It cannot compile or parse,
# so it scores L0 and looks exactly like a failed repair unless the flag is
# carried alongside it.
# ──────────────────────────────────────────────────────────────────────

# The configured output budget per cloud model, so a pre-flight check reads the
# same number the request sends instead of a copy that can drift. Unchanged
# values: these are what the published 504 ran with. The local models have no
# output cap - their OLLAMA_NUM_CTX window holds prompt and output together.
OUTPUT_CAPS = {
    "claude": 8192,
    "gpt":    8192,
    "gemini": 32768,
}


TRUNCATION_REASON = {
    "claude": "max_tokens",
    "gpt":    "length",
    "gemini": "MAX_TOKENS",
    "ollama": "length",
    "vllm":   "length",
}


def _reason_text(raw) -> str:
    """A provider's stop reason as a plain string (Gemini's is an enum)."""
    if raw is None:
        return ""
    return str(getattr(raw, "name", None) or raw)


def is_truncated(provider: str, reason: str) -> bool:
    want = TRUNCATION_REASON.get(provider)
    if not want or not reason:
        return False
    return reason.strip().upper().endswith(want.upper())


# ──────────────────────────────────────────────────────────────────────
# Per-provider call functions. Each returns the same shape:
#   (response_text: str, usage: dict)
# where usage always carries input_tokens, output_tokens, stop_reason and
# truncated.
# ──────────────────────────────────────────────────────────────────────

def _call_claude(prompt: str, system: str) -> Tuple[str, dict]:
    client = _get_anthropic()
    response = client.messages.create(
        model=MODELS["claude"],
        max_tokens=OUTPUT_CAPS["claude"],
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text
    reason = _reason_text(getattr(response, "stop_reason", None))
    usage = {
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "stop_reason": reason,
        "truncated": is_truncated("claude", reason),
    }
    return text, usage


def _call_gpt(prompt: str, system: str) -> Tuple[str, dict]:
    client = _get_openai()
    response = client.chat.completions.create(
        model=MODELS["gpt"],
        max_completion_tokens=OUTPUT_CAPS["gpt"],
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    )
    text = response.choices[0].message.content or ""
    reason = _reason_text(getattr(response.choices[0], "finish_reason", None))
    usage = {
        "input_tokens": response.usage.prompt_tokens,
        "output_tokens": response.usage.completion_tokens,
        "stop_reason": reason,
        "truncated": is_truncated("gpt", reason),
    }
    # Reasoning tokens share max_completion_tokens with the visible answer, so
    # record them: they explain a truncation that the file length alone doesn't.
    details = getattr(response.usage, "completion_tokens_details", None)
    reasoning = getattr(details, "reasoning_tokens", None)
    if reasoning is not None:
        usage["reasoning_tokens"] = reasoning
    # An empty string here would be written out as an empty .java file and
    # scored as a genuine L0. On reasoning models max_completion_tokens covers
    # reasoning tokens as well as visible output, so the whole budget can be
    # consumed before any text is emitted.
    if not text.strip():
        raise RuntimeError(
            f"OpenAI returned an empty response (finish_reason="
            f"{response.choices[0].finish_reason!r}, completion_tokens="
            f"{usage['output_tokens']}, max_completion_tokens="
            f"{OUTPUT_CAPS['gpt']})."
        )
    return text, usage


def _call_gemini(prompt: str, system: str) -> Tuple[str, dict]:
    client = _get_gemini()
    from google.genai import types
    response = client.models.generate_content(
        model=MODELS["gemini"],
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=OUTPUT_CAPS["gemini"],
            thinking_config=types.ThinkingConfig(thinking_budget=512),
        ),
    )
    text = response.text
    candidate = response.candidates[0] if response.candidates else None
    reason = _reason_text(getattr(candidate, "finish_reason", None)) if candidate else ""
    if text is None:
        raise RuntimeError(f"Gemini returned no text (finish_reason={reason or 'unknown'})")
    usage = {
        "input_tokens": getattr(response.usage_metadata, "prompt_token_count", 0),
        "output_tokens": getattr(response.usage_metadata, "candidates_token_count", 0),
        "stop_reason": reason,
        "truncated": is_truncated("gemini", reason),
    }
    return text, usage


def _call_ollama(prompt: str, system: str, model_key: str) -> Tuple[str, dict]:
    """
    Local generation via Ollama's /api/generate.

    num_ctx is the TOTAL window — the prompt and the generated file share it.
    The request disables Ollama's silent truncation and context shifting, and
    the guards below are a backstop in case a server ignores those fields: any
    sign the window ran out raises, because a half-written Java file cannot
    compile and would be scored as a genuine L0.
    """
    import httpx

    body = {
        "model":      MODELS[model_key],
        "prompt":     prompt,
        "system":     system,
        "stream":     False,            # default is streaming NDJSON; .json() would fail
        "keep_alive": OLLAMA_KEEP_ALIVE,
        # Ollama's defaults degrade silently when the window is too small: a long
        # prompt is cut to about half the window, and a full window is shifted
        # (oldest tokens dropped) while generation carries on. Turn both off so
        # an over-long prompt returns HTTP 400 and a full window stops with
        # done_reason "length". Measured on Ollama 0.33.2.
        "truncate":   False,
        "shift":      False,
        "options":    {"num_ctx": OLLAMA_NUM_CTX},
    }

    try:
        response = httpx.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json=body,
            # long read budget, but fail fast if nothing is listening
            timeout=httpx.Timeout(OLLAMA_TIMEOUT, connect=10.0),
        )
    except httpx.RequestError as e:
        raise RuntimeError(f"Ollama unreachable at {OLLAMA_BASE_URL} for "
                           f"{model_key}: {type(e).__name__}: {e}") from e

    if response.status_code != 200:
        raise RuntimeError(f"Ollama HTTP {response.status_code} for {model_key}: "
                           f"{response.text[:300]}")

    data = response.json()
    if data.get("error"):
        raise RuntimeError(f"Ollama error for {model_key}: {data['error']}")

    text = data.get("response") or ""
    reason = _reason_text(data.get("done_reason"))
    usage = {
        "input_tokens":  data.get("prompt_eval_count", 0),
        "output_tokens": data.get("eval_count", 0),
        "stop_reason": reason,
        "truncated": is_truncated("ollama", reason),
    }

    if not text.strip():
        raise RuntimeError(f"Ollama returned an empty response for {model_key} "
                           f"(done_reason={data.get('done_reason')!r})")

    # Output hit the ceiling: the file is cut off mid-token.
    if data.get("done_reason") == "length":
        raise RuntimeError(
            f"Ollama truncated the output for {model_key} at num_ctx="
            f"{OLLAMA_NUM_CTX} (in={usage['input_tokens']}, "
            f"out={usage['output_tokens']}). Raise OLLAMA_NUM_CTX in config.py."
        )

    # Prompt at the window edge. Backstop only: with truncate=False the server
    # rejects an over-long prompt with HTTP 400 before we get here, and 0.33.2's
    # own truncation cuts to about HALF the window, which this check would miss.
    n_in = usage["input_tokens"]
    if n_in and n_in >= OLLAMA_NUM_CTX - 64:
        raise RuntimeError(
            f"Prompt for {model_key} was truncated to fit num_ctx="
            f"{OLLAMA_NUM_CTX} (prompt_eval_count={n_in}). "
            f"Raise OLLAMA_NUM_CTX in config.py."
        )

    # Window exhausted. When the context fills, some Ollama builds shift it
    # (discard the oldest tokens and keep generating) and finish with a normal
    # done_reason, so neither check above fires. Prompt plus generated tokens
    # can only reach num_ctx if the window ran out, whatever the build does.
    n_out = usage["output_tokens"]
    if n_in + n_out >= OLLAMA_NUM_CTX:
        raise RuntimeError(
            f"Context window exhausted for {model_key}: prompt_eval_count={n_in} "
            f"+ eval_count={n_out} = {n_in + n_out} >= num_ctx={OLLAMA_NUM_CTX} "
            f"(done_reason={data.get('done_reason')!r}). The output is not "
            f"trustworthy; raise OLLAMA_NUM_CTX in config.py."
        )

    return text, usage


class PromptExceedsWindow(Exception):
    """
    The prompt leaves no room for output in the vLLM window. Nothing was sent.
    generate.run_cell records the cell as skipped rather than retrying it: the
    prompt will not get shorter.
    """


def vllm_placeholders(model_keys) -> list:
    """The vLLM keys among these whose config id is still a placeholder."""
    return [k for k in model_keys
            if k in VLLM_MODELS and VLLM_MODELS[k].startswith(VLLM_PLACEHOLDER)]


def vllm_max_tokens(prompt_tokens: int, max_model_len: int = VLLM_MAX_MODEL_LEN) -> int:
    """
    The output budget for one request: whatever the window has left after the
    prompt and a small margin, capped at VLLM_MAX_OUTPUT_TOKENS. Raises
    PromptExceedsWindow when that leaves nothing.
    """
    room = max_model_len - prompt_tokens - VLLM_TOKEN_MARGIN
    if room <= 0:
        raise PromptExceedsWindow(
            f"prompt is {prompt_tokens} tokens; with the {VLLM_TOKEN_MARGIN}-token "
            f"margin that leaves no room for output in max_model_len={max_model_len}"
        )
    return min(room, VLLM_MAX_OUTPUT_TOKENS)


def _vllm_prompt_tokens(model_id: str, messages: list) -> Tuple[int, int]:
    """
    (prompt tokens, the server's max_model_len) from vLLM's /tokenize.

    The count goes through the server's own tokenizer and chat template, with
    the same messages the request will send, so it is exact rather than
    estimated. /tokenize lives at the server root, not under /v1.
    """
    import httpx

    root = VLLM_BASE_URL.rstrip("/")
    if root.endswith("/v1"):
        root = root[:-3]
    try:
        response = httpx.post(
            f"{root}/tokenize",
            json={"model": model_id, "messages": messages,
                  "add_generation_prompt": True, "add_special_tokens": False},
            timeout=httpx.Timeout(60.0, connect=10.0),
        )
    except httpx.RequestError as e:
        raise RuntimeError(f"vLLM unreachable at {root} for {model_id}: "
                           f"{type(e).__name__}: {e}") from e
    if response.status_code != 200:
        raise RuntimeError(f"vLLM /tokenize HTTP {response.status_code} for {model_id}: "
                           f"{response.text[:300]}")
    data = response.json()
    return data["count"], data.get("max_model_len")


def _call_vllm(prompt: str, system: str, model_key: str) -> Tuple[str, dict]:
    """
    Generation on a vLLM server through its OpenAI-compatible API.

    The prompt is counted first, and max_tokens is set to what the window has
    left (see vllm_max_tokens). A prompt that leaves no room is never sent.
    Unlike Ollama, running out of output budget is flagged rather than raised,
    as it is for the cloud models: finish_reason "length" sets `truncated`.
    No temperature is set, as for every other model: each runs at its server's
    default.
    """
    model_id = MODELS[model_key]
    if vllm_placeholders([model_key]):
        raise ValueError(
            f"{model_key} has no Hugging Face id yet ({model_id!r}). "
            f"Fill it in under VLLM_MODELS in config.py."
        )

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]
    n_in, server_len = _vllm_prompt_tokens(model_id, messages)
    if server_len and server_len != VLLM_MAX_MODEL_LEN:
        raise RuntimeError(
            f"vLLM reports max_model_len={server_len} for {model_id}, but "
            f"VLLM_MAX_MODEL_LEN is {VLLM_MAX_MODEL_LEN}. Make them match "
            f"(config.py or the VLLM_MAX_MODEL_LEN env var, or the server's "
            f"--max-model-len)."
        )
    max_tokens = vllm_max_tokens(n_in)

    response = _get_vllm().chat.completions.create(
        model=model_id,
        max_tokens=max_tokens,
        messages=messages,
    )
    text = response.choices[0].message.content or ""
    reason = _reason_text(getattr(response.choices[0], "finish_reason", None))
    usage = {
        "input_tokens": response.usage.prompt_tokens,
        "output_tokens": response.usage.completion_tokens,
        "max_tokens": max_tokens,
        "stop_reason": reason,
        "truncated": is_truncated("vllm", reason),
    }
    if not text.strip():
        raise RuntimeError(
            f"vLLM returned an empty response for {model_key} (finish_reason="
            f"{reason!r}, completion_tokens={usage['output_tokens']}, "
            f"max_tokens={max_tokens})."
        )
    return text, usage


# ──────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────

_DISPATCH = {
    "claude": _call_claude,
    "gpt": _call_gpt,
    "gemini": _call_gemini,
    # all four local models share one function; bind the key so call_model
    # can keep its single-argument dispatch
    **{k: partial(_call_ollama, model_key=k) for k in LOCAL_MODELS},
    **{k: partial(_call_vllm, model_key=k) for k in VLLM_MODELS},
}


def call_model(model_key: str, prompt: str, language: str = "Java") -> Tuple[str, dict]:
    """
    Call the named model with the given prompt.

    Args:
        model_key: any key of config.MODELS
        prompt:    full user prompt text
        language:  source language of the file being repaired; selects the
                   system prompt and fence cleanup. The default is what the
                   Vul4J cells used.

    Returns:
        (response_text, usage_dict)
        usage_dict has keys: input_tokens, output_tokens, latency_s
    """
    if model_key not in _DISPATCH:
        raise ValueError(f"Unknown model_key: {model_key!r}. Use one of {list(_DISPATCH)}.")
    if language not in SYSTEM_PROMPTS:
        raise ValueError(f"Unknown language: {language!r}. Use one of {list(SYSTEM_PROMPTS)}.")

    start = time.time()
    text, usage = _DISPATCH[model_key](prompt, SYSTEM_PROMPTS[language])
    usage["latency_s"] = round(time.time() - start, 2)
    # Always present, whatever the provider reported, so every caller and every
    # log can rely on them.
    usage.setdefault("stop_reason", "")
    usage.setdefault("truncated", False)
    strip = _strip_markdown_fences if language == "Java" else _strip_outer_fence
    return strip(text), usage


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