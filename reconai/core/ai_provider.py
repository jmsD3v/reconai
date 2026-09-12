"""
AI Provider — auto-detects the configured AI provider and returns a plain-text completion.

Priority order when multiple keys are set (first one found wins):
    ANTHROPIC_API_KEY > GEMINI_API_KEY > OPENAI_API_KEY

This priority order is shared across the whole portfolio suite (ReconAI, WebHunter,
PhishSim) — keep it identical if this file is touched in another project.

Supported providers:
    - Anthropic Claude   (anthropic SDK)
    - Google Gemini      (google-genai SDK)
    - OpenAI             (openai SDK)
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable

_PROVIDER_ENV_VARS = (
    ("anthropic", "ANTHROPIC_API_KEY"),
    ("gemini", "GEMINI_API_KEY"),
    ("openai", "OPENAI_API_KEY"),
)


def detect_provider() -> tuple[str, str]:
    """Return (provider_name, api_key) for the first configured provider, in priority order."""
    for provider, env_var in _PROVIDER_ENV_VARS:
        api_key = os.getenv(env_var)
        if api_key:
            return provider, api_key

    raise RuntimeError(
        "No AI provider API key set. Set one of: ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY."
    )


async def _complete_anthropic(api_key: str, prompt: str, max_tokens: int) -> str:
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=api_key)
    try:
        message = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
    except anthropic.AuthenticationError as exc:
        raise RuntimeError("invalid ANTHROPIC_API_KEY.") from exc


async def _complete_gemini(api_key: str, prompt: str, max_tokens: int) -> str:
    from google import genai
    from google.genai import errors as genai_errors

    client = genai.Client(api_key=api_key)
    try:
        response = await client.aio.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config={"max_output_tokens": max_tokens},
        )
        return response.text
    except genai_errors.ClientError as exc:
        status = getattr(exc, "code", None)
        if status in (401, 403) or "API_KEY_INVALID" in str(exc):
            raise RuntimeError("invalid GEMINI_API_KEY.") from exc
        raise


async def _complete_openai(api_key: str, prompt: str, max_tokens: int) -> str:
    import openai

    client = openai.AsyncOpenAI(api_key=api_key)
    try:
        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""
    except openai.AuthenticationError as exc:
        raise RuntimeError("invalid OPENAI_API_KEY.") from exc


_COMPLETERS: dict[str, Callable[[str, str, int], Awaitable[str]]] = {
    "anthropic": _complete_anthropic,
    "gemini": _complete_gemini,
    "openai": _complete_openai,
}


async def get_ai_completion(prompt: str, max_tokens: int = 1024) -> str:
    """
    Detect the configured AI provider (by env var priority) and return a raw
    text completion for the given prompt.

    Raises RuntimeError if no provider API key is set, or if the configured
    key is rejected by the provider as invalid.
    """
    provider, api_key = detect_provider()
    return await _COMPLETERS[provider](api_key, prompt, max_tokens)
