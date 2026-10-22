"""OpenRouter provider (OpenAI-compatible chat completions). Default model: Gemma 4 31B (free)."""

from __future__ import annotations

import logging
from typing import Any

import openai

from vibeguard.engine.llm.provider import LLMError, system_prompt
from vibeguard.engine.llm.schemas import LLMReport, ReportParseError, parse_report

log = logging.getLogger(__name__)

MAX_OUTPUT_TOKENS = 8192


class _TryNextModel(Exception):
    """This model can't serve the request right now (429, 404, 5xx); the fallback might."""


class OpenRouterProvider:
    name = "openrouter"

    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str = "https://openrouter.ai/api/v1",
        fallback_model: str | None = None,
        app_url: str = "http://localhost:3000",
        app_name: str = "VibeGuard",
        timeout: float = 45.0,
        client: Any | None = None,
    ) -> None:
        self.models = [model] + (
            [fallback_model] if fallback_model and fallback_model != model else []
        )
        self._client = client or openai.OpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            # No SDK retries: waiting out a free-tier 429 would eat the scan deadline; the
            # fallback model is the retry.
            max_retries=0,
            default_headers={"HTTP-Referer": app_url, "X-Title": app_name},
        )

    def analyze(self, prompt: str) -> LLMReport:
        reasons: list[str] = []
        for model in self.models:
            try:
                return self._complete(model, prompt)
            except _TryNextModel as exc:
                log.warning("OpenRouter model %s unavailable: %s", model, exc)
                reasons.append(f"{model}: {exc}")
        raise LLMError(
            "All LLM models unavailable (" + "; ".join(reasons) + "); semantic pass skipped"
        )

    def _complete(self, model: str, prompt: str) -> LLMReport:
        try:
            response = self._client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                # Repeatable scans: same code in, same findings out (as far as the host allows)
                temperature=0,
                seed=0,
                max_tokens=MAX_OUTPUT_TOKENS,
            )
        except openai.AuthenticationError:
            raise LLMError("OpenRouter rejected the API key; semantic pass skipped") from None
        except openai.RateLimitError:
            raise _TryNextModel("rate limited (429)") from None
        except openai.NotFoundError:
            raise _TryNextModel("model not found (404)") from None
        except (openai.APITimeoutError, openai.APIConnectionError):
            raise LLMError("Could not reach OpenRouter; semantic pass skipped") from None
        except openai.APIStatusError as exc:
            if exc.status_code >= 500:
                raise _TryNextModel(f"upstream error ({exc.status_code})") from None
            raise LLMError(f"OpenRouter error {exc.status_code}; semantic pass skipped") from None

        # OpenRouter can return HTTP 200 with an error object and no choices
        if not getattr(response, "choices", None):
            raise _TryNextModel("empty response")
        choice = response.choices[0]
        if getattr(choice.message, "refusal", None) or choice.finish_reason == "content_filter":
            raise LLMError("Model declined this chunk (refusal); semantic pass skipped for it")
        if choice.finish_reason == "length":
            raise LLMError("Model output truncated at max_tokens; chunk discarded")

        try:
            return parse_report(choice.message.content or "")
        except ReportParseError as exc:
            raise LLMError(f"Model output was not usable JSON ({exc})") from None
