"""OpenRouter provider (OpenAI-compatible chat completions). Default model: Gemma 4 31B (free).

Responses are streamed: reasoning makes answers slow, and a stream keeps bytes flowing so the
HTTP read timeout measures silence rather than total length. A wall-clock deadline still caps
each request so a slow stream can't outlive the scan budget.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Any

import openai

from vibeguard.engine.llm.provider import LLMError, system_prompt
from vibeguard.engine.llm.schemas import LLMReport, ReportParseError, parse_report

log = logging.getLogger(__name__)

MAX_OUTPUT_TOKENS = 8192
# Reasoning tokens count against max_tokens on OpenRouter: leave room for the thinking too
MAX_OUTPUT_TOKENS_WITH_REASONING = 16384
# How long a model that failed (429, 404, 5xx) is skipped for the rest of the scan
COOLDOWN_S = 60.0


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
        reasoning: bool = True,
        client: Any | None = None,
        fallback_models: Sequence[str] = (),
    ) -> None:
        self.timeout = timeout
        self.reasoning = reasoning
        # Primary first, then fallbacks in order, without duplicates. Free models from different
        # providers rarely saturate at the same time, so a longer chain keeps the pass alive.
        chain = [model, *([fallback_model] if fallback_model else []), *fallback_models]
        self.models = list(dict.fromkeys(m for m in chain if m))
        # model -> monotonic time until which it's skipped. One provider serves a whole scan,
        # so a model that just said 429 isn't asked again for every remaining chunk.
        self._cooldown: dict[str, float] = {}
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
        now = time.monotonic()
        ready = [m for m in self.models if self._cooldown.get(m, 0.0) <= now]
        # Everything cooling down: try them all anyway rather than give up without asking
        for model in ready or self.models:
            try:
                return self._complete(model, prompt)
            except _TryNextModel as exc:
                log.warning("OpenRouter model %s unavailable: %s", model, exc)
                reasons.append(f"{model}: {exc}")
                self._cooldown[model] = time.monotonic() + COOLDOWN_S
        raise LLMError(
            "All LLM models unavailable (" + "; ".join(reasons) + "); semantic pass skipped"
        )

    def _complete(self, model: str, prompt: str) -> LLMReport:
        deadline = time.monotonic() + self.timeout
        extra_body: dict[str, Any] = {}
        if self.reasoning:
            # Think before answering; one turn per chunk, so the reasoning text itself (and
            # reasoning_details for multi-turn) isn't needed back
            extra_body["reasoning"] = {"enabled": True, "exclude": True}
        content: list[str] = []
        finish_reason: str | None = None
        refusal = False
        try:
            stream = self._client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                # Repeatable scans: same code in, same findings out (as far as the host allows)
                temperature=0,
                seed=0,
                max_tokens=MAX_OUTPUT_TOKENS_WITH_REASONING
                if self.reasoning
                else MAX_OUTPUT_TOKENS,
                stream=True,
                extra_body=extra_body or None,
            )
            for chunk in stream:
                if time.monotonic() > deadline:
                    stream.close()
                    raise LLMError(f"Model took longer than {self.timeout:.0f}s; chunk skipped")
                # OpenRouter's final usage chunk (and keep-alives) carry no choices
                if not getattr(chunk, "choices", None):
                    continue
                choice = chunk.choices[0]
                if choice.delta is not None:
                    if choice.delta.content:
                        content.append(choice.delta.content)
                    if getattr(choice.delta, "refusal", None):
                        refusal = True
                if choice.finish_reason:
                    finish_reason = choice.finish_reason
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
        except openai.APIError as exc:
            # The stream started (HTTP 200) and then OpenRouter sent an error event instead
            raise _TryNextModel(f"stream error ({exc.message[:120]})") from None

        if refusal or finish_reason == "content_filter":
            raise LLMError("Model declined this chunk (refusal); semantic pass skipped for it")
        if finish_reason == "length":
            raise LLMError("Model output truncated at max_tokens; chunk discarded")
        if not content and finish_reason is None:
            raise _TryNextModel("empty response")

        try:
            return parse_report("".join(content))
        except ReportParseError as exc:
            # Fallbacks are different models: one of them may well follow the format
            raise _TryNextModel(f"output was not usable JSON ({exc})") from None
