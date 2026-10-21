from __future__ import annotations

from typing import Any

import anthropic
from pydantic import ValidationError

from vibeguard.engine.llm.provider import LLMError, system_prompt
from vibeguard.engine.llm.schemas import LLMReport, inline_json_schema

# Security review prompts can trip safety classifiers; let the API re-route a declined request
# to a suitable model inside the same call instead of silently losing the semantic pass.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        model: str = "claude-opus-5-5",
        effort: str = "medium",
        api_key: str | None = None,
        timeout: float = 45.0,
        client: Any | None = None,
    ) -> None:
        self.model = model
        self.effort = effort
        # No explicit key: the SDK resolves ANTHROPIC_API_KEY / `ant auth login` profiles itself.
        self._client = client or anthropic.Anthropic(
            **({"api_key": api_key} if api_key else {}), timeout=timeout, max_retries=1
        )
        self._schema = inline_json_schema(LLMReport)

    def analyze(self, prompt: str) -> LLMReport:
        try:
            response = self._client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system_prompt(),
                messages=[{"role": "user", "content": prompt}],
                output_config={
                    "effort": self.effort,
                    "format": {"type": "json_schema", "schema": self._schema},
                },
                betas=[FALLBACK_BETA],
                fallbacks="default",
            )
        except anthropic.AuthenticationError as exc:
            raise LLMError("Anthropic credentials rejected; semantic pass skipped") from exc
        except anthropic.RateLimitError as exc:
            raise LLMError("Anthropic rate limit hit; semantic pass skipped") from exc
        except anthropic.APIStatusError as exc:
            raise LLMError(f"Anthropic API error {exc.status_code}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError("Could not reach the Anthropic API") from exc
        except anthropic.AnthropicError as exc:
            raise LLMError(f"Anthropic client error: {exc}") from exc
        except TypeError as exc:
            # The SDK raises TypeError (not an API error) when no credentials resolve at all
            if "authentication method" not in str(exc):
                raise
            raise LLMError(
                "No Anthropic credentials configured (set ANTHROPIC_API_KEY); semantic pass skipped"
            ) from None

        if response.stop_reason == "refusal":
            raise LLMError("Model declined this chunk (refusal); semantic pass skipped for it")
        if response.stop_reason == "max_tokens":
            raise LLMError("Model output truncated at max_tokens; chunk discarded")

        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise LLMError("Model returned no text block")
        try:
            return LLMReport.model_validate_json(text)
        except ValidationError as exc:
            raise LLMError("Model output failed schema validation") from exc
