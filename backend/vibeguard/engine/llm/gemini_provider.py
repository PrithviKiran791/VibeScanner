"""Gemini provider (optional extra: `pip install -e .[gemini]`). Not covered by the test suite."""

from __future__ import annotations

from pydantic import ValidationError

from vibeguard.engine.llm.provider import LLMError, system_prompt
from vibeguard.engine.llm.schemas import LLMReport


class GeminiProvider:
    name = "gemini"

    def __init__(self, model: str, api_key: str) -> None:
        try:
            from google import genai
        except ImportError as exc:
            raise LLMError("google-genai is not installed; run pip install -e .[gemini]") from exc
        self.model = model
        self._client = genai.Client(api_key=api_key)

    def analyze(self, prompt: str) -> LLMReport:
        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=prompt,
                config={
                    "system_instruction": system_prompt(),
                    "response_mime_type": "application/json",
                    "response_schema": LLMReport,
                },
            )
        except Exception as exc:  # google-genai raises a broad family of errors
            raise LLMError(f"Gemini request failed: {type(exc).__name__}") from exc
        try:
            return LLMReport.model_validate_json(response.text or "")
        except ValidationError as exc:
            raise LLMError("Gemini output failed schema validation") from exc
