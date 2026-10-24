"""Provider-agnostic LLM interface and prompt assembly."""

from __future__ import annotations

from functools import cache
from html import escape
from importlib.resources import files
from typing import Protocol

from vibeguard.config import Settings
from vibeguard.engine.llm.schemas import LLMReport
from vibeguard.engine.models import CodeUnit


class LLMError(Exception):
    """The provider failed; the scan continues deterministic-only and records a warning."""


class LLMProvider(Protocol):
    name: str

    def analyze(self, prompt: str) -> LLMReport: ...


@cache
def system_prompt() -> str:
    return files("vibeguard.engine.llm").joinpath("prompts/security_review.md").read_text("utf-8")


def build_prompt(units: list[CodeUnit], middleware: CodeUnit | None = None) -> str:
    parts = ["Review these entry points and report findings."]
    if middleware is not None:
        parts.append(
            f'<middleware file="{escape(middleware.file_path)}">\n'
            f"{_numbered(middleware.code, middleware.line_start)}\n</middleware>"
        )
    for u in units:
        attrs = (
            f'id="{escape(u.unit_id)}" file="{escape(u.file_path)}" kind="{u.kind}" '
            f'method="{u.http_method or "-"}" lines="{u.line_start}-{u.line_end}"'
        )
        imports = "\n".join(u.imports)
        parts.append(
            f"<unit {attrs}>\n<imports>\n{imports}\n</imports>\n"
            f"<code>\n{_numbered(u.code, u.line_start)}\n</code>\n</unit>"
        )
    return "\n\n".join(parts)


def chunk_units(units: list[CodeUnit], max_chars: int) -> list[list[CodeUnit]]:
    chunks: list[list[CodeUnit]] = []
    current: list[CodeUnit] = []
    size = 0
    for u in units:
        cost = len(u.code) + sum(len(i) for i in u.imports) + 200
        if current and size + cost > max_chars:
            chunks.append(current)
            current, size = [], 0
        current.append(u)
        size += cost
    if current:
        chunks.append(current)
    return chunks


def get_provider(settings: Settings) -> LLMProvider | None:
    timeout = max(5.0, settings.scan_deadline_s - 10)
    if settings.llm_provider == "openrouter":
        if (
            settings.openrouter_api_key is None
            or not settings.openrouter_api_key.get_secret_value()
        ):
            raise LLMError(
                "No OpenRouter API key configured (set OPENROUTER_API_KEY); semantic pass skipped"
            )
        try:
            from vibeguard.engine.llm.openrouter_provider import OpenRouterProvider
        except ImportError as exc:
            raise LLMError("openai is not installed; run pip install -e .[openrouter]") from exc

        return OpenRouterProvider(
            model=settings.resolved_llm_model,
            api_key=settings.openrouter_api_key.get_secret_value(),
            base_url=settings.llm_base_url,
            fallback_model=settings.llm_fallback_model,
            fallback_models=settings.llm_fallback_models,
            app_url=settings.llm_app_url,
            app_name=settings.llm_app_name,
            timeout=timeout,
            reasoning=settings.llm_reasoning,
        )
    if settings.llm_provider == "gemini":
        from vibeguard.engine.llm.gemini_provider import GeminiProvider

        if settings.gemini_api_key is None:
            return None
        return GeminiProvider(
            model=settings.resolved_llm_model, api_key=settings.gemini_api_key.get_secret_value()
        )
    return None


def _numbered(code: str, first_line: int) -> str:
    lines = code.splitlines()
    width = len(str(first_line + len(lines)))
    return "\n".join(f"{first_line + i:>{width}}| {line}" for i, line in enumerate(lines))
