"""Structured output contract for the semantic pass. The provider must return exactly this."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

LLMCategory = Literal[
    "Broken Access Control",
    "Broken Authentication",
    "Injection",
    "Prompt Injection",
    "Client/Server Boundary Leak",
    "Mass Assignment",
    "Business Logic",
    "Security Misconfiguration",
]


class LLMFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unit_id: str = Field(description="The id attribute of the <unit> the issue is in.")
    title: str = Field(description="At most 6 words, e.g. 'IDOR On User Profile Fetch'.")
    category: LLMCategory
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    cwe_id: str = Field(description="e.g. 'CWE-639'.")
    line_start: int = Field(description="First vulnerable line, from the gutter numbers.")
    line_end: int = Field(description="Last vulnerable line, from the gutter numbers.")
    vulnerable_code: str = Field(
        description="Lines line_start..line_end copied verbatim, no gutter."
    )
    fixed_code: str = Field(
        description="Drop-in replacement for exactly lines line_start..line_end, same indentation."
    )
    explanation: str = Field(
        description="Exactly two plain-English sentences: impact, then root cause."
    )


class LLMReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[LLMFinding]


def inline_json_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Pydantic schema with $refs inlined, for providers that dislike $defs."""
    schema = model.model_json_schema()
    defs = schema.pop("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                return resolve(defs[node["$ref"].rsplit("/", 1)[-1]])
            return {k: resolve(v) for k, v in node.items()}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    return resolve(schema)
