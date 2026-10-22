"""Output contract for the semantic pass, and a tolerant parser for JSON-mode responses.

JSON mode (`response_format={"type": "json_object"}`) guarantees syntactically valid JSON, not
this schema, so each finding is validated on its own: one malformed finding is dropped and
counted instead of discarding the whole chunk.
"""

from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator


class LLMFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    title: str = Field(min_length=1, max_length=255)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    file_path: str = Field(min_length=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    description: str = Field(min_length=1)
    cwe_id: str | None = None
    # Replacement for exactly lines line_start..line_end; "" when no safe patch exists
    suggested_patch: str = ""
    # Evidence: the vulnerable lines copied verbatim. The hallucination guard checks it against
    # the real file, so a finding without it is rejected.
    vulnerable_code: str = Field(min_length=1)
    category: str = Field(default="Security Issue", max_length=128)

    @field_validator("severity", mode="before")
    @classmethod
    def _upper(cls, v: object) -> object:
        return v.strip().upper() if isinstance(v, str) else v

    @field_validator("file_path")
    @classmethod
    def _posix(cls, v: str) -> str:
        return v.strip().replace("\\", "/").removeprefix("./")

    @field_validator("cwe_id", mode="before")
    @classmethod
    def _cwe(cls, v: object) -> object:
        if isinstance(v, int):
            return f"CWE-{v}"
        if isinstance(v, str) and v.strip().isdigit():
            return f"CWE-{v.strip()}"
        return v or None


class LLMReport(BaseModel):
    findings: list[LLMFinding]
    _rejected: int = PrivateAttr(default=0)

    @property
    def rejected(self) -> int:
        """Findings present in the response that failed validation."""
        return self._rejected


class ReportParseError(ValueError):
    pass


_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.S)


def parse_report(text: str) -> LLMReport:
    data = _load_json_object(text)
    raw = data.get("findings")
    if not isinstance(raw, list):
        raise ReportParseError('Response has no "findings" list')

    findings: list[LLMFinding] = []
    rejected = 0
    for item in raw:
        try:
            findings.append(LLMFinding.model_validate(item))
        except ValidationError:
            rejected += 1
    report = LLMReport(findings=findings)
    report._rejected = rejected
    return report


def _load_json_object(text: str) -> dict:
    s = text.strip()
    if m := _FENCE.match(s):  # some models wrap JSON in a code fence even in JSON mode
        s = m.group(1)
    try:
        data = json.loads(s)
    except json.JSONDecodeError:
        start, end = s.find("{"), s.rfind("}")
        if start == -1 or end <= start:
            raise ReportParseError("Response is not JSON") from None
        try:
            data = json.loads(s[start : end + 1])
        except json.JSONDecodeError:
            raise ReportParseError("Response is not valid JSON") from None
    if not isinstance(data, dict):
        raise ReportParseError("Response JSON is not an object")
    return data
