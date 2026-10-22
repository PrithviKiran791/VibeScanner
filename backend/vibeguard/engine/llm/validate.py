"""Hallucination guard: LLM findings must point at real code inside a unit we actually sent.

- A file/line range outside every unit we sent, or `vulnerable_code` that isn't on those lines
  -> discarded.
- A `suggested_patch` that doesn't parse (Tree-sitter) -> finding kept, patch dropped. A real
  vulnerability without a patch is still worth reporting; a broken patch is not.
"""

from __future__ import annotations

import re

from vibeguard.engine.diff import replace_lines, unified_diff
from vibeguard.engine.llm.schemas import LLMFinding
from vibeguard.engine.models import CodeUnit, Finding, FindingSource, Severity, SourceFile
from vibeguard.engine.syntax.tree import parses_cleanly

_WS = re.compile(r"\s+")
_SLUG = re.compile(r"[^a-z0-9]+")


def to_findings(
    raw: list[LLMFinding], units: list[CodeUnit], files: dict[str, SourceFile]
) -> tuple[list[Finding], int]:
    accepted: list[Finding] = []
    dropped = 0

    for lf in raw:
        sf = files.get(lf.file_path)
        if sf is None or _enclosing_unit(lf, units) is None or not _evidence_matches(lf, sf):
            dropped += 1
            continue
        accepted.append(_finding(lf, sf))

    return accepted, dropped


def _enclosing_unit(lf: LLMFinding, units: list[CodeUnit]) -> CodeUnit | None:
    """Only code we actually sent may be reported on (never .env files, components, libs)."""
    return next(
        (
            u
            for u in units
            if u.file_path == lf.file_path
            and u.line_start <= lf.line_start <= lf.line_end <= u.line_end
        ),
        None,
    )


def _evidence_matches(lf: LLMFinding, sf: SourceFile) -> bool:
    actual = "\n".join(sf.lines[lf.line_start - 1 : lf.line_end])
    claimed = _norm(lf.vulnerable_code)
    return bool(claimed) and claimed in _norm(actual)


def _finding(lf: LLMFinding, sf: SourceFile) -> Finding:
    fixed: str | None = None
    diff: str | None = None
    if _norm(lf.suggested_patch) and _norm(lf.suggested_patch) != _norm(lf.vulnerable_code):
        patched = replace_lines(sf.text, lf.line_start, lf.line_end, lf.suggested_patch)
        if sf.language and parses_cleanly(sf.language, patched):
            fixed = lf.suggested_patch
            diff = unified_diff(sf.path, sf.text, patched) or None

    return Finding(
        rule_id="llm-" + (_SLUG.sub("-", lf.category.lower()).strip("-") or "finding"),
        severity=Severity(lf.severity),
        category=lf.category,
        title=lf.title,
        cwe_id=lf.cwe_id,
        file_path=sf.path,
        line_start=lf.line_start,
        line_end=lf.line_end,
        snippet_original=sf.snippet(lf.line_start, lf.line_end, context=0),
        snippet_fixed=fixed,
        unified_diff=diff,
        explanation=lf.description,
        source=FindingSource.LLM,
    )


def _norm(code: str) -> str:
    return _WS.sub(" ", code).strip()
