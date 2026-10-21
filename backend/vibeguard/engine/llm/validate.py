"""Hallucination guard: LLM findings must point at real code inside a unit we actually sent.

- Unknown unit, out-of-range lines, or `vulnerable_code` that isn't on those lines -> discarded.
- A `fixed_code` that doesn't parse (Tree-sitter) -> finding kept, patch dropped. A real
  vulnerability without a patch is still worth reporting; a broken patch is not.
"""

from __future__ import annotations

import re

from vibeguard.engine.diff import replace_lines, unified_diff
from vibeguard.engine.llm.schemas import LLMFinding
from vibeguard.engine.models import CodeUnit, Finding, FindingSource, Severity, SourceFile
from vibeguard.engine.syntax.tree import parses_cleanly

_WS = re.compile(r"\s+")


def to_findings(
    raw: list[LLMFinding], units: list[CodeUnit], files: dict[str, SourceFile]
) -> tuple[list[Finding], int]:
    by_id = {u.unit_id: u for u in units}
    accepted: list[Finding] = []
    dropped = 0

    for lf in raw:
        unit = by_id.get(lf.unit_id)
        sf = files.get(unit.file_path) if unit else None
        if unit is None or sf is None or not _location_matches(lf, unit, sf):
            dropped += 1
            continue
        accepted.append(_finding(lf, sf))

    return accepted, dropped


def _location_matches(lf: LLMFinding, unit: CodeUnit, sf: SourceFile) -> bool:
    if not (unit.line_start <= lf.line_start <= lf.line_end <= unit.line_end):
        return False
    actual = "\n".join(sf.lines[lf.line_start - 1 : lf.line_end])
    claimed = _norm(lf.vulnerable_code)
    return bool(claimed) and claimed in _norm(actual)


def _finding(lf: LLMFinding, sf: SourceFile) -> Finding:
    fixed: str | None = None
    diff: str | None = None
    if _norm(lf.fixed_code) and _norm(lf.fixed_code) != _norm(lf.vulnerable_code):
        patched = replace_lines(sf.text, lf.line_start, lf.line_end, lf.fixed_code)
        if sf.language and parses_cleanly(sf.language, patched):
            fixed = lf.fixed_code
            diff = unified_diff(sf.path, sf.text, patched) or None

    return Finding(
        rule_id=f"llm-{lf.category.lower().replace('/', '-').replace(' ', '-')}",
        severity=Severity(lf.severity),
        category=lf.category,
        title=lf.title,
        cwe_id=lf.cwe_id or None,
        file_path=sf.path,
        line_start=lf.line_start,
        line_end=lf.line_end,
        snippet_original=sf.snippet(lf.line_start, lf.line_end, context=0),
        snippet_fixed=fixed,
        unified_diff=diff,
        explanation=lf.explanation,
        source=FindingSource.LLM,
    )


def _norm(code: str) -> str:
    return _WS.sub(" ", code).strip()
