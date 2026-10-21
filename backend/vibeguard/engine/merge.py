"""Merge and deduplicate static + LLM findings."""

from __future__ import annotations

from vibeguard.engine.models import Finding, FindingSource


def merge_findings(static: list[Finding], llm: list[Finding]) -> list[Finding]:
    merged = _dedupe(static)

    for lf in llm:
        twin = next((sf for sf in merged if _same_issue(sf, lf)), None)
        if twin is None:
            merged.append(lf)
            continue
        idx = merged.index(twin)
        merged[idx] = twin.model_copy(
            update={
                "severity": max(twin.severity, lf.severity, key=lambda s: s.rank),
                # Static evidence wins on location; the LLM wins on explanation and fills a
                # missing patch.
                "explanation": lf.explanation,
                "snippet_fixed": twin.snippet_fixed or lf.snippet_fixed,
                "unified_diff": twin.unified_diff or lf.unified_diff,
                "source": FindingSource.MERGED,
            }
        )

    return sorted(merged, key=lambda f: (-f.severity.rank, f.file_path, f.line_start))


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that hit the same lines for the same weakness (e.g. two secret rules)."""
    out: list[Finding] = []
    for f in sorted(findings, key=lambda f: -f.severity.rank):
        if not any(_same_issue(f, kept) for kept in out):
            out.append(f)
    return out


def _same_issue(a: Finding, b: Finding) -> bool:
    if not a.overlaps(b):
        return False
    if a.cwe_id and b.cwe_id:
        return a.cwe_id == b.cwe_id
    return a.category == b.category
