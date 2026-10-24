"""Deterministic Hardening Index (PRD FR-3). The LLM never touches the score."""

from __future__ import annotations

from collections.abc import Iterable

from vibeguard.engine.models import Finding, FindingDomain, Severity, SeverityCounts

PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def hardening_index(findings: Iterable[Finding]) -> int:
    """Security findings only: code-quality smells have their own score (static/quality.py)."""
    return max(0, 100 - sum(PENALTIES[f.severity] for f in _security(findings)))


def count_by_severity(findings: Iterable[Finding]) -> SeverityCounts:
    counts = SeverityCounts()
    for f in _security(findings):
        attr = f.severity.value.lower()
        setattr(counts, attr, getattr(counts, attr) + 1)
    return counts


def _security(findings: Iterable[Finding]) -> Iterable[Finding]:
    return (f for f in findings if f.domain == FindingDomain.SECURITY)
