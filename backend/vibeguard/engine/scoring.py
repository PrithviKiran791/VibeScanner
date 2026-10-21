"""Deterministic Hardening Index (PRD FR-3). The LLM never touches the score."""

from __future__ import annotations

from collections.abc import Iterable

from vibeguard.engine.models import Finding, Severity, SeverityCounts

PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def hardening_index(findings: Iterable[Finding]) -> int:
    return max(0, 100 - sum(PENALTIES[f.severity] for f in findings))


def count_by_severity(findings: Iterable[Finding]) -> SeverityCounts:
    counts = SeverityCounts()
    for f in findings:
        attr = f.severity.value.lower()
        setattr(counts, attr, getattr(counts, attr) + 1)
    return counts
