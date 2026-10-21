"""Persistence-side scoring: only OPEN findings cost points, so triage moves the score."""

from __future__ import annotations

from collections.abc import Iterable

from vibeguard.db.models import Finding, FindingStatus, Scan
from vibeguard.engine.scoring import PENALTIES


def apply_score(scan: Scan, findings: Iterable[Finding]) -> None:
    open_findings = [f for f in findings if f.status == FindingStatus.OPEN]
    scan.hardening_score = max(0, 100 - sum(PENALTIES[f.severity] for f in open_findings))
    scan.total_findings = len(open_findings)
    for sev in ("critical", "high", "medium", "low"):
        setattr(
            scan, f"{sev}_count", sum(1 for f in open_findings if f.severity.value.lower() == sev)
        )
