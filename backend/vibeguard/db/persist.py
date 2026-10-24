"""Map engine results onto ORM rows."""

from __future__ import annotations

from datetime import UTC, datetime

from vibeguard.db.models import Finding, FindingStatus, Remediation, Scan, ScanStatus
from vibeguard.db.scoring import apply_score
from vibeguard.engine.models import ScanResult


def persist_result(scan: Scan, result: ScanResult) -> list[Finding]:
    rows = [
        Finding(
            scan_id=scan.id,
            rule_id=f.rule_id,
            severity=f.severity,
            category=f.category,
            title=f.title,
            cwe_id=f.cwe_id,
            file_path=f.file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            snippet_original=f.snippet_original,
            snippet_fixed=f.snippet_fixed,
            unified_diff=f.unified_diff,
            explanation=f.explanation,
            source=f.source,
            # Explicit for the same reason as status: apply_score filters on it pre-flush
            domain=f.domain,
            # Explicit, not the column default: apply_score reads it before the flush
            status=FindingStatus.OPEN,
            remediation=Remediation(**f.remediation.model_dump()) if f.remediation else None,
        )
        for f in result.findings
    ]
    apply_score(scan, rows)
    if result.quality is not None:
        scan.quality_score = result.quality.score
        scan.quality_grade = result.quality.grade
        scan.quality_breakdown = result.quality.breakdown.model_dump()
    scan.commit_hash = result.commit_hash
    scan.files_scanned = result.files_scanned
    scan.llm_used = result.llm_used
    scan.warnings = result.warnings
    scan.duration_ms = result.duration_ms
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now(UTC)
    return rows
