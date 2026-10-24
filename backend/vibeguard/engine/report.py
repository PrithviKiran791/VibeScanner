"""Audit report export (PRD FR-4.3)."""

from __future__ import annotations

from vibeguard.engine.models import ScanResult


def to_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def to_markdown(result: ScanResult) -> str:
    c = result.counts
    lines = [
        f"# VibeGuard Audit — {result.target}",
        "",
        f"**Hardening Index: {result.hardening_score}/100**",
        "",
    ]
    if result.quality is not None:
        q, b = result.quality, result.quality.breakdown
        lines += [
            f"**Code Quality: {q.score}/100 ({q.grade})**",
            "",
            "| Modularity | Type safety | Error hygiene | Cleanliness | Architecture |",
            "| :-: | :-: | :-: | :-: | :-: |",
            f"| {b.modularity} | {b.type_safety} | {b.error_hygiene} | {b.cleanliness} "
            f"| {b.architecture} |",
            "",
        ]
    lines += [
        "| Critical | High | Medium | Low |",
        "| :-: | :-: | :-: | :-: |",
        f"| {c.critical} | {c.high} | {c.medium} | {c.low} |",
        "",
        f"Scanned {result.files_scanned} files"
        + (f", {result.units_analyzed} entry points reviewed by LLM" if result.llm_used else "")
        + f" in {result.duration_ms / 1000:.1f}s.",
        "",
    ]
    if result.commit_hash:
        lines += [f"Commit: `{result.commit_hash}`", ""]

    for i, f in enumerate(result.findings, start=1):
        tag = f"{f.severity} smell" if f.domain == "QUALITY" else f.severity
        lines += [
            f"## {i}. [{tag}] {f.title}",
            "",
            f"`{f.file_path}:{f.line_start}` · {f.cwe_id or f.category}",
            "",
            f.explanation,
            "",
        ]
        if f.unified_diff:
            lines += ["```diff", f.unified_diff.rstrip("\n"), "```", ""]

    if result.warnings:
        lines += ["## Scan Notes", ""] + [f"- {w}" for w in result.warnings] + [""]
    return "\n".join(lines)
