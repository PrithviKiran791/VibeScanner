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
        lines += [
            f"## {i}. [{f.severity}] {f.title}",
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
