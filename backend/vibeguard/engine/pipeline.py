"""The hybrid scan pipeline (app_flow steps 5–9). Framework-free: the CLI and Celery both call this."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Literal

import httpx

from vibeguard.config import Settings
from vibeguard.engine.ingest.file_index import index_files
from vibeguard.engine.ingest.workspace import Workspace
from vibeguard.engine.llm.provider import (
    LLMError,
    LLMProvider,
    build_prompt,
    chunk_units,
    get_provider,
)
from vibeguard.engine.llm.schemas import LLMFinding
from vibeguard.engine.llm.validate import to_findings
from vibeguard.engine.merge import merge_findings
from vibeguard.engine.models import CodeUnit, Finding, ScanResult
from vibeguard.engine.scoring import count_by_severity, hardening_index
from vibeguard.engine.static.deps import ExistenceCache, scan_dependencies
from vibeguard.engine.static.secrets import scan_secrets
from vibeguard.engine.static.sinks import scan_sinks
from vibeguard.engine.syntax.routes import extract_units, select_for_llm

log = logging.getLogger(__name__)

Progress = Callable[[str, int], None]
AUTO: Literal["auto"] = "auto"


def run_scan(
    workspace: Workspace,
    settings: Settings,
    provider: LLMProvider | None | Literal["auto"] = AUTO,
    progress: Progress | None = None,
    registry_cache: ExistenceCache | None = None,
    registry_transport: httpx.AsyncBaseTransport | None = None,
) -> ScanResult:
    started = time.monotonic()
    deadline = started + settings.scan_deadline_s
    report = progress or (lambda _stage, _pct: None)
    warnings: list[str] = []

    report("INDEXING", 5)
    files = index_files(workspace.root, settings.max_repo_bytes, settings.max_file_bytes)
    by_path = {f.path: f for f in files}

    # Pass 1: deterministic
    report("ANALYZING_STATIC", 15)
    static: list[Finding] = []
    for sf in files:
        static.extend(scan_secrets(sf))
        static.extend(scan_sinks(sf))
    if settings.registry_check:
        static.extend(
            scan_dependencies(
                files, registry_cache, settings.registry_timeout_s, transport=registry_transport
            )
        )

    # Pass 2: relevance pruning
    report("PRUNING", 35)
    all_units = [u for sf in files for u in extract_units(sf)]
    selected = select_for_llm(all_units, settings.llm_max_units)
    middleware = next((u for u in all_units if u.kind == "middleware"), None)

    # Pass 3: semantic LLM review
    llm: list[Finding] = []
    llm_used = False
    if provider == AUTO:
        try:
            provider = get_provider(settings)
        except LLMError as exc:
            warnings.append(str(exc))
            provider = None
    if provider is None:
        warnings.append("LLM pass disabled: deterministic findings only")
    elif selected:
        report("ANALYZING_LLM", 50)
        raw, ok_chunks, llm_warnings = _run_llm(provider, selected, middleware, settings, deadline)
        warnings.extend(llm_warnings)
        llm, dropped = to_findings(raw, selected, by_path)
        llm_used = ok_chunks > 0
        if dropped:
            warnings.append(f"Discarded {dropped} LLM finding(s) that did not match the source")

    # Aggregate + score
    report("SCORING", 90)
    findings = merge_findings(static, llm)
    result = ScanResult(
        target=workspace.target,
        commit_hash=workspace.commit_hash,
        files_scanned=len(files),
        units_analyzed=len(selected) if llm_used else 0,
        llm_used=llm_used,
        hardening_score=hardening_index(findings),
        counts=count_by_severity(findings),
        findings=findings,
        warnings=warnings,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    report("COMPLETED", 100)
    return result


def _run_llm(
    provider: LLMProvider,
    units: list[CodeUnit],
    middleware: CodeUnit | None,
    settings: Settings,
    deadline: float,
) -> tuple[list[LLMFinding], int, list[str]]:
    """Returns (raw findings, number of chunks that succeeded, warnings)."""
    chunks = chunk_units(units, settings.llm_chunk_chars)
    warnings: list[str] = []
    raw: list[LLMFinding] = []
    ok = rejected = 0

    pool = ThreadPoolExecutor(max_workers=settings.llm_concurrency)
    futures = [pool.submit(provider.analyze, build_prompt(c, middleware)) for c in chunks]
    done, pending = wait(futures, timeout=max(0.0, deadline - time.monotonic()))
    # Don't block the scan on stragglers; their HTTP calls time out on their own.
    pool.shutdown(wait=False, cancel_futures=True)

    for fut in done:
        try:
            report = fut.result()
            raw.extend(report.findings)
            rejected += report.rejected
            ok += 1
        except LLMError as exc:
            warnings.append(str(exc))
        except Exception:  # a provider bug must not sink the deterministic results
            log.exception("LLM chunk failed")
            warnings.append("An LLM chunk failed unexpectedly")
    if pending:
        warnings.append(f"{len(pending)} LLM chunk(s) skipped: scan deadline reached")
    if rejected:
        warnings.append(f"Discarded {rejected} LLM finding(s) that did not match the output schema")
    return raw, ok, sorted(set(warnings))
