from __future__ import annotations

import logging
import uuid
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Response, status
from redis.exceptions import RedisError
from sqlalchemy import case, select
from sqlalchemy.ext.asyncio import AsyncSession

from vibeguard.api.deps import Dispatcher, get_dispatcher, get_github_client, get_redis
from vibeguard.api.enqueue import QueueUnavailableError, ScanAlreadyRunningError, enqueue_scan
from vibeguard.api.ratelimit import rate_limit
from vibeguard.api.schemas import (
    Counts,
    FindingOut,
    FindingUpdate,
    FindingUpdateOut,
    OpenPullRequestOut,
    Progress,
    ScanCreate,
    ScanOut,
    ScoreOut,
)
from vibeguard.config import Settings, get_settings
from vibeguard.db.models import (
    Finding,
    FindingStatus,
    PullRequest,
    Scan,
    ScanSource,
)
from vibeguard.db.scoring import apply_score
from vibeguard.db.session import get_session
from vibeguard.engine.ingest.workspace import IngestError
from vibeguard.engine.models import Remediation as RemediationSpec
from vibeguard.engine.models import Severity
from vibeguard.engine.patch import PatchMismatchError
from vibeguard.engine.remediation import RemediationMismatchError
from vibeguard.integrations.github import (
    FixRequest,
    GitHubClient,
    GitHubError,
    NoFixError,
    open_fix_pr,
)
from vibeguard.worker.contracts import TargetSource, resolve_local_path
from vibeguard.worker.state import job_key

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")

SessionDep = Annotated[AsyncSession, Depends(get_session)]
RedisDep = Annotated[aioredis.Redis, Depends(get_redis)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
DispatchDep = Annotated[Dispatcher, Depends(get_dispatcher)]
GitHubDep = Annotated[GitHubClient | None, Depends(get_github_client)]

# Compare against the column so each value binds as the native enum type: PostgreSQL has no
# `vulnerability_severity = varchar` operator (SQLite never noticed the difference).
SEVERITY_ORDER = case(*((Finding.severity == s, s.rank) for s in Severity), else_=0)


@router.post(
    "/scans",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanOut,
    dependencies=[Depends(rate_limit("scans", lambda s: s.rate_limit_scans_per_minute))],
)
async def create_scan(
    body: ScanCreate,
    response: Response,
    session: SessionDep,
    r: RedisDep,
    settings: SettingsDep,
    dispatch: DispatchDep,
) -> ScanOut:
    target = _target_from(body, settings)
    try:
        scan = await enqueue_scan(target, body.options, session, r, dispatch)
    except ScanAlreadyRunningError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail={"message": str(exc), "scan_id": exc.scan_id}
        ) from None
    except QueueUnavailableError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Task queue unavailable") from None

    response.headers["Location"] = f"/api/v1/scans/{scan.id}"
    return await _scan_out(scan, r)


@router.get("/scans", response_model=list[ScanOut])
async def list_scans(session: SessionDep, r: RedisDep, limit: int = 20) -> list[ScanOut]:
    """Most recent first, for the Scan History view."""
    limit = max(1, min(limit, 100))
    scans = await session.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit))
    return [await _scan_out(scan, r) for scan in scans]


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: uuid.UUID, session: SessionDep, r: RedisDep) -> ScanOut:
    return await _scan_out(await _get_scan(session, scan_id), r)


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
async def list_findings(scan_id: uuid.UUID, session: SessionDep) -> list[Finding]:
    await _get_scan(session, scan_id)
    rows = await session.scalars(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(SEVERITY_ORDER.desc(), Finding.file_path, Finding.line_start)
    )
    return list(rows)


@router.patch(
    "/findings/{finding_id}",
    response_model=FindingUpdateOut,
    dependencies=[Depends(rate_limit("triage", lambda s: s.rate_limit_triage_per_minute))],
)
async def update_finding(
    finding_id: uuid.UUID, body: FindingUpdate, session: SessionDep
) -> FindingUpdateOut:
    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    scan = await _get_scan(session, finding.scan_id)

    finding.status = body.status
    siblings = list(await session.scalars(select(Finding).where(Finding.scan_id == scan.id)))
    apply_score(scan, siblings)
    await session.commit()

    return FindingUpdateOut(
        finding=FindingOut.model_validate(finding),
        scan=ScoreOut(scan_id=scan.id, hardening_score=scan.hardening_score, counts=_counts(scan)),
    )


@router.post(
    "/findings/{finding_id}/pull-request",
    response_model=OpenPullRequestOut,
    dependencies=[Depends(rate_limit("prs", lambda s: s.rate_limit_prs_per_minute))],
)
async def open_pull_request(
    finding_id: uuid.UUID, response: Response, session: SessionDep, github: GitHubDep
) -> OpenPullRequestOut:
    """Apply the finding's fix on a branch and open a PR. Idempotent per finding."""
    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    scan = await _get_scan(session, finding.scan_id)

    created = False
    if finding.pull_request is None:
        if scan.source_type != ScanSource.GITHUB:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only GitHub scans can open PRs")
        if github is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "GitHub is not configured on this server (set VIBEGUARD_GITHUB_TOKEN)",
            )
        try:
            opened = await open_fix_pr(github, _fix_request(finding, scan))
        except NoFixError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
        except (PatchMismatchError, RemediationMismatchError) as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
        except GitHubError as exc:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from None

        finding.pull_request = PullRequest(
            finding_id=finding.id,
            pr_number=opened.number,
            pr_url=opened.url,
            branch_name=opened.branch,
        )
        finding.status = FindingStatus.PATCH_APPLIED
        siblings = list(await session.scalars(select(Finding).where(Finding.scan_id == scan.id)))
        apply_score(scan, siblings)
        await session.commit()
        created = True

    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return OpenPullRequestOut(
        finding=FindingOut.model_validate(finding),
        scan=ScoreOut(scan_id=scan.id, hardening_score=scan.hardening_score, counts=_counts(scan)),
        created=created,
    )


def _fix_request(finding: Finding, scan: Scan) -> FixRequest:
    rem = finding.remediation
    return FixRequest(
        finding_id=str(finding.id),
        repo_url=scan.repository.url,
        file_path=finding.file_path,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity.value,
        cwe_id=finding.cwe_id,
        line_start=finding.line_start,
        explanation=finding.explanation,
        unified_diff=finding.unified_diff,
        remediation=RemediationSpec(
            kind="replace_span",
            file_path=rem.file_path,
            line=rem.line,
            col_start=rem.col_start,
            col_end=rem.col_end,
            replacement=rem.replacement,
            env_var_name=rem.env_var_name,
            expected_text=rem.expected_text,
            verify_rule=rem.verify_rule,
        )
        if rem is not None
        else None,
    )


def _target_from(body: ScanCreate, settings: Settings) -> TargetSource:
    try:
        if body.repo_url is not None:
            target = TargetSource(kind="github", url=body.repo_url.strip())
            target.canonical  # noqa: B018 - validates the URL shape
            return target
        path = resolve_local_path(body.local_path or "", settings)
        return TargetSource(kind="local", path=str(path))
    except IngestError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None


async def _get_scan(session: AsyncSession, scan_id: uuid.UUID) -> Scan:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


async def _scan_out(scan: Scan, r: aioredis.Redis) -> ScanOut:
    return ScanOut(
        id=scan.id,
        status=scan.status,
        source_type=scan.source_type,
        target=scan.repository.url,
        repository=scan.repository.name,
        commit_hash=scan.commit_hash,
        hardening_score=scan.hardening_score,
        counts=_counts(scan),
        files_scanned=scan.files_scanned,
        llm_used=scan.llm_used,
        warnings=scan.warnings or [],
        duration_ms=scan.duration_ms,
        error_message=scan.error_message,
        progress=None if scan.status.terminal else await _progress(r, str(scan.id)),
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


async def _progress(r: aioredis.Redis, scan_id: str) -> Progress | None:
    try:
        raw = await r.hgetall(job_key(scan_id))
    except RedisError:
        return None  # progress is best-effort; status still comes from PostgreSQL
    data = {
        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
        for k, v in raw.items()
    }
    if "step" not in data:
        return None
    return Progress(step=data["step"], percentage=int(data.get("percentage", 0)))


def _counts(scan: Scan) -> Counts:
    return Counts(
        critical=scan.critical_count,
        high=scan.high_count,
        medium=scan.medium_count,
        low=scan.low_count,
        total=scan.total_findings,
    )
