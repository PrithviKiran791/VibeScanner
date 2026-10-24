"""Open a fix PR on GitHub from a stored finding (PRD FR-4.2).

Flow: read the default branch's current copy of the file -> rebuild the fix on it (span
remediation for secrets, strict diff re-apply otherwise) -> branch -> commit -> PR. If the token
can't push to the repo, the branch lives on a fork and the PR goes upstream from there.
"""

from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from vibeguard.engine.ingest.workspace import parse_github_url
from vibeguard.engine.models import Remediation
from vibeguard.engine.patch import apply_unified_diff
from vibeguard.engine.remediation import apply_remediation

API = "https://api.github.com"


class GitHubError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class NoFixError(Exception):
    pass


@dataclass(frozen=True)
class FixRequest:
    """Everything the PR flow needs from a finding row; nothing secret."""

    finding_id: str
    repo_url: str
    file_path: str
    rule_id: str
    title: str
    severity: str
    cwe_id: str | None
    line_start: int
    explanation: str
    unified_diff: str | None
    remediation: Remediation | None
    # Shown in the PR body when there's no CWE ("Error Hygiene" for a code-quality fix)
    category: str = "Security"


@dataclass(frozen=True)
class OpenedPR:
    number: int
    url: str
    branch: str


class GitHubClient:
    def __init__(
        self,
        token: str,
        transport: httpx.AsyncBaseTransport | None = None,
        fork_poll_interval_s: float = 2.0,
        fork_poll_attempts: int = 10,
    ) -> None:
        self._http = httpx.AsyncClient(
            base_url=API,
            transport=transport,
            timeout=15.0,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "VibeGuard",
            },
        )
        self.fork_poll_interval_s = fork_poll_interval_s
        self.fork_poll_attempts = fork_poll_attempts

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _call(self, method: str, path: str, **kw: Any) -> Any:
        try:
            resp = await self._http.request(method, path, **kw)
        except httpx.HTTPError:
            raise GitHubError("Could not reach GitHub") from None
        if resp.status_code >= 400:
            try:
                message = resp.json().get("message", "")
            except ValueError:
                message = ""
            raise GitHubError(
                f"GitHub {resp.status_code}: {message or 'request failed'}", resp.status_code
            )
        return resp.json() if resp.content else None

    async def repo(self, owner: str, name: str) -> dict[str, Any]:
        return await self._call("GET", f"/repos/{owner}/{name}")

    async def head_sha(self, owner: str, name: str, branch: str) -> str:
        data = await self._call("GET", f"/repos/{owner}/{name}/git/ref/heads/{quote(branch)}")
        return data["object"]["sha"]

    async def file(self, owner: str, name: str, path: str, ref: str) -> tuple[str, str]:
        data = await self._call(
            "GET", f"/repos/{owner}/{name}/contents/{quote(path)}", params={"ref": ref}
        )
        if not isinstance(data, dict) or data.get("type") != "file" or "content" not in data:
            raise GitHubError(f"{path} is not a regular file under 1MB on GitHub")
        raw = base64.b64decode(data["content"])
        try:
            return raw.decode("utf-8"), data["sha"]
        except UnicodeDecodeError:
            raise GitHubError(f"{path} is not UTF-8 text") from None

    async def fork(self, owner: str, name: str) -> tuple[str, str]:
        data = await self._call("POST", f"/repos/{owner}/{name}/forks", json={})
        fork_owner, fork_name = data["owner"]["login"], data["name"]
        # Fork creation is async on GitHub's side; wait until its refs exist
        for _ in range(self.fork_poll_attempts):
            try:
                await self.head_sha(fork_owner, fork_name, data["default_branch"])
                return fork_owner, fork_name
            except GitHubError as exc:
                if exc.status not in (404, 409):
                    raise
            await asyncio.sleep(self.fork_poll_interval_s)
        raise GitHubError("Fork was not ready in time; try again shortly")

    async def create_branch(self, owner: str, name: str, branch: str, sha: str) -> None:
        await self._call(
            "POST",
            f"/repos/{owner}/{name}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": sha},
        )

    async def put_file(
        self, owner: str, name: str, path: str, text: str, blob_sha: str, branch: str, message: str
    ) -> None:
        await self._call(
            "PUT",
            f"/repos/{owner}/{name}/contents/{quote(path)}",
            json={
                "message": message,
                "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
                "sha": blob_sha,
                "branch": branch,
            },
        )

    async def open_pr(
        self, owner: str, name: str, head: str, base: str, title: str, body: str
    ) -> tuple[int, str]:
        data = await self._call(
            "POST",
            f"/repos/{owner}/{name}/pulls",
            json={"title": title, "head": head, "base": base, "body": body},
        )
        return data["number"], data["html_url"]


def build_patched(original: str, fix: FixRequest) -> str:
    """Rebuild the fix on today's copy of the file. Raises on drift."""
    if fix.remediation is not None:
        patched = apply_remediation(original, fix.remediation)
    elif fix.unified_diff:
        patched = apply_unified_diff(original, fix.unified_diff)
    else:
        raise NoFixError("This finding has no automated fix")
    if patched == original:
        raise NoFixError("The fix is already applied on the default branch")
    return patched


def branch_name(fix: FixRequest) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", fix.rule_id.lower()).strip("-")[:40]
    return f"vibeguard/{slug}-{fix.finding_id.replace('-', '')[:8]}"


def pr_body(fix: FixRequest) -> str:
    lines = [
        f"**{fix.severity}** · {fix.cwe_id or fix.category} · `{fix.file_path}:{fix.line_start}`",
        "",
        fix.explanation,
    ]
    if fix.remediation is not None and fix.remediation.env_var_name:
        lines += [
            "",
            f"**Before merging:** set `{fix.remediation.env_var_name}` in your deployment's "
            "environment. If a credential was committed, rotate it now; it is still in git history.",
        ]
    if fix.rule_id == "hallucinated-dependency":
        lines += ["", "Run your package manager afterwards so the lockfile drops the package too."]
    lines += ["", "---", "Opened by VibeGuard. Review the change before merging."]
    return "\n".join(lines)


async def open_fix_pr(client: GitHubClient, fix: FixRequest) -> OpenedPR:
    owner, name = parse_github_url(fix.repo_url)
    info = await client.repo(owner, name)
    base = info["default_branch"]
    base_sha = await client.head_sha(owner, name, base)

    original, blob_sha = await client.file(owner, name, fix.file_path, base_sha)
    patched = build_patched(original, fix)  # before any write: refuse early on drift

    head_owner, head_name = owner, name
    if not info.get("permissions", {}).get("push"):
        head_owner, head_name = await client.fork(owner, name)

    branch = branch_name(fix)
    await client.create_branch(head_owner, head_name, branch, base_sha)
    await client.put_file(
        head_owner,
        head_name,
        fix.file_path,
        patched,
        blob_sha,
        branch,
        message=f"fix(security): {fix.title}" + (f" ({fix.cwe_id})" if fix.cwe_id else ""),
    )
    head = branch if head_owner == owner else f"{head_owner}:{branch}"
    number, url = await client.open_pr(
        owner, name, head, base, f"[VibeGuard] {fix.title}", pr_body(fix)
    )
    return OpenedPR(number=number, url=url, branch=branch)
