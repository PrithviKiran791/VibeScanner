"""One-click PR flow against an in-memory fake of the GitHub REST API."""

import base64
import contextlib
import json
import re

import httpx
import pytest

from tests.fixtures.materialize import DEMO_STRIPE_KEY
from vibeguard.api.deps import get_github_client
from vibeguard.engine.ingest.workspace import Workspace
from vibeguard.integrations.github import GitHubClient
from vibeguard.worker import tasks

UPSTREAM = ("acme", "vibe-app")


class FakeGitHub:
    def __init__(self, files: dict[str, str], can_push: bool = True, status: int | None = None):
        self.files = dict(files)
        self.can_push = can_push
        self.forced_status = status
        self.refs: dict[tuple[str, str, str], str] = {(*UPSTREAM, "main"): "base-sha"}
        self.commits: list[dict] = []
        self.pulls: list[dict] = []
        self.calls: list[str] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, req: httpx.Request) -> httpx.Response:
        path, method = req.url.path, req.method
        self.calls.append(f"{method} {path}")
        if self.forced_status:
            return httpx.Response(self.forced_status, json={"message": "Bad credentials"})
        body = json.loads(req.content) if req.content else {}

        if m := re.fullmatch(r"/repos/([^/]+)/([^/]+)", path):
            return httpx.Response(
                200,
                json={"default_branch": "main", "permissions": {"push": self.can_push}},
            )
        if m := re.fullmatch(r"/repos/([^/]+)/([^/]+)/git/ref/heads/(.+)", path):
            sha = self.refs.get((m[1], m[2], m[3]))
            return (
                httpx.Response(200, json={"object": {"sha": sha}}) if sha else httpx.Response(404)
            )
        if m := re.fullmatch(r"/repos/([^/]+)/([^/]+)/contents/(.+)", path):
            if method == "GET":
                text = self.files.get(m[3])
                if text is None:
                    return httpx.Response(404, json={"message": "Not Found"})
                content = base64.encodebytes(text.encode()).decode()  # GitHub wraps at 60 cols
                return httpx.Response(
                    200, json={"type": "file", "content": content, "sha": "blob-1"}
                )
            self.commits.append({"owner": m[1], "path": m[3], **body})
            return httpx.Response(200, json={"commit": {"sha": "new"}})
        if m := re.fullmatch(r"/repos/([^/]+)/([^/]+)/git/refs", path):
            self.refs[(m[1], m[2], body["ref"].removeprefix("refs/heads/"))] = body["sha"]
            return httpx.Response(201, json={})
        if m := re.fullmatch(r"/repos/([^/]+)/([^/]+)/forks", path):
            self.refs[("vibe-bot", m[2], "main")] = "base-sha"
            return httpx.Response(
                202, json={"owner": {"login": "vibe-bot"}, "name": m[2], "default_branch": "main"}
            )
        if m := re.fullmatch(r"/repos/([^/]+)/([^/]+)/pulls", path):
            self.pulls.append(body)
            n = len(self.pulls)
            return httpx.Response(
                201, json={"number": n, "html_url": f"https://github.com/acme/vibe-app/pull/{n}"}
            )
        return httpx.Response(404, json={"message": f"unhandled {method} {path}"})


async def _github_scan(service, demo_app, monkeypatch) -> list[dict]:
    @contextlib.contextmanager
    def fake_clone(url, token=None, timeout_s=30, max_bytes=None):
        yield Workspace(root=demo_app, target="acme/vibe-app", commit_hash="c" * 40)

    monkeypatch.setattr(tasks, "github_workspace", fake_clone)
    sid = (
        await service.client.post(
            "/api/v1/scans",
            json={"repo_url": "https://github.com/acme/vibe-app", "options": {"llm": False}},
        )
    ).json()["id"]
    await service.run_jobs()
    return (await service.client.get(f"/api/v1/scans/{sid}/findings")).json()


def _use(service, gh: FakeGitHub | None) -> None:
    async def dep():
        if gh is None:
            yield None
            return
        client = GitHubClient("t", transport=gh.transport(), fork_poll_interval_s=0)
        yield client
        await client.aclose()

    service.client._transport.app.dependency_overrides[get_github_client] = dep


def _files(demo_app) -> dict[str, str]:
    return {
        p.relative_to(demo_app).as_posix(): p.read_text(encoding="utf-8")
        for p in demo_app.rglob("*")
        if p.is_file()
    }


def _by_rule(findings, rule):
    return next(f for f in findings if f["rule_id"] == rule)


async def test_secret_fix_pr_uses_remediation_and_never_leaks_key(service, demo_app, monkeypatch):
    findings = await _github_scan(service, demo_app, monkeypatch)
    gh = FakeGitHub(_files(demo_app))
    _use(service, gh)
    stripe = _by_rule(findings, "stripe-secret-key")

    resp = await service.client.post(f"/api/v1/findings/{stripe['id']}/pull-request")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["created"] is True
    assert body["finding"]["status"] == "PATCH_APPLIED"
    assert body["finding"]["pull_request"]["pr_url"] == "https://github.com/acme/vibe-app/pull/1"
    assert body["scan"]["counts"]["critical"] == 3  # patched findings stop costing points

    [commit] = gh.commits
    new_text = base64.b64decode(commit["content"]).decode()
    assert "new Stripe(process.env.STRIPE_SECRET_KEY!," in new_text
    assert DEMO_STRIPE_KEY not in new_text
    assert commit["branch"].startswith("vibeguard/stripe-secret-key-") and commit["sha"] == "blob-1"

    [pr] = gh.pulls
    assert pr["head"] == commit["branch"] and pr["base"] == "main"
    assert "STRIPE_SECRET_KEY" in pr["body"] and "rotate it" in pr["body"]
    assert DEMO_STRIPE_KEY not in json.dumps(gh.pulls)

    # Idempotent: no second PR, no GitHub traffic
    calls = len(gh.calls)
    again = await service.client.post(f"/api/v1/findings/{stripe['id']}/pull-request")
    assert again.status_code == 200 and again.json()["created"] is False
    assert len(gh.calls) == calls


async def test_diff_fix_pr_reapplies_stored_patch(service, demo_app, monkeypatch):
    findings = await _github_scan(service, demo_app, monkeypatch)
    gh = FakeGitHub(_files(demo_app))
    _use(service, gh)
    sql = _by_rule(findings, "sql-string-interpolation")

    assert (
        await service.client.post(f"/api/v1/findings/{sql['id']}/pull-request")
    ).status_code == 201
    new_text = base64.b64decode(gh.commits[0]["content"]).decode()
    assert (
        'db.query("SELECT id, title FROM posts WHERE title LIKE $1 LIMIT 20", [`%${q}%`])'
        in new_text
    )


async def test_drifted_file_is_refused_without_writing(service, demo_app, monkeypatch):
    findings = await _github_scan(service, demo_app, monkeypatch)
    files = _files(demo_app)
    files["app/api/search/route.ts"] = files["app/api/search/route.ts"].replace(
        "LIMIT 20", "LIMIT 50"
    )
    gh = FakeGitHub(files)
    _use(service, gh)
    sql = _by_rule(findings, "sql-string-interpolation")

    resp = await service.client.post(f"/api/v1/findings/{sql['id']}/pull-request")
    assert resp.status_code == 409
    assert gh.commits == [] and gh.pulls == [] and not any("git/refs" in c for c in gh.calls)


async def test_no_push_access_goes_through_a_fork(service, demo_app, monkeypatch):
    findings = await _github_scan(service, demo_app, monkeypatch)
    gh = FakeGitHub(_files(demo_app), can_push=False)
    _use(service, gh)
    xss = _by_rule(findings, "react-dangerously-set-inner-html")

    assert (
        await service.client.post(f"/api/v1/findings/{xss['id']}/pull-request")
    ).status_code == 201
    assert gh.commits[0]["owner"] == "vibe-bot"
    assert gh.pulls[0]["head"].startswith("vibe-bot:vibeguard/")


@pytest.mark.parametrize(
    ("gh", "rule", "expected"),
    [
        (None, "stripe-secret-key", 503),  # no token configured
        ("unfixable", "shell-command-injection", 422),
        ("bad-token", "stripe-secret-key", 502),
    ],
)
async def test_pr_error_mapping(service, demo_app, monkeypatch, gh, rule, expected):
    findings = await _github_scan(service, demo_app, monkeypatch)
    fake = None
    if gh == "unfixable":
        fake = FakeGitHub(_files(demo_app))
    elif gh == "bad-token":
        fake = FakeGitHub(_files(demo_app), status=401)
    _use(service, fake)
    resp = await service.client.post(
        f"/api/v1/findings/{_by_rule(findings, rule)['id']}/pull-request"
    )
    assert resp.status_code == expected, resp.text


async def test_local_scans_cannot_open_prs(service, demo_app):
    sid = (await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})).json()[
        "id"
    ]
    await service.run_jobs()
    findings = (await service.client.get(f"/api/v1/scans/{sid}/findings")).json()
    _use(service, FakeGitHub({}))
    resp = await service.client.post(f"/api/v1/findings/{findings[0]['id']}/pull-request")
    assert resp.status_code == 400


async def test_scan_history_lists_newest_first(service, demo_app, monkeypatch):
    await _github_scan(service, demo_app, monkeypatch)
    await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})
    history = (await service.client.get("/api/v1/scans?limit=5")).json()
    assert [s["source_type"] for s in history] == ["LOCAL", "GITHUB"]
    assert history[0]["status"] == "QUEUED" and history[0]["progress"]["step"] == "QUEUED"
