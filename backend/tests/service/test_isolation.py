"""Multi-tenancy: every scan belongs to the user who started it, and nobody else can reach it."""

from sqlalchemy import select

from tests.auth_helpers import ALLOWED_EMAIL, bearer, mint
from vibeguard.db.models import User
from vibeguard.db.session import sync_session_factory

OTHER_EMAIL = "other@example.com"
ZERO = "00000000-0000-0000-0000-000000000000"


def as_b() -> dict[str, str]:
    return bearer(mint(OTHER_EMAIL, sub="uid-b", user_id="uid-b", name="User B"))


async def _scan_as_a(service, demo_app) -> str:
    resp = await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})
    assert resp.status_code == 202
    await service.run_jobs()
    return resp.json()["id"]


async def test_users_only_see_their_own_scans(service, demo_app):
    service.settings.auth_allowed_emails = [ALLOWED_EMAIL, OTHER_EMAIL]
    sid = await _scan_as_a(service, demo_app)

    mine = (await service.client.get("/api/v1/scans")).json()
    theirs = (await service.client.get("/api/v1/scans", headers=as_b())).json()
    assert [s["id"] for s in mine] == [sid]
    assert theirs == []


async def test_other_users_scans_look_missing(service, demo_app):
    service.settings.auth_allowed_emails = [ALLOWED_EMAIL, OTHER_EMAIL]
    sid = await _scan_as_a(service, demo_app)
    finding = (await service.client.get(f"/api/v1/scans/{sid}/findings")).json()[0]

    attempts = [
        ("GET", f"/api/v1/scans/{sid}", None),
        ("GET", f"/api/v1/scans/{sid}/findings", None),
        ("DELETE", f"/api/v1/scans/{sid}", None),
        ("PATCH", f"/api/v1/findings/{finding['id']}", {"status": "DISMISSED_FALSE_POSITIVE"}),
        ("POST", f"/api/v1/findings/{finding['id']}/pull-request", None),
    ]
    for method, path, body in attempts:
        resp = await service.client.request(method, path, json=body, headers=as_b())
        # Same answer as for an id that doesn't exist: no way to probe for other users' scans
        missing = await service.client.request(
            method, path.replace(sid, ZERO).replace(finding["id"], ZERO), json=body, headers=as_b()
        )
        assert resp.status_code == 404, (method, path)
        assert resp.json() == missing.json()

    # Nothing changed for the owner
    after = (await service.client.get(f"/api/v1/scans/{sid}/findings")).json()
    assert next(f for f in after if f["id"] == finding["id"])["status"] == "OPEN"


async def test_running_scan_conflict_hides_other_users_scan_id(service, demo_app):
    service.settings.auth_allowed_emails = [ALLOWED_EMAIL, OTHER_EMAIL]
    first = await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})

    own = await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})
    other = await service.client.post(
        "/api/v1/scans", json={"local_path": str(demo_app)}, headers=as_b()
    )
    assert own.status_code == other.status_code == 409
    assert own.json()["detail"]["scan_id"] == first.json()["id"]
    assert other.json()["detail"]["scan_id"] is None


async def test_owner_can_delete_a_finished_scan(service, demo_app):
    sid = await _scan_as_a(service, demo_app)
    resp = await service.client.delete(f"/api/v1/scans/{sid}")
    assert resp.status_code == 204
    assert (await service.client.get(f"/api/v1/scans/{sid}")).status_code == 404
    assert (await service.client.get("/api/v1/scans")).json() == []


async def test_running_scan_cannot_be_deleted(service, demo_app):
    resp = await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})
    deleted = await service.client.delete(f"/api/v1/scans/{resp.json()['id']}")
    assert deleted.status_code == 409


async def test_history_summarises_each_scan(service, demo_app):
    sid = await _scan_as_a(service, demo_app)
    [row] = (await service.client.get("/api/v1/scans")).json()
    assert row["id"] == sid and row["status"] == "COMPLETED"
    assert row["counts"] == {
        "critical": 5,
        "high": 2,
        "medium": 0,
        "low": 0,
        "total": 7,
        "patched": 0,
    }
    assert row["duration_ms"] is not None and row["created_at"]


async def test_first_request_creates_the_user_row_and_keeps_it_current(service):
    await service.client.get("/api/v1/scans")
    await service.client.get("/api/v1/scans", headers=bearer(mint(name="Renamed")))
    with sync_session_factory(service.settings.database_url)() as s:
        users = list(s.scalars(select(User)))
    assert [(u.firebase_uid, u.email, u.name) for u in users] == [
        ("uid-123", ALLOWED_EMAIL, "Renamed")
    ]


async def test_github_sign_in_is_allowlisted_by_account_id(service):
    """Firebase never marks GitHub emails verified, so GitHub users are allowed by account id."""
    github = {"sign_in_provider": "github.com", "identities": {"github.com": ["4242"]}}
    token = mint("dev@users.noreply.github.com", email_verified=False, firebase=github)

    denied = await service.client.get("/api/v1/me", headers=bearer(token))
    assert denied.status_code == 403 and "GitHub account 4242" in denied.json()["detail"]

    service.settings.auth_allowed_github_ids = ["4242"]
    assert (await service.client.get("/api/v1/me", headers=bearer(token))).status_code == 200
    with sync_session_factory(service.settings.database_url)() as s:
        assert s.scalar(select(User.github_id)) == "4242"


async def test_github_account_without_a_public_email(service):
    service.settings.auth_allowed_github_ids = ["7"]
    github = {"sign_in_provider": "github.com", "identities": {"github.com": ["7"]}}
    token = mint(drop=("email", "email_verified"), firebase=github)
    resp = await service.client.get("/api/v1/me", headers=bearer(token))
    assert resp.status_code == 200 and resp.json()["email"] is None


async def test_unverified_email_cannot_borrow_an_allowlisted_github_id(service):
    """The id must come from Firebase's signed identities, not from the email."""
    service.settings.auth_allowed_github_ids = ["4242"]
    resp = await service.client.get(
        "/api/v1/me", headers=bearer(mint("4242@example.com", email_verified=False))
    )
    assert resp.status_code == 403
