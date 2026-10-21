import json
import shutil

from tests.fixtures.materialize import DEMO_STRIPE_KEY
from vibeguard.worker.state import events_channel, lock_key


async def _submit(svc, path):
    resp = await svc.client.post("/api/v1/scans", json={"local_path": str(path)})
    assert resp.status_code == 202, resp.text
    return resp


async def test_full_lifecycle_post_to_persisted_findings(service, demo_app):
    resp = await _submit(service, demo_app)
    scan = resp.json()
    sid = scan["id"]
    assert scan["status"] == "QUEUED" and scan["source_type"] == "LOCAL"
    assert scan["progress"] == {"step": "QUEUED", "percentage": 0}
    assert resp.headers["location"] == f"/api/v1/scans/{sid}"
    assert len(service.jobs) == 1

    pubsub = service.redis.pubsub()
    pubsub.subscribe(events_channel(sid))
    await service.run_jobs()

    done = (await service.client.get(f"/api/v1/scans/{sid}")).json()
    assert done["status"] == "COMPLETED"
    assert done["hardening_score"] == 0
    assert done["counts"] == {"critical": 5, "high": 2, "medium": 0, "low": 0, "total": 7}
    assert done["llm_used"] and done["files_scanned"] == 10
    assert done["duration_ms"] is not None and done["completed_at"] is not None
    assert done["progress"] is None  # terminal scans report from PostgreSQL only

    events = [
        json.loads(m["data"]) for m in iter(pubsub.get_message, None) if m["type"] == "message"
    ]
    assert events[0]["type"] == "PROGRESS" and events[-1]["type"] == "SCAN_COMPLETED"
    assert {"ANALYZING_STATIC", "ANALYZING_LLM"} <= {e["status"] for e in events}

    findings = (await service.client.get(f"/api/v1/scans/{sid}/findings")).json()
    ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    assert [ranks[f["severity"]] for f in findings] == sorted(
        (ranks[f["severity"]] for f in findings), reverse=True
    )
    idor = next(f for f in findings if f["cwe_id"] == "CWE-639")
    assert idor["source"] == "LLM" and idor["unified_diff"]

    stripe = next(f for f in findings if f["rule_id"] == "stripe-secret-key")
    assert stripe["remediation"]["env_var_name"] == "STRIPE_SECRET_KEY"
    assert stripe["remediation"]["replacement"] == "process.env.STRIPE_SECRET_KEY!"
    assert DEMO_STRIPE_KEY not in json.dumps(findings)  # never stored, never served

    # Lock released after the run
    assert service.redis.get(lock_key(str(demo_app.resolve()))) is None


async def test_patch_finding_recalculates_score(service, demo_app):
    sid = (await _submit(service, demo_app)).json()["id"]
    await service.run_jobs()
    findings = (await service.client.get(f"/api/v1/scans/{sid}/findings")).json()
    criticals = [f for f in findings if f["severity"] == "CRITICAL"]

    for f in criticals:
        resp = await service.client.patch(
            f"/api/v1/findings/{f['id']}", json={"status": "DISMISSED_FALSE_POSITIVE"}
        )
        assert resp.status_code == 200
    body = resp.json()
    assert body["finding"]["status"] == "DISMISSED_FALSE_POSITIVE"
    assert body["scan"]["hardening_score"] == 100 - 2 * 12  # only the two HIGHs remain open
    assert body["scan"]["counts"] == {"critical": 0, "high": 2, "medium": 0, "low": 0, "total": 2}

    resp = await service.client.patch(
        f"/api/v1/findings/{criticals[0]['id']}", json={"status": "OPEN"}
    )
    assert resp.json()["scan"]["hardening_score"] == 100 - 24 - 25
    scan = (await service.client.get(f"/api/v1/scans/{sid}")).json()
    assert scan["hardening_score"] == 51  # persisted, not just echoed

    bad = await service.client.patch(
        f"/api/v1/findings/{criticals[0]['id']}", json={"status": "NOPE"}
    )
    assert bad.status_code == 422


async def test_duplicate_scan_is_rejected_until_first_finishes(service, demo_app):
    first = (await _submit(service, demo_app)).json()["id"]
    dup = await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})
    assert dup.status_code == 409
    assert dup.json()["detail"]["scan_id"] == first

    await service.run_jobs()
    await _submit(service, demo_app)


async def test_input_validation(service, demo_app, tmp_path):
    post = service.client.post
    cases = [
        {},
        {"repo_url": "https://github.com/a/b", "local_path": str(demo_app)},
        {"repo_url": "https://gitlab.com/a/b"},
        {"repo_url": "https://github.com/a/b/../../etc"},
        {"local_path": str(tmp_path)},  # outside local_scan_root
        {"local_path": str(demo_app), "options": {"llm": True, "rm_rf": True}},
    ]
    for body in cases:
        resp = await post("/api/v1/scans", json=body)
        assert resp.status_code == 422, (body, resp.text)

    service.settings.allow_local_paths = False
    resp = await post("/api/v1/scans", json={"local_path": str(demo_app)})
    assert resp.status_code == 422 and "disabled" in resp.text


async def test_worker_failure_marks_scan_failed_and_releases_lock(service, demo_app, tmp_path):
    victim = shutil.copytree(demo_app, demo_app.parent / "victim")
    sid = (await _submit(service, victim)).json()["id"]
    shutil.rmtree(victim)  # gone before the worker picks it up
    await service.run_jobs()

    scan = (await service.client.get(f"/api/v1/scans/{sid}")).json()
    assert scan["status"] == "FAILED" and scan["error_message"] == "Path is not a directory"
    assert service.redis.get(lock_key(str(victim.resolve()))) is None


async def test_queue_outage_returns_503_and_does_not_leave_a_lock(service, demo_app):
    service.fail_dispatch = True
    resp = await service.client.post("/api/v1/scans", json={"local_path": str(demo_app)})
    assert resp.status_code == 503
    assert service.redis.get(lock_key(str(demo_app.resolve()))) is None


async def test_not_found(service):
    missing = "00000000-0000-0000-0000-000000000000"
    assert (await service.client.get(f"/api/v1/scans/{missing}")).status_code == 404
    assert (await service.client.get(f"/api/v1/scans/{missing}/findings")).status_code == 404
    resp = await service.client.patch(f"/api/v1/findings/{missing}", json={"status": "OPEN"})
    assert resp.status_code == 404
    assert (await service.client.get("/api/v1/scans/not-a-uuid")).status_code == 422
