"""The API reports the Code Quality Score next to the Hardening Index, and keeps them apart."""

import uuid

import pytest


@pytest.fixture
def smelly_app(demo_app):
    """A small app (inside the allowed local scan root) with one vulnerability and some smells."""
    root = demo_app.parent / f"smelly-{uuid.uuid4().hex[:6]}"
    (root / "app" / "api" / "orders").mkdir(parents=True)
    (root / "app" / "api" / "orders" / "route.ts").write_text(
        "export async function POST(req: Request) {\n"
        "  const body = (await req.json()) as any;\n"
        "  console.log('order', body);\n"
        "  try {\n"
        "    await save(body);\n"
        "  } catch (e) {}\n"
        "  eval(body.code);\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )
    return root


async def _scan(service, path) -> tuple[dict, list[dict]]:
    sid = (await service.client.post("/api/v1/scans", json={"local_path": str(path)})).json()["id"]
    await service.run_jobs()
    scan = (await service.client.get(f"/api/v1/scans/{sid}")).json()
    findings = (await service.client.get(f"/api/v1/scans/{sid}/findings")).json()
    return scan, findings


async def test_scan_reports_both_scores(service, smelly_app):
    scan, findings = await _scan(service, smelly_app)
    assert scan["status"] == "COMPLETED"

    assert isinstance(scan["quality_score"], int) and scan["quality_score"] < 100
    assert scan["quality_grade"] in {"A", "B", "C", "D", "F"}
    b = scan["quality_breakdown"]
    assert set(b) >= {
        "modularity",
        "type_safety",
        "error_hygiene",
        "cleanliness",
        "architecture",
        "total_loc",
        "files_scanned",
        "code_smells_count",
    }
    assert b["error_hygiene"] < 100 and b["type_safety"] < 100 and b["total_loc"] == 9

    domains = {f["domain"] for f in findings}
    assert domains == {"SECURITY", "QUALITY"}
    quality = [f for f in findings if f["domain"] == "QUALITY"]
    assert {f["rule_id"] for f in quality} >= {
        "quality/empty-catch",
        "quality/any",
        "quality/console-log",
    }

    # The Hardening Index and counts reflect security findings only (the eval)
    security = [f for f in findings if f["domain"] == "SECURITY"]
    assert scan["counts"]["total"] == len(security)
    assert scan["hardening_score"] == 100 - sum(
        {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 1}[f["severity"]] for f in security
    )


async def test_dismissing_a_smell_leaves_the_hardening_index_alone(service, smelly_app):
    scan, findings = await _scan(service, smelly_app)
    smell = next(f for f in findings if f["rule_id"] == "quality/empty-catch")
    resp = await service.client.patch(
        f"/api/v1/findings/{smell['id']}", json={"status": "DISMISSED_FALSE_POSITIVE"}
    )
    assert resp.status_code == 200
    assert resp.json()["scan"]["hardening_score"] == scan["hardening_score"]


async def test_quality_fix_can_be_rebuilt_from_its_diff(service, smelly_app):
    _, findings = await _scan(service, smelly_app)
    smell = next(f for f in findings if f["rule_id"] == "quality/empty-catch")
    assert smell["unified_diff"] and "throw e;" in smell["unified_diff"]
    assert smell["category"] == "Error Hygiene" and smell["cwe_id"] is None
