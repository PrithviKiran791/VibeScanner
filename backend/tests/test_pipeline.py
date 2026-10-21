import json

from tests.conftest import HALLUCINATED, FakeProvider, registry_transport
from vibeguard.engine.cli import main
from vibeguard.engine.ingest.workspace import local_workspace
from vibeguard.engine.llm.provider import LLMError
from vibeguard.engine.llm.schemas import LLMFinding
from vibeguard.engine.models import FindingSource
from vibeguard.engine.pipeline import run_scan
from vibeguard.engine.report import to_markdown

IDOR_UNIT = "app/api/user/[id]/route.ts#GET@4"


def _scan(app, settings, provider):
    with local_workspace(app) as ws:
        return run_scan(
            ws, settings, provider=provider, registry_transport=registry_transport({HALLUCINATED})
        )


def _idor() -> LLMFinding:
    return LLMFinding(
        unit_id=IDOR_UNIT,
        title="IDOR On User Fetch",
        category="Broken Access Control",
        severity="CRITICAL",
        cwe_id="CWE-639",
        line_start=5,
        line_end=5,
        vulnerable_code="const user = await prisma.user.findUnique({ where: { id: params.id } });",
        fixed_code=(
            "  const session = await auth();\n"
            '  if (session?.user?.id !== params.id) return new Response("Forbidden", { status: 403 });\n'
            "  const user = await prisma.user.findUnique({ where: { id: params.id } });"
        ),
        explanation="Any visitor can read any user's record. The URL id is never checked against the session.",
    )


def test_fixture_deterministic_findings(demo_app, settings):
    result = _scan(demo_app, settings, provider=None)
    rules = sorted(f.rule_id for f in result.findings)
    assert rules == sorted(
        [
            "public-env-secret",
            "stripe-secret-key",
            "hallucinated-dependency",
            "sql-string-interpolation",
            "react-dangerously-set-inner-html",
            "shell-command-injection",
        ]
    )
    assert result.hardening_score == 0
    assert not result.llm_used
    # Every finding that has a patch is a real git-style diff for its own file
    for f in result.findings:
        if f.unified_diff:
            assert f.unified_diff.startswith(f"--- a/{f.file_path}\n+++ b/{f.file_path}\n")


def test_fixture_with_llm_adds_idor_and_only_sends_pruned_units(demo_app, settings):
    provider = FakeProvider([_idor()])
    result = _scan(demo_app, settings, provider)
    idor = next(f for f in result.findings if f.cwe_id == "CWE-639")
    assert idor.source == FindingSource.LLM and idor.unified_diff
    assert result.llm_used and result.units_analyzed >= 3

    prompt = "".join(provider.prompts)
    assert "deleteProject" in prompt and IDOR_UNIT in prompt
    # Components and libs are never sent to the LLM
    assert "dangerouslySetInnerHTML" not in prompt and "sk_live_" not in prompt


def test_llm_failure_degrades_to_static(demo_app, settings):
    result = _scan(demo_app, settings, FakeProvider(error=LLMError("Anthropic rate limit hit")))
    assert not result.llm_used
    assert "Anthropic rate limit hit" in result.warnings
    assert len(result.findings) == 6


def test_progress_reports_stages(demo_app, settings):
    stages = []
    with local_workspace(demo_app) as ws:
        run_scan(
            ws,
            settings,
            provider=None,
            progress=lambda s, p: stages.append(s),
            registry_transport=registry_transport(set()),
        )
    assert stages[0] == "INDEXING" and stages[-1] == "COMPLETED"


def test_markdown_report(demo_app, settings):
    md = to_markdown(_scan(demo_app, settings, provider=None))
    assert "**Hardening Index: 0/100**" in md and "```diff" in md


def test_cli_writes_reports_and_fail_under(demo_app, tmp_path, capsys):
    out = tmp_path / "r.json"
    code = main(
        [
            "scan",
            str(demo_app),
            "--no-llm",
            "--no-registry",
            "--json",
            str(out),
            "--fail-under",
            "50",
        ]
    )
    assert code == 1
    data = json.loads(out.read_text())
    assert data["hardening_score"] == 0 and data["counts"]["critical"] == 4
    assert "HARDENING INDEX 0/100" in capsys.readouterr().out


def test_cli_rejects_bad_target(capsys):
    assert main(["scan", "does/not/exist", "--no-llm"]) == 2
