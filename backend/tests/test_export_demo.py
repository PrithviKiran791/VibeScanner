import re
import subprocess

from tests.fixtures.export_demo import export_demo
from vibeguard.config import Settings
from vibeguard.engine.ingest.workspace import local_workspace
from vibeguard.engine.pipeline import run_scan

# Provider patterns GitHub push protection blocks; none may appear in the public demo
PUSH_PROTECTED = re.compile(r"sk_live_[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}")


def test_export_is_a_committed_push_safe_repo(tmp_path):
    repo = export_demo(tmp_path / "demo")

    tracked = subprocess.run(
        ["git", "ls-files"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.split()
    assert {".env.local", "lib/session.ts", "README.md", "package.json"} <= set(tracked)
    assert not any(t.endswith(".tmpl") for t in tracked)
    assert (
        subprocess.run(
            ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True
        ).stdout
        == ""
    )

    for path in tracked:
        assert not PUSH_PROTECTED.search((repo / path).read_text(encoding="utf-8")), path


def test_exported_demo_still_shows_the_planted_findings(tmp_path):
    repo = export_demo(tmp_path / "demo")
    settings = Settings(_env_file=None, llm_provider="none", registry_check=False)
    with local_workspace(repo) as ws:
        result = run_scan(ws, settings, provider=None)
    rules = {f.rule_id for f in result.findings}
    assert {
        "generic-secret-assignment",
        "public-env-secret",
        "sql-string-interpolation",
        "shell-command-injection",
        "react-dangerously-set-inner-html",
    } <= rules
    assert "stripe-secret-key" not in rules
