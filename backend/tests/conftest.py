from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
import pytest

if sys.platform == "win32":
    # psycopg's async driver can't run on Windows' default Proactor loop; only matters when
    # VIBEGUARD_TEST_DATABASE_URL points the suite at PostgreSQL (production runs on Linux).
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from tests.fixtures.materialize import build_demo_app
from vibeguard.config import Settings
from vibeguard.engine.ingest.file_index import LANGUAGE_BY_EXT
from vibeguard.engine.llm.schemas import LLMFinding, LLMReport
from vibeguard.engine.models import SourceFile

HALLUCINATED = "react-secure-auth-helpers-pro"


def make_sf(path: str, text: str) -> SourceFile:
    return SourceFile(
        path=path,
        abs_path=Path(path),
        text=text,
        language=LANGUAGE_BY_EXT.get(Path(path).suffix.lower()),
    )


def registry_transport(missing: set[str]) -> httpx.MockTransport:
    """Fake npm/PyPI: 404 for names in `missing`, 200 otherwise."""

    def handler(request: httpx.Request) -> httpx.Response:
        hit = any(m in request.url.path for m in missing)
        return httpx.Response(404 if hit else 200, json={})

    return httpx.MockTransport(handler)


class FakeProvider:
    name = "fake"

    def __init__(self, findings: list[LLMFinding] | None = None, error: Exception | None = None):
        self.findings = findings or []
        self.error = error
        self.prompts: list[str] = []

    def analyze(self, prompt: str) -> LLMReport:
        self.prompts.append(prompt)
        if self.error:
            raise self.error
        return LLMReport(findings=self.findings)


@pytest.fixture
def settings() -> Settings:
    return Settings(llm_provider="none", registry_check=True, _env_file=None)


@pytest.fixture(scope="session")
def demo_app(tmp_path_factory) -> Path:
    """The vulnerable demo app with its fake secrets assembled (never committed literally)."""
    return build_demo_app(tmp_path_factory.mktemp("demo") / "vulnerable_app")
