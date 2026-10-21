from types import SimpleNamespace

import anthropic
import httpx
import pytest

from tests.conftest import make_sf
from tests.test_routes import ROUTE
from vibeguard.engine.llm.anthropic_provider import FALLBACK_BETA, AnthropicProvider
from vibeguard.engine.llm.provider import LLMError, build_prompt, chunk_units
from vibeguard.engine.llm.schemas import LLMFinding, LLMReport, inline_json_schema
from vibeguard.engine.llm.validate import to_findings
from vibeguard.engine.models import FindingSource
from vibeguard.engine.syntax.routes import extract_units

PATH = "app/api/user/[id]/route.ts"
VULN = "  const user = await prisma.user.findUnique({ where: { id: params.id } });"
FIX = (
    "  const session = await auth();\n"
    "  if (session?.user?.id !== params.id) return NextResponse.json({}, { status: 403 });\n"
    "  const user = await prisma.user.findUnique({ where: { id: params.id } });"
)


@pytest.fixture
def ctx():
    sf = make_sf(PATH, ROUTE)
    units = extract_units(sf)
    return sf, units, {PATH: sf}


def _lf(unit_id: str, **over) -> LLMFinding:
    base = dict(
        unit_id=unit_id,
        title="IDOR On User Fetch",
        category="Broken Access Control",
        severity="CRITICAL",
        cwe_id="CWE-639",
        line_start=5,
        line_end=5,
        vulnerable_code=VULN.strip(),
        fixed_code=FIX,
        explanation="Anyone can read any user. The id from the URL is never checked against the session.",
    )
    return LLMFinding(**(base | over))


def test_prompt_has_gutter_numbers_and_unit_ids(ctx):
    _, units, _ = ctx
    prompt = build_prompt(units)
    assert f'id="{units[0].unit_id}"' in prompt
    assert "5| " + VULN in prompt
    assert 'import { prisma } from "@/lib/db";' in prompt


def test_chunking_respects_budget(ctx):
    _, units, _ = ctx
    assert len(chunk_units(units, max_chars=10)) == len(units)
    assert len(chunk_units(units, max_chars=100_000)) == 1


def test_valid_finding_is_accepted_with_parseable_patch(ctx):
    sf, units, files = ctx
    [f], dropped = to_findings([_lf(units[0].unit_id)], units, files)
    assert dropped == 0 and f.source == FindingSource.LLM
    assert f.rule_id == "llm-broken-access-control"
    assert "+  const session = await auth();" in f.unified_diff


@pytest.mark.parametrize(
    "override",
    [
        {"unit_id": "app/api/nope/route.ts#GET@1"},  # unit we never sent
        {"line_start": 40, "line_end": 41},  # outside the unit
        {"vulnerable_code": "db.user.delete()"},  # code not on those lines
        {"line_start": 6, "line_end": 6},  # real line, but not the claimed code
    ],
)
def test_hallucinated_findings_are_discarded(ctx, override):
    _, units, files = ctx
    lf = _lf(units[0].unit_id).model_copy(update=override)
    accepted, dropped = to_findings([lf], units, files)
    assert accepted == [] and dropped == 1


def test_unparseable_fix_keeps_finding_but_drops_patch(ctx):
    _, units, files = ctx
    [f], _ = to_findings(
        [_lf(units[0].unit_id, fixed_code="  const user = await (((")], units, files
    )
    assert f.unified_diff is None and f.snippet_fixed is None


def test_schema_is_strict_and_ref_free():
    schema = inline_json_schema(LLMReport)
    assert "$defs" not in str(schema) and "$ref" not in str(schema)
    item = schema["properties"]["findings"]["items"]
    assert item["additionalProperties"] is False
    assert set(item["required"]) == set(LLMFinding.model_fields)


class _StubMessages:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


def _client(messages: _StubMessages):
    return SimpleNamespace(beta=SimpleNamespace(messages=messages))


def _response(text: str, stop_reason: str = "end_turn"):
    return SimpleNamespace(
        stop_reason=stop_reason, content=[SimpleNamespace(type="text", text=text)]
    )


def test_anthropic_request_shape_and_parse():
    msgs = _StubMessages(_response(LLMReport(findings=[]).model_dump_json()))
    provider = AnthropicProvider(model="claude-opus-5-5", effort="medium", client=_client(msgs))
    assert provider.analyze("review this").findings == []

    [call] = msgs.calls
    assert call["model"] == "claude-opus-5-5"
    assert call["betas"] == [FALLBACK_BETA] and call["fallbacks"] == "default"
    assert call["output_config"]["effort"] == "medium"
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert "untrusted input" in call["system"]
    assert "thinking" not in call and "temperature" not in call


@pytest.mark.parametrize(
    ("response", "match"),
    [
        (_response("", stop_reason="refusal"), "declined"),
        (_response('{"findings": [', stop_reason="max_tokens"), "truncated"),
        (_response('{"findings": [{"bogus": 1}]}'), "schema"),
    ],
)
def test_anthropic_bad_responses_raise_llm_error(response, match):
    provider = AnthropicProvider(client=_client(_StubMessages(response)))
    with pytest.raises(LLMError, match=match):
        provider.analyze("x")


def test_anthropic_api_errors_become_llm_error():
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    err = anthropic.RateLimitError(
        "slow down", response=httpx.Response(429, request=req), body=None
    )
    provider = AnthropicProvider(client=_client(_StubMessages(error=err)))
    with pytest.raises(LLMError, match="rate limit"):
        provider.analyze("x")
