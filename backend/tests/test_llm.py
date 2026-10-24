import json
from types import SimpleNamespace

import httpx
import openai
import pytest

from tests.conftest import make_sf
from tests.test_routes import ROUTE
from vibeguard.config import Settings
from vibeguard.engine.llm.openrouter_provider import OpenRouterProvider
from vibeguard.engine.llm.provider import LLMError, build_prompt, chunk_units, get_provider
from vibeguard.engine.llm.schemas import LLMFinding, parse_report
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
PRIMARY = "google/gemma-4-31b-it:free"
FALLBACK = "google/gemma-4-26b-a4b-it:free"


@pytest.fixture
def ctx():
    sf = make_sf(PATH, ROUTE)
    units = extract_units(sf)
    return sf, units, {PATH: sf}


def _finding_dict(**over) -> dict:
    base = {
        "title": "IDOR On User Fetch",
        "severity": "CRITICAL",
        "category": "Broken Access Control",
        "cwe_id": "CWE-639",
        "file_path": PATH,
        "line_start": 5,
        "line_end": 5,
        "vulnerable_code": VULN.strip(),
        "suggested_patch": FIX,
        "description": "Anyone can read any user. The URL id is never checked against the session.",
    }
    return base | over


def _lf(**over) -> LLMFinding:
    return LLMFinding.model_validate(_finding_dict(**over))


# --- prompt assembly -----------------------------------------------------------------------


def test_prompt_has_gutter_numbers_and_file_attributes(ctx):
    _, units, _ = ctx
    prompt = build_prompt(units)
    assert f'file="{PATH}"' in prompt
    assert "5| " + VULN in prompt
    assert 'import { prisma } from "@/lib/db";' in prompt


def test_chunking_respects_budget(ctx):
    _, units, _ = ctx
    assert len(chunk_units(units, max_chars=10)) == len(units)
    assert len(chunk_units(units, max_chars=100_000)) == 1


# --- JSON-mode parsing ---------------------------------------------------------------------


def test_parse_report_validates_each_finding_and_normalizes():
    text = json.dumps(
        {
            "findings": [
                _finding_dict(severity="high", cwe_id=639, file_path="./app\\x.ts"),
                {"title": "missing everything"},
                _finding_dict(severity="SEVERE"),
            ]
        }
    )
    report = parse_report(text)
    assert len(report.findings) == 1 and report.rejected == 2
    f = report.findings[0]
    assert (f.severity, f.cwe_id, f.file_path) == ("HIGH", "CWE-639", "app/x.ts")


@pytest.mark.parametrize(
    "text",
    [
        '```json\n{"findings": []}\n```',
        'Here you go: {"findings": []} hope that helps',
        '{"findings": []}',
    ],
)
def test_parse_report_tolerates_fences_and_chatter(text):
    assert parse_report(text).findings == []


@pytest.mark.parametrize("text", ["", "no json here", "[1, 2]", '{"results": []}'])
def test_parse_report_rejects_unusable_output(text):
    with pytest.raises(ValueError):
        parse_report(text)


# --- hallucination guard -------------------------------------------------------------------


def test_valid_finding_is_accepted_with_parseable_patch(ctx):
    _, units, files = ctx
    [f], dropped = to_findings([_lf()], units, files)
    assert dropped == 0 and f.source == FindingSource.LLM
    assert f.rule_id == "llm-broken-access-control"
    assert f.explanation.startswith("Anyone can read")
    assert "+  const session = await auth();" in f.unified_diff


@pytest.mark.parametrize(
    "override",
    [
        {"file_path": "app/api/nope/route.ts"},  # file we never sent
        {"file_path": ".env.local"},  # never sent to the LLM, so never reportable
        {"line_start": 40, "line_end": 41},  # outside every unit
        {"line_start": 11, "line_end": 11},  # real file, but not inside a sent unit (helper)
        {"vulnerable_code": "db.user.delete()"},  # code not on those lines
        {"line_start": 6, "line_end": 6},  # real line, but not the claimed code
    ],
)
def test_hallucinated_findings_are_discarded(ctx, override):
    _, units, files = ctx
    accepted, dropped = to_findings([_lf(**override)], units, files)
    assert accepted == [] and dropped == 1


def test_unparseable_patch_keeps_finding_but_drops_patch(ctx):
    _, units, files = ctx
    [f], _ = to_findings([_lf(suggested_patch="  const user = await (((")], units, files)
    assert f.unified_diff is None and f.snippet_fixed is None


def test_empty_patch_means_report_without_fix(ctx):
    _, units, files = ctx
    [f], _ = to_findings([_lf(suggested_patch="")], units, files)
    assert f.unified_diff is None


# --- OpenRouter client ---------------------------------------------------------------------


class _StubCompletions:
    """Stands in for client.chat.completions; `script` maps model -> response or exception."""

    def __init__(self, script: dict):
        self.script, self.calls = script, []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.script[kwargs["model"]]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _client(completions: _StubCompletions):
    return SimpleNamespace(chat=SimpleNamespace(completions=completions))


class _Stream(list):
    """A streamed completion: iterable chunks plus close(), like openai.Stream."""

    closed = False

    def close(self):
        self.closed = True


def _chunk(content=None, finish_reason=None, refusal=None):
    delta = SimpleNamespace(content=content, refusal=refusal)
    return SimpleNamespace(choices=[SimpleNamespace(delta=delta, finish_reason=finish_reason)])


def _completion(content: str, finish_reason: str = "stop", refusal: str | None = None):
    # Split the text across chunks, then a usage-only chunk with no choices, as OpenRouter does
    half = len(content) // 2
    return _Stream(
        [
            _chunk(content[:half] or None),
            _chunk(content[half:] or None, refusal=refusal),
            _chunk(finish_reason=finish_reason),
            SimpleNamespace(choices=[], usage=SimpleNamespace(completion_tokens=1)),
        ]
    )


def _status_error(cls, status: int):
    req = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    return cls("error", response=httpx.Response(status, request=req), body=None)


def _provider(script: dict, fallback: str | None = FALLBACK):
    stub = _StubCompletions(script)
    return OpenRouterProvider(
        model=PRIMARY, api_key="k", fallback_model=fallback, client=_client(stub)
    ), stub


def test_request_shape_and_parse():
    provider, stub = _provider({PRIMARY: _completion(json.dumps({"findings": [_finding_dict()]}))})
    report = provider.analyze("review this")
    assert [f.title for f in report.findings] == ["IDOR On User Fetch"]

    [call] = stub.calls
    assert call["model"] == PRIMARY
    assert call["response_format"] == {"type": "json_object"}
    assert call["temperature"] == 0
    assert call["stream"] is True
    assert call["extra_body"] == {"reasoning": {"enabled": True, "exclude": True}}
    system, user = call["messages"]
    assert system["role"] == "system" and '"findings"' in system["content"]
    assert "untrusted input" in system["content"]
    assert user == {"role": "user", "content": "review this"}


def test_real_client_sends_openrouter_headers():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.update(url=str(req.url), headers=dict(req.headers), body=json.loads(req.content))

        def event(delta: dict, finish: str | None = None) -> str:
            chunk = {
                "id": "x",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": PRIMARY,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            }
            return f"data: {json.dumps(chunk)}\n\n"

        sse = (
            ": OPENROUTER PROCESSING\n\n"  # keep-alive comment
            + event({"role": "assistant", "content": '{"findings": '})
            + event({"content": "[]}"})
            + event({}, "stop")
            + "data: [DONE]\n\n"
        )
        return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})

    client = openai.OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key="sk-or-test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        default_headers={"HTTP-Referer": "http://localhost:3000", "X-Title": "VibeGuard"},
    )
    provider = OpenRouterProvider(model=PRIMARY, api_key="sk-or-test", client=client)
    assert provider.analyze("x").findings == []
    assert seen["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert seen["headers"]["authorization"] == "Bearer sk-or-test"
    assert seen["headers"]["http-referer"] == "http://localhost:3000"
    assert seen["headers"]["x-title"] == "VibeGuard"
    assert seen["body"]["response_format"] == {"type": "json_object"}
    assert seen["body"]["stream"] is True
    assert seen["body"]["reasoning"] == {"enabled": True, "exclude": True}


def test_mid_stream_error_event_falls_back():
    """HTTP 200, then OpenRouter sends an error event instead of tokens."""

    def handler(req: httpx.Request) -> httpx.Response:
        model = json.loads(req.content)["model"]
        if model == PRIMARY:
            err = {"error": {"message": "Provider returned error", "code": 429}}
            return httpx.Response(
                200,
                text=f"data: {json.dumps(err)}\n\n",
                headers={"content-type": "text/event-stream"},
            )
        ok = {
            "id": "x",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": model,
            "choices": [
                {"index": 0, "delta": {"content": '{"findings": []}'}, "finish_reason": "stop"}
            ],
        }
        return httpx.Response(
            200,
            text=f"data: {json.dumps(ok)}\n\ndata: [DONE]\n\n",
            headers={"content-type": "text/event-stream"},
        )

    client = openai.OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key="k",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    provider = OpenRouterProvider(
        model=PRIMARY, api_key="k", fallback_model=FALLBACK, client=client
    )
    assert provider.analyze("x").findings == []


def test_reasoning_can_be_turned_off():
    stub = _StubCompletions({PRIMARY: _completion('{"findings": []}')})
    provider = OpenRouterProvider(model=PRIMARY, api_key="k", reasoning=False, client=_client(stub))
    provider.analyze("x")
    assert stub.calls[0]["extra_body"] is None


def test_slow_stream_is_cut_off_at_the_deadline(monkeypatch):
    import vibeguard.engine.llm.openrouter_provider as mod

    clock = iter([0.0, 1.0, 100.0, 200.0])
    monkeypatch.setattr(mod.time, "monotonic", lambda: next(clock))
    stream = _completion('{"findings": []}')
    stub = _StubCompletions({PRIMARY: stream})
    provider = OpenRouterProvider(model=PRIMARY, api_key="k", timeout=10, client=_client(stub))
    with pytest.raises(LLMError, match="longer than 10s"):
        provider.analyze("x")
    assert stream.closed


def test_rate_limit_falls_back_to_secondary_model():
    provider, stub = _provider(
        {
            PRIMARY: _status_error(openai.RateLimitError, 429),
            FALLBACK: _completion('{"findings": []}'),
        }
    )
    assert provider.analyze("x").findings == []
    assert [c["model"] for c in stub.calls] == [PRIMARY, FALLBACK]


def test_both_models_rate_limited_raises_llm_error():
    provider, _ = _provider(
        {
            PRIMARY: _status_error(openai.RateLimitError, 429),
            FALLBACK: _status_error(openai.InternalServerError, 503),
        }
    )
    with pytest.raises(LLMError, match="All LLM models unavailable"):
        provider.analyze("x")


@pytest.mark.parametrize(
    ("response", "match"),
    [
        (_completion("", refusal="I can't help with that"), "declined"),
        (_completion("", finish_reason="content_filter"), "declined"),
        (_completion('{"findings": [', finish_reason="length"), "truncated"),
    ],
)
def test_bad_responses_raise_llm_error_without_fallback(response, match):
    provider, stub = _provider({PRIMARY: response})
    with pytest.raises(LLMError, match=match):
        provider.analyze("x")
    assert len(stub.calls) == 1


def test_bad_key_does_not_try_fallback():
    provider, stub = _provider({PRIMARY: _status_error(openai.AuthenticationError, 401)})
    with pytest.raises(LLMError, match="rejected the API key"):
        provider.analyze("x")
    assert len(stub.calls) == 1


def test_missing_key_disables_semantic_pass_with_clear_message():
    settings = Settings(_env_file=None, openrouter_api_key=None)
    with pytest.raises(LLMError, match="set OPENROUTER_API_KEY"):
        get_provider(settings)


def test_get_provider_wires_settings(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("LLM_MODEL", "google/gemma-4-31b-it:free")
    provider = get_provider(Settings(_env_file=None))
    assert isinstance(provider, OpenRouterProvider)
    assert provider.models == [
        PRIMARY,
        FALLBACK,
        "nvidia/nemotron-3.5-super-vl:free",
        "dots-studio/dots-3-note-preview:free",
    ]


THIRD = "nvidia/nemotron-3.5-super-vl:free"


def _chain(script: dict):
    stub = _StubCompletions(script)
    provider = OpenRouterProvider(
        model=PRIMARY,
        api_key="k",
        fallback_model=FALLBACK,
        fallback_models=[THIRD, PRIMARY],  # duplicates are dropped
        client=_client(stub),
    )
    return provider, stub


def test_other_providers_answer_when_gemma_is_saturated():
    provider, stub = _chain(
        {
            PRIMARY: _status_error(openai.RateLimitError, 429),
            FALLBACK: _status_error(openai.RateLimitError, 429),
            THIRD: _completion('{"findings": []}'),
        }
    )
    assert provider.models == [PRIMARY, FALLBACK, THIRD]
    assert provider.analyze("x").findings == []
    assert [c["model"] for c in stub.calls] == [PRIMARY, FALLBACK, THIRD]


def test_rate_limited_models_are_skipped_for_the_next_chunks():
    provider, stub = _chain(
        {
            PRIMARY: _status_error(openai.RateLimitError, 429),
            FALLBACK: _status_error(openai.RateLimitError, 429),
            THIRD: _completion('{"findings": []}'),
        }
    )
    provider.analyze("chunk 1")
    stub.calls.clear()
    stub.script[THIRD] = _completion('{"findings": []}')  # a fresh stream for chunk 2
    provider.analyze("chunk 2")
    assert [c["model"] for c in stub.calls] == [THIRD]


def test_unusable_output_tries_the_next_model():
    provider, stub = _chain(
        {
            PRIMARY: _completion("I found some issues!"),
            FALLBACK: _completion('{"findings": []}'),
        }
    )
    assert provider.analyze("x").findings == []
    assert [c["model"] for c in stub.calls] == [PRIMARY, FALLBACK]
