import base64
import json

from tests.conftest import make_sf
from tests.fixtures.materialize import DEMO_STRIPE_KEY
from vibeguard.engine.models import Severity
from vibeguard.engine.static.secrets import redact, scan_secrets, shannon_entropy
from vibeguard.engine.syntax.tree import parses_cleanly

STRIPE = DEMO_STRIPE_KEY


def _jwt(payload: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'HS256'})}.{enc(payload)}.c2lnbmF0dXJlc2lnbmF0dXJl"


def test_stripe_key_in_ts_gets_env_fix_and_is_redacted():
    sf = make_sf("lib/stripe.ts", f'const s = new Stripe("{STRIPE}");\n')
    [f] = scan_secrets(sf)
    assert f.rule_id == "stripe-secret-key" and f.severity == Severity.CRITICAL
    assert f.snippet_fixed == "const s = new Stripe(process.env.STRIPE_SECRET_KEY!);"
    assert STRIPE not in f.snippet_original and STRIPE not in f.unified_diff
    assert parses_cleanly("typescript", f.snippet_fixed)


def test_js_fix_has_no_non_null_assertion():
    sf = make_sf("lib/stripe.js", f"const key = '{STRIPE}';\n")
    [f] = scan_secrets(sf)
    assert f.snippet_fixed == "const key = process.env.STRIPE_SECRET_KEY;"


def test_secret_in_env_file_has_no_code_fix():
    sf = make_sf(".env", f"STRIPE_KEY={STRIPE}\n")
    [f] = scan_secrets(sf)
    assert f.unified_diff is None and "Rotate" in f.explanation


def test_placeholders_and_low_entropy_values_are_ignored():
    sf = make_sf(
        "config.ts",
        'const apiKey = "your_api_key_goes_here_123";\nconst password = "aaaaaaaaaaaaaaaaaaaa";\n',
    )
    assert scan_secrets(sf) == []


def test_generic_high_entropy_secret_is_flagged():
    sf = make_sf("config.ts", 'const apiKey = "Zx9Qm2LpT7vR4nW8kY3s";\n')
    [f] = scan_secrets(sf)
    assert f.rule_id == "generic-secret-assignment"


def test_supabase_service_role_jwt_detected_but_anon_key_ignored():
    service = make_sf("lib/sb.ts", f'const k = "{_jwt({"role": "service_role"})}";\n')
    anon = make_sf("lib/sb.ts", f'const k = "{_jwt({"role": "anon"})}";\n')
    assert [f.rule_id for f in scan_secrets(service)] == ["supabase-service-role"]
    assert scan_secrets(anon) == []


def test_public_prefixed_server_secret_is_flagged_in_code_and_env():
    code = make_sf("app/page.tsx", "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n")
    [f] = scan_secrets(code)
    assert f.rule_id == "public-env-secret"
    assert f.snippet_fixed == "const k = process.env.STRIPE_SECRET_KEY;"
    ok = make_sf("app/page.tsx", "const url = process.env.NEXT_PUBLIC_SUPABASE_URL;\n")
    assert scan_secrets(ok) == []


def test_helpers():
    assert redact(STRIPE) == "sk_l********"
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2


def test_openrouter_key_detected_with_env_fix():
    key = "sk-or-v1-" + "a1" * 32  # assembled so no key-shaped literal sits in git
    [f] = scan_secrets(
        make_sf("lib/llm.ts", f'const client = new OpenAI({{ apiKey: "{key}" }});\n')
    )
    assert f.rule_id == "openrouter-api-key" and f.severity == Severity.CRITICAL
    assert (
        f.snippet_fixed == "const client = new OpenAI({ apiKey: process.env.OPENROUTER_API_KEY! });"
    )
    assert key not in f.snippet_original
