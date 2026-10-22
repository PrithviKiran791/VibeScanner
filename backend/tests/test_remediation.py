import pytest

from tests.conftest import make_sf
from tests.fixtures.materialize import DEMO_STRIPE_KEY
from vibeguard.config import Settings
from vibeguard.engine.remediation import RemediationMismatchError, apply_remediation
from vibeguard.engine.static.secrets import scan_secrets, verify_span

SOURCE = f'import Stripe from "stripe";\r\nexport const s = new Stripe("{DEMO_STRIPE_KEY}");\r\n'


def _secret_finding():
    [f] = scan_secrets(make_sf("lib/stripe.ts", SOURCE))
    return f


def test_secret_finding_carries_coordinates_but_no_secret():
    f = _secret_finding()
    rem = f.remediation
    assert (rem.line, rem.env_var_name, rem.verify_rule) == (
        2,
        "STRIPE_SECRET_KEY",
        "stripe-secret-key",
    )
    assert rem.replacement == "process.env.STRIPE_SECRET_KEY!"
    stored = f.model_dump_json()
    assert DEMO_STRIPE_KEY not in stored  # nothing persisted contains the raw key


def test_fresh_clone_is_patched_exactly():
    patched = apply_remediation(SOURCE, _secret_finding().remediation)
    assert (
        patched
        == 'import Stripe from "stripe";\r\nexport const s = new Stripe(process.env.STRIPE_SECRET_KEY!);\r\n'
    )


@pytest.mark.parametrize(
    "fresh",
    [
        'import Stripe from "stripe";\nexport const s = new Stripe(process.env.STRIPE_SECRET_KEY!);\n',  # already fixed
        '// moved\nimport Stripe from "stripe";\n',  # line shifted
        "one line\n",  # line gone
    ],
)
def test_changed_file_is_refused(fresh):
    with pytest.raises(RemediationMismatchError):
        apply_remediation(fresh, _secret_finding().remediation)


def test_public_env_rename_uses_expected_text():
    [f] = scan_secrets(
        make_sf("app/page.tsx", "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n")
    )
    assert f.remediation.expected_text == "NEXT_PUBLIC_STRIPE_SECRET_KEY"
    out = apply_remediation("const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n", f.remediation)
    assert out == "const k = process.env.STRIPE_SECRET_KEY;\n"


def test_verify_span():
    assert verify_span("stripe-secret-key", f'"{DEMO_STRIPE_KEY}"')
    assert not verify_span("stripe-secret-key", '"sk_test_abc"')
    assert not verify_span("unknown-rule", f'"{DEMO_STRIPE_KEY}"')


def test_llm_model_from_env(monkeypatch):
    for var in ("VIBEGUARD_LLM_MODEL", "LLM_MODEL", "LLM_MODEL_ID"):
        monkeypatch.delenv(var, raising=False)
    assert Settings(_env_file=None).resolved_llm_model == "google/gemma-4-31b-it:free"
    monkeypatch.setenv("LLM_MODEL", "google/gemma-4-26b-a4b-it:free")
    assert Settings(_env_file=None).resolved_llm_model == "google/gemma-4-26b-a4b-it:free"
    monkeypatch.setenv("VIBEGUARD_LLM_MODEL", "google/gemma-4-31b-it")
    assert Settings(_env_file=None).resolved_llm_model == "google/gemma-4-31b-it"
    assert Settings(_env_file=None, llm_provider="none").llm_model == "google/gemma-4-31b-it"
