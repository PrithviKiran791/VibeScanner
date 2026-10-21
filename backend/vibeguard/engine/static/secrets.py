"""Secret detection: provider regexes, entropy, Supabase service-role JWTs, public env prefixes.

Secret values never leave this module unredacted: snippets and diffs are scrubbed, so a stored
`unified_diff` for a secret finding is a *display* artifact that won't apply. Each fixable finding
also carries a `Remediation` (line + column span + replacement expression) so the PR worker can
patch a fresh clone deterministically; `verify_span` lets it confirm the span still holds a secret
without the secret ever being stored.
"""

from __future__ import annotations

import base64
import json
import math
import re
import tomllib
from collections import Counter
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from pathlib import PurePosixPath

from vibeguard.engine.diff import replace_lines, unified_diff
from vibeguard.engine.models import Finding, Remediation, Severity, SourceFile

CATEGORY = "Secret Exposure"
CWE_HARDCODED = "CWE-798"
CWE_EXPOSURE = "CWE-200"

PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "your_",
    "your-",
    "xxxx",
    "changeme",
    "dummy",
    "redacted",
    "<",
    "${",
    "****",
)

JWT = re.compile(
    r"\b(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.(?P<payload>eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,})"
)

PUBLIC_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_", "PUBLIC_")
SENSITIVE_NAME = re.compile(
    r"SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|STRIPE_SK|_SK\b|ADMIN_KEY|DATABASE_URL"
)
PUBLIC_ENV_REF = re.compile(r"\b(?P<name>(?:" + "|".join(PUBLIC_PREFIXES) + r")[A-Z0-9_]+)\b")

JS_LANGS = {"javascript", "typescript", "tsx"}


@dataclass(frozen=True)
class SecretRule:
    id: str
    title: str
    severity: Severity
    regex: re.Pattern[str]
    env: str | None
    entropy: float | None


@cache
def load_rules() -> tuple[SecretRule, ...]:
    raw = files("vibeguard.engine.static").joinpath("rules/secrets.toml").read_text("utf-8")
    return tuple(
        SecretRule(
            id=r["id"],
            title=r["title"],
            severity=Severity(r["severity"]),
            regex=re.compile(r["regex"]),
            env=r.get("env"),
            entropy=r.get("entropy"),
        )
        for r in tomllib.loads(raw)["rules"]
    )


def scan_secrets(sf: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    is_env_file = _is_env_file(sf.path)

    for lineno, line in enumerate(sf.lines, start=1):
        for rule in load_rules():
            for m in rule.regex.finditer(line):
                value = m["secret"]
                if _is_placeholder(value):
                    continue
                if rule.entropy is not None and shannon_entropy(value) < rule.entropy:
                    continue
                findings.append(
                    _hardcoded_finding(
                        sf, lineno, rule.id, rule.title, rule.severity, value, rule.env
                    )
                )

        for m in JWT.finditer(line):
            if _jwt_role(m["payload"]) == "service_role":
                findings.append(
                    _hardcoded_finding(
                        sf,
                        lineno,
                        "supabase-service-role",
                        "Exposed Supabase Service Role Key",
                        Severity.CRITICAL,
                        m["secret"],
                        "SUPABASE_SERVICE_ROLE_KEY",
                    )
                )

        for m in PUBLIC_ENV_REF.finditer(line):
            name = m["name"]
            if SENSITIVE_NAME.search(name):
                findings.append(_public_env_finding(sf, lineno, name, m.start("name"), is_env_file))

    return findings


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


def verify_span(rule_id: str, span: str) -> bool:
    """True if `span` (the exact text a Remediation covers) still holds what `rule_id` flagged.

    The PR worker calls this on a fresh clone before replacing anything, so a moved or already
    fixed line is never clobbered.
    """
    quoted = len(span) >= 2 and span[0] == span[-1] and span[0] in "\"'`"
    inner = span[1:-1] if quoted else span
    if rule_id == "supabase-service-role":
        m = JWT.fullmatch(inner)
        return m is not None and _jwt_role(m["payload"]) == "service_role"
    rule = next((r for r in load_rules() if r.id == rule_id), None)
    if rule is None:
        return False
    m = rule.regex.search(span)
    return m is not None and m["secret"] == inner


def apply_span(line: str, rem: Remediation) -> str:
    return line[: rem.col_start] + rem.replacement + line[rem.col_end :]


def redact(value: str) -> str:
    keep = 4 if len(value) > 12 else 0
    return value[:keep] + "*" * 8


def _hardcoded_finding(
    sf: SourceFile,
    lineno: int,
    rule_id: str,
    title: str,
    severity: Severity,
    value: str,
    env: str | None,
) -> Finding:
    in_env_file = _is_env_file(sf.path)
    remediation = None if in_env_file else _env_reference_fix(sf, lineno, value, env, rule_id)

    if in_env_file:
        explanation = (
            f"A live credential is committed in `{sf.path}`, so anyone with repo access can use it. "
            "Rotate the key now, then add this file to .gitignore and load it from your host's secret store."
        )
    else:
        explanation = (
            "This credential is hardcoded in source and ships to everyone who can read the repo or bundle. "
            f"Rotate it and read it from `{env or 'an environment variable'}` on the server instead."
        )

    return _build(
        sf, lineno, rule_id, title, severity, CWE_HARDCODED, explanation, remediation, value
    )


def _public_env_finding(
    sf: SourceFile, lineno: int, name: str, col: int, in_env_file: bool
) -> Finding:
    prefix = next(p for p in PUBLIC_PREFIXES if name.startswith(p))
    private_name = name.removeprefix(prefix)
    remediation = Remediation(
        file_path=sf.path,
        line=lineno,
        col_start=col,
        col_end=col + len(name),
        replacement=private_name,
        env_var_name=private_name,
        expected_text=name,  # an env var *name*, not a secret: safe to store
    )
    where = "is declared" if in_env_file else "is read"
    explanation = (
        f"`{name}` {where} with the `{prefix}` prefix, which the bundler inlines into client JavaScript. "
        f"Drop the prefix and only read `{private_name}` from server code (route handlers, server actions)."
    )
    return _build(
        sf,
        lineno,
        "public-env-secret",
        "Server Secret Exposed To Client Bundle",
        Severity.CRITICAL,
        CWE_EXPOSURE,
        explanation,
        remediation,
        None,
    )


def _build(
    sf: SourceFile,
    lineno: int,
    rule_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    explanation: str,
    remediation: Remediation | None,
    secret: str | None,
) -> Finding:
    scrub = (lambda s: s.replace(secret, redact(secret))) if secret else (lambda s: s)
    diff = fixed_line = None
    if remediation is not None:
        fixed_line = apply_span(sf.lines[lineno - 1], remediation)
        patched = replace_lines(sf.text, lineno, lineno, fixed_line)
        diff = scrub(unified_diff(sf.path, sf.text, patched)) or None
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=CATEGORY,
        title=title,
        cwe_id=cwe,
        file_path=sf.path,
        line_start=lineno,
        line_end=lineno,
        snippet_original=scrub(sf.snippet(lineno, lineno)),
        snippet_fixed=fixed_line,
        unified_diff=diff,
        explanation=explanation,
        remediation=remediation,
    )


def _env_reference_fix(
    sf: SourceFile, lineno: int, value: str, env: str | None, rule_id: str
) -> Remediation | None:
    """Swap a quoted secret literal for an env lookup when that keeps the code valid."""
    if not env:
        return None
    literal = re.search(rf"""(["'`]){re.escape(value)}\1""", sf.lines[lineno - 1])
    if not literal:
        return None
    if sf.language in JS_LANGS:
        # TS types env values as `string | undefined`; assert so the fix still type-checks.
        ref = f"process.env.{env}" + ("!" if sf.language in ("typescript", "tsx") else "")
    elif sf.language == "python" and re.search(r"^\s*import os\b", sf.text, re.M):
        ref = f'os.environ["{env}"]'
    else:
        return None
    return Remediation(
        file_path=sf.path,
        line=lineno,
        col_start=literal.start(),
        col_end=literal.end(),
        replacement=ref,
        env_var_name=env,
        verify_rule=rule_id,
    )


def _jwt_role(payload_b64: str) -> str | None:
    try:
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded)).get("role")
    except (ValueError, UnicodeDecodeError, AttributeError):
        return None


def _is_placeholder(value: str) -> bool:
    lower = value.lower()
    return any(marker in lower for marker in PLACEHOLDER_MARKERS)


def _is_env_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return name == ".env" or (
        name.startswith(".env.") and not name.endswith((".example", ".sample", ".template"))
    )
