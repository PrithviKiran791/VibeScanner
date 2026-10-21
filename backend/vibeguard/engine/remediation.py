"""Apply a stored `Remediation` to a fresh clone (used by the Phase 3 PR worker).

Secret findings store a masked display diff, so the patch is rebuilt here from coordinates: verify
the span still holds what was flagged, then swap in the replacement. Nothing secret is stored.
"""

from __future__ import annotations

from vibeguard.engine.models import Remediation
from vibeguard.engine.static.secrets import verify_span


class RemediationMismatchError(Exception):
    """The file changed since the scan; refuse rather than patch the wrong text."""


def apply_remediation(text: str, rem: Remediation) -> str:
    # Same line splitting as SourceFile.lines, so line numbers agree with the scan.
    lines = text.splitlines(keepends=True)
    if not 1 <= rem.line <= len(lines):
        raise RemediationMismatchError(f"{rem.file_path}: line {rem.line} no longer exists")

    raw = lines[rem.line - 1]
    body = raw.rstrip("\r\n")
    eol = raw[len(body) :]
    span = body[rem.col_start : rem.col_end]

    if rem.expected_text is not None:
        ok = span == rem.expected_text
    elif rem.verify_rule is not None:
        ok = verify_span(rem.verify_rule, span)
    else:
        ok = False
    if not ok:
        raise RemediationMismatchError(f"{rem.file_path}:{rem.line} no longer matches the finding")

    lines[rem.line - 1] = body[: rem.col_start] + rem.replacement + body[rem.col_end :] + eol
    return "".join(lines)
