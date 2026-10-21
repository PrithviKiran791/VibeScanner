"""Strict unified-diff applier for a single file (used to re-apply stored fixes to a fresh copy).

Context and removed lines must match exactly (line endings aside). A hunk may sit at a shifted
offset if lines were added above it, but nothing is ever fuzzed: if the code changed, the patch
is refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
MAX_OFFSET = 200


class PatchMismatchError(Exception):
    pass


@dataclass
class _Hunk:
    old_start: int
    lines: list[tuple[str, str]] = field(default_factory=list)  # (op, text without EOL)

    @property
    def old(self) -> list[str]:
        return [t for op, t in self.lines if op in (" ", "-")]


def apply_unified_diff(text: str, diff: str) -> str:
    hunks = _parse(diff)
    if not hunks:
        raise PatchMismatchError("Diff has no hunks")

    src = text.splitlines(keepends=True)
    eol = "\r\n" if "\r\n" in text else "\n"
    body = [line.rstrip("\r\n") for line in src]
    out: list[str] = []
    cursor = 0  # index into src of the next untouched line

    for hunk in hunks:
        at = _locate(body, hunk, cursor)
        out.extend(src[cursor:at])
        i = at
        for op, line in hunk.lines:
            if op == " ":
                out.append(src[i])
                i += 1
            elif op == "-":
                i += 1
            else:
                out.append(line + eol)
        cursor = i

    touched_last_line = cursor >= len(src)
    out.extend(src[cursor:])
    result = "".join(out)
    # Hunks that rewrote the final line add an EOL; keep "no newline at end of file" files as-is
    if touched_last_line and text and not text.endswith(("\n", "\r")):
        result = result.removesuffix(eol)
    return result


def _locate(body: list[str], hunk: _Hunk, cursor: int) -> int:
    want = hunk.old
    expected = max(cursor, hunk.old_start - 1 if want else hunk.old_start)
    for delta in range(MAX_OFFSET + 1):
        for at in (expected + delta, expected - delta) if delta else (expected,):
            if cursor <= at <= len(body) - len(want) and body[at : at + len(want)] == want:
                return at
    raise PatchMismatchError(
        f"Hunk at line {hunk.old_start} no longer matches the file; it changed after the scan"
    )


def _parse(diff: str) -> list[_Hunk]:
    hunks: list[_Hunk] = []
    current: _Hunk | None = None
    for raw in diff.splitlines():
        line = raw.rstrip("\r")
        if line.startswith(("--- ", "+++ ")) and current is None:
            continue
        if m := HUNK_HEADER.match(line):
            current = _Hunk(old_start=int(m.group(1)))
            hunks.append(current)
            continue
        if current is None or line.startswith("\\"):
            continue
        op, rest = (line[0], line[1:]) if line else (" ", "")
        if op not in (" ", "-", "+"):
            raise PatchMismatchError(f"Malformed diff line: {line[:40]!r}")
        current.lines.append((op, rest))
    return hunks
