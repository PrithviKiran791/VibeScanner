"""Unified diff generation (PRD FR-4.1)."""

from __future__ import annotations

import difflib


def unified_diff(path: str, original: str, patched: str, context: int = 3) -> str:
    """Return a `git apply`-compatible unified diff, or "" if nothing changed."""
    if original == patched:
        return ""
    a = _lines(original)
    b = _lines(patched)
    diff = difflib.unified_diff(a, b, fromfile=f"a/{path}", tofile=f"b/{path}", n=context)
    out = "".join(diff)
    return out if out.endswith("\n") else out + "\n"


def replace_lines(text: str, line_start: int, line_end: int, replacement: str) -> str:
    """Replace 1-indexed inclusive line range with `replacement`, preserving EOL style."""
    eol = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    trailing = text.endswith(("\n", "\r\n"))
    new = replacement.splitlines()
    lines[line_start - 1 : line_end] = new
    out = eol.join(lines)
    return out + eol if trailing else out


def _lines(text: str) -> list[str]:
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith(("\n", "\r")):
        # difflib needs a newline on the last line to produce a clean hunk
        lines[-1] += "\n"
    return lines
