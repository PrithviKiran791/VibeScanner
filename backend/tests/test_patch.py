import pytest

from tests.conftest import make_sf
from vibeguard.engine.diff import unified_diff
from vibeguard.engine.patch import PatchMismatchError, apply_unified_diff
from vibeguard.engine.static.sinks import scan_sinks

SQL = (
    "import { db } from './db';\n"
    "\n"
    "export async function GET(q: string) {\n"
    "  return db.query(`SELECT * FROM t WHERE id = ${q}`);\n"
    "}\n"
)


def _sql_diff(text: str = SQL) -> str:
    [f] = scan_sinks(make_sf("route.ts", text))
    return f.unified_diff


def test_round_trip_matches_scan_time_patch():
    patched = apply_unified_diff(SQL, _sql_diff())
    assert 'db.query("SELECT * FROM t WHERE id = $1", [q])' in patched
    assert unified_diff("route.ts", SQL, patched) == _sql_diff()


def test_hunk_found_after_lines_added_above():
    shifted = "// a new comment\n// and another\n" + SQL
    patched = apply_unified_diff(shifted, _sql_diff())
    assert patched.startswith("// a new comment\n") and "$1" in patched


def test_changed_code_is_refused():
    edited = SQL.replace("${q}", "${q.trim()}")
    with pytest.raises(PatchMismatchError, match="changed after the scan"):
        apply_unified_diff(edited, _sql_diff())


def test_crlf_files_keep_crlf():
    crlf = SQL.replace("\n", "\r\n")
    patched = apply_unified_diff(crlf, _sql_diff())
    assert "\r\n" in patched and "\n" not in patched.replace("\r\n", "")


def test_missing_final_newline_preserved():
    original = "a\nb\nc"
    diff = unified_diff("f", original, "a\nB\nc")
    assert apply_unified_diff(original, diff) == "a\nB\nc"


def test_empty_diff_rejected():
    with pytest.raises(PatchMismatchError):
        apply_unified_diff(SQL, "")
