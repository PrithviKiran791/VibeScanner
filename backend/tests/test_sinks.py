import pytest

from tests.conftest import make_sf
from vibeguard.engine.static.sinks import scan_sinks


def _one(path: str, code: str):
    findings = scan_sinks(make_sf(path, code))
    assert len(findings) == 1, findings
    return findings[0]


def test_pg_query_template_becomes_numbered_params():
    f = _one("a.ts", "await db.query(`SELECT * FROM users WHERE id = ${id} AND org = ${org}`);\n")
    assert f.cwe_id == "CWE-89"
    assert (
        f.snippet_fixed
        == 'await db.query("SELECT * FROM users WHERE id = $1 AND org = $2", [id, org]);'
    )


def test_quoted_like_pattern_becomes_single_param():
    f = _one("a.ts", "db.query(`SELECT * FROM p WHERE t LIKE '%${q}%'`);\n")
    assert f.snippet_fixed == 'db.query("SELECT * FROM p WHERE t LIKE $1", [`%${q}%`]);'


def test_mysql_uses_question_marks():
    code = (
        "import mysql from \"mysql2/promise\";\nconn.execute(`DELETE FROM t WHERE id = '${id}'`);\n"
    )
    f = _one("a.ts", code)
    assert f.snippet_fixed == 'conn.execute("DELETE FROM t WHERE id = ?", [id]);'


def test_prisma_unsafe_becomes_tagged_template():
    f = _one("a.ts", "await prisma.$queryRawUnsafe(`SELECT * FROM u WHERE email = '${email}'`);\n")
    assert f.snippet_fixed == "await prisma.$queryRaw`SELECT * FROM u WHERE email = ${email}`;"


def test_query_with_existing_params_reported_without_patch():
    f = _one("a.ts", "db.query(`SELECT * FROM t WHERE a = ${a}`, []);\n")
    assert f.unified_diff is None


def test_non_sql_templates_and_static_sql_are_ignored():
    assert scan_sinks(make_sf("a.ts", "db.query(`SELECT 1`);\nlog.get(`hello ${name}`);\n")) == []


def test_dangerously_set_inner_html_wrapped_and_import_added():
    code = '"use client";\nimport React from "react";\nexport const C = ({ h }) => <div dangerouslySetInnerHTML={{ __html: h }} />;\n'
    f = _one("c.tsx", code)
    assert "DOMPurify.sanitize(h)" in f.snippet_fixed
    assert '+import DOMPurify from "isomorphic-dompurify";' in f.unified_diff


def test_sanitized_or_static_html_is_ignored():
    code = (
        "const a = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(h) }} />;\n"
        'const b = <div dangerouslySetInnerHTML={{ __html: "<b>hi</b>" }} />;\n'
    )
    assert scan_sinks(make_sf("c.tsx", code)) == []


def test_inner_html_assignment_fixed_to_text_content():
    f = _one("a.js", "el.innerHTML = userInput;\n")
    assert f.snippet_fixed == "el.textContent = userInput;"


@pytest.mark.parametrize(
    "code", ["eval(input);\n", "const f = new Function(body);\n", "eval(`x${y}`);\n"]
)
def test_dynamic_eval(code):
    assert _one("a.js", code).cwe_id == "CWE-95"


def test_literal_eval_ignored():
    assert scan_sinks(make_sf("a.js", 'eval("1 + 1");\n')) == []


def test_shell_injection_requires_child_process():
    code = 'import { exec } from "child_process";\nexec(`ls ${dir}`);\n'
    assert _one("a.ts", code).cwe_id == "CWE-78"
    # RegExp.prototype.exec is not a shell
    assert scan_sinks(make_sf("b.ts", "const m = re.exec(`${input}`);\n")) == []


def test_python_files_are_skipped():
    assert scan_sinks(make_sf("a.py", "eval(x)\n")) == []
