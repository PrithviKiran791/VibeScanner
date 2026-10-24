"""Code Quality Score: smell detection, scoring, grades and the fixes it offers."""

import ast

from tests.conftest import make_sf
from vibeguard.engine.models import Finding, FindingDomain, Severity
from vibeguard.engine.patch import apply_unified_diff
from vibeguard.engine.scoring import count_by_severity, hardening_index
from vibeguard.engine.static.quality import analyze_quality, grade_for
from vibeguard.engine.syntax.tree import parses_cleanly


def _rules(findings: list[Finding]) -> set[str]:
    return {f.rule_id.removeprefix("quality/") for f in findings}


def _by_rule(findings: list[Finding], rule: str) -> Finding:
    return next(f for f in findings if f.rule_id == f"quality/{rule}")


BLOATED = "\n".join(
    [
        "import { useState } from 'react';",
        "import { unusedThing } from './lib';",
        "",
        "export async function POST(req: any) {",
        "  const body = (await req.json()) as any;",
        "  console.log('incoming', body);",
        "  try {",
        "    await save(body);",
        "  } catch (e) {}",
        "  debugger;",
        "  // @ts-ignore",
        "  return Response.json(body.missing);",
        "}",
        "",
        "export function handler() {",
        *[f"  const v{i} = {i};" for i in range(90)],
        "  return useState;",
        "}",
        *[f"export const filler{i} = {i};" for i in range(350)],
    ]
)


def test_bloated_ai_file_is_flagged_on_every_metric():
    report, findings = analyze_quality([make_sf("app/api/orders/route.ts", BLOATED)])
    assert report is not None
    assert {"large-file", "long-function", "any", "ts-ignore", "empty-catch", "console-log",
            "debugger", "unused-import"} <= _rules(findings)  # fmt: skip
    assert all(f.domain == FindingDomain.QUALITY for f in findings)

    b = report.breakdown
    assert b.modularity < 100 and b.type_safety < 100 and b.error_hygiene < 100
    assert b.cleanliness < 100
    assert b.total_loc == len([line for line in BLOATED.splitlines() if line.strip()])
    assert b.files_scanned == 1 and b.code_smells_count >= 8
    assert report.score < 100 and report.grade == grade_for(report.score)

    # Grouped: one finding for both `any`s, naming the count
    assert _by_rule(findings, "any").title == "2 uses of `any`"
    assert _by_rule(findings, "unused-import").explanation.startswith("Unused: unusedThing.")
    # Swallowed in an API route: a high-severity smell
    assert _by_rule(findings, "empty-catch").severity == Severity.HIGH
    assert _by_rule(findings, "empty-catch").title == "Swallowed exception in POST"


def test_empty_catch_fix_rethrows_and_still_parses():
    src = "async function load() {\n  try {\n    await go();\n  } catch (e) {}\n}\n"
    _, findings = analyze_quality([make_sf("lib/load.ts", src)])
    fix = _by_rule(findings, "empty-catch").unified_diff
    patched = apply_unified_diff(src, fix)
    assert "throw e;" in patched and parses_cleanly("typescript", patched)


def test_catch_without_a_binding_gets_one():
    src = "function f() {\n  try {\n    go();\n  } catch {}\n}\n"
    _, findings = analyze_quality([make_sf("lib/f.js", src)])
    patched = apply_unified_diff(src, _by_rule(findings, "empty-catch").unified_diff)
    assert "catch (err) {" in patched and "throw err;" in patched


def test_log_only_catch_is_a_swallow_too():
    src = "function f() {\n  try {\n    go();\n  } catch (err) {\n    console.log(err);\n  }\n}\n"
    _, findings = analyze_quality([make_sf("lib/f.ts", src)])
    f = _by_rule(findings, "log-only-catch")
    patched = apply_unified_diff(src, f.unified_diff)
    assert "    console.log(err);\n    throw err;\n" in patched


def test_console_log_fix_deletes_only_standalone_statements():
    src = (
        "export function f(x: number) {\n"
        "  console.log('a', x);\n"
        "  if (x) console.log('inline');\n"  # removing this would leave `if (x)` dangling
        "  return x;\n"
        "}\n"
    )
    _, findings = analyze_quality([make_sf("lib/f.ts", src)])
    f = _by_rule(findings, "console-log")
    assert f.title == "2 leftover console.log calls"
    patched = apply_unified_diff(src, f.unified_diff)
    assert "console.log('a', x);" not in patched
    assert "if (x) console.log('inline');" in patched


def test_python_smells_and_fixes():
    src = (
        "import os\n"
        "import json\n"
        "\n"
        "@app.post('/orders')\n"
        "def create(payload):\n"
        "    try:\n"
        "        return json.dumps(payload)\n"
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "def helper():\n"
        "    print('debug')\n"
    )
    _, findings = analyze_quality([make_sf("api/orders.py", src)])
    assert {"empty-catch", "untyped-route", "print", "unused-import"} <= _rules(findings)
    assert "Unused: os." in _by_rule(findings, "unused-import").explanation

    swallow = _by_rule(findings, "empty-catch")
    assert swallow.title == "Swallowed exception in create" and swallow.severity == Severity.HIGH
    patched = apply_unified_diff(src, swallow.unified_diff)
    assert "    except Exception:\n        raise\n" in patched
    ast.parse(patched)


def test_print_in_scripts_is_fine():
    src = "def main():\n    print('hi')\n\nif __name__ == '__main__':\n    main()\n"
    _, findings = analyze_quality([make_sf("tools/run.py", src)])
    assert "print" not in _rules(findings)


def test_else_if_chains_are_not_nesting_but_real_nesting_is():
    chain = (
        "function f(x) {\n"
        + "".join(
            f"  {'if' if i == 0 else '} else if'} (x === {i}) {{\n    go();\n" for i in range(8)
        )
        + "  }\n}\n"
    )
    deep = (
        "function g(a, b, c, d, e) {\n"
        "  if (a) {\n    if (b) {\n      if (c) {\n        if (d) {\n          if (e) {\n"
        "            go();\n          }\n        }\n      }\n    }\n  }\n}\n"
    )
    _, flat = analyze_quality([make_sf("lib/chain.js", chain)])
    _, nested = analyze_quality([make_sf("lib/deep.js", deep)])
    assert "deep-nesting" not in _rules(flat)
    assert _by_rule(nested, "deep-nesting").title == "Deeply nested conditionals in g"


def test_python_elif_is_not_nesting():
    src = "def f(x):\n" + "".join(
        f"    {'if' if i == 0 else 'elif'} x == {i}:\n        return {i}\n" for i in range(8)
    )
    _, findings = analyze_quality([make_sf("svc/f.py", src)])
    assert "deep-nesting" not in _rules(findings)


def test_database_calls_belong_outside_components():
    src = (
        "import { prisma } from '@/lib/db';\n"
        "async function loadUsers() {\n"
        "  return prisma.user.findMany();\n"  # a data helper: fine
        "}\n"
        "export default async function UsersPage() {\n"
        "  const posts = await prisma.post.findMany();\n"  # in the component: smell
        "  const users = await loadUsers();\n"
        "  return <ul>{users.length + posts.length}</ul>;\n"
        "}\n"
    )
    _, findings = analyze_quality([make_sf("app/users/page.tsx", src)])
    db = [f for f in findings if f.rule_id == "quality/db-in-component"]
    assert [f.line_start for f in db] == [6]
    assert db[0].severity == Severity.HIGH


def test_raw_fetch_only_flagged_in_client_components():
    client = (
        "'use client';\nexport function Feed() {\n"
        "  useEffect(() => { fetch('/api/feed'); }, []);\n  return <div />;\n}\n"
    )
    server = "export default async function Feed() {\n  await fetch('https://x');\n  return <div />;\n}\n"
    _, a = analyze_quality([make_sf("components/Feed.tsx", client)])
    _, b = analyze_quality([make_sf("app/feed/page.tsx", server)])
    assert "fetch-in-component" in _rules(a)
    assert "fetch-in-component" not in _rules(b)


def test_commented_out_code_blocks():
    block = "\n".join(f"// const old{i} = compute({i});" for i in range(12))
    prose = "\n".join(f"// This explains step {i} of the algorithm in words" for i in range(12))
    _, code = analyze_quality([make_sf("lib/a.ts", block + "\nexport const x = 1;\n")])
    _, words = analyze_quality([make_sf("lib/b.ts", prose + "\nexport const x = 1;\n")])
    assert "commented-out-code" in _rules(code)
    assert "commented-out-code" not in _rules(words)


def test_clean_code_gets_an_a():
    src = "export function add(a: number, b: number): number {\n  return a + b;\n}\n"
    report, findings = analyze_quality([make_sf("lib/math.ts", src)])
    assert findings == []
    assert report.score == 100 and report.grade == "A"


def test_scores_are_normalized_by_size():
    smelly = "export function f(x: any) {\n  console.log(x);\n}\n"
    filler = "\n".join(f"export const c{i}: number = {i};" for i in range(3000))
    small, _ = analyze_quality([make_sf("lib/f.ts", smelly)])
    big, _ = analyze_quality([make_sf("lib/f.ts", smelly), make_sf("lib/consts.ts", filler)])
    assert big.breakdown.type_safety > small.breakdown.type_safety


def test_tests_and_type_declarations_are_skipped():
    noisy = "export function t(x: any) {\n  console.log(x);\n}\n"
    report, findings = analyze_quality(
        [
            make_sf("src/__tests__/a.ts", noisy),
            make_sf("src/b.test.ts", noisy),
            make_sf("types/global.d.ts", noisy),
            make_sf("tests/test_c.py", "print(1)\n"),
        ]
    )
    assert report is None and findings == []


def test_grade_boundaries():
    assert [grade_for(s) for s in (100, 90, 89, 80, 79, 65, 64, 50, 49, 0)] == [
        "A", "A", "B", "B", "C", "C", "D", "D", "F", "F",
    ]  # fmt: skip


def test_quality_findings_never_touch_the_hardening_index():
    smell = Finding(
        rule_id="quality/empty-catch",
        severity=Severity.HIGH,
        category="Error Hygiene",
        title="Swallowed exception",
        file_path="a.ts",
        line_start=1,
        line_end=1,
        snippet_original="",
        explanation="",
        domain=FindingDomain.QUALITY,
    )
    vuln = smell.model_copy(update={"domain": FindingDomain.SECURITY, "rule_id": "sql"})
    assert hardening_index([smell]) == 100
    assert hardening_index([smell, vuln]) == 88
    assert count_by_severity([smell, vuln]).high == 1


def test_anonymous_callbacks_are_not_given_a_made_up_name():
    src = "useEffect(() => {\n  try {\n    go();\n  } catch (e) {}\n}, []);\n"
    _, findings = analyze_quality([make_sf("components/Feed.tsx", src)])
    assert _by_rule(findings, "empty-catch").title == "Swallowed exception"
