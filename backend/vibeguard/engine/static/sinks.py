"""AST sink detection for JS/TS: SQL interpolation, XSS sinks, eval, shell injection.

Each detector returns a finding and, where a mechanical fix is safe, a patch. Every patch is
re-parsed with Tree-sitter; a fix that produces a syntax error is dropped, never shipped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from tree_sitter import Node

from vibeguard.engine.diff import unified_diff
from vibeguard.engine.models import Finding, Severity, SourceFile
from vibeguard.engine.syntax.tree import (
    apply_edits,
    callee_name,
    line_end,
    line_start,
    parse,
    parses_cleanly,
    text,
    walk,
)

SQL_SHAPE = re.compile(
    r"^\s*(?:select\b.+\bfrom|insert\s+into|update\b.+\bset|delete\s+from|with\b.+\bselect)\b",
    re.I | re.S,
)
SQL_CALLEES = frozenset(
    {
        "query",
        "execute",
        "raw",
        "run",
        "all",
        "get",
        "prepare",
        "exec",
        "$queryRawUnsafe",
        "$executeRawUnsafe",
        "unsafe",
    }
)
PRISMA_SAFE = {"$queryRawUnsafe": "$queryRaw", "$executeRawUnsafe": "$executeRaw"}
SHELL_CALLEES = frozenset({"exec", "execSync", "spawnSync"})
MYSQL_STYLE = re.compile(
    r"""from\s+["'](?:mysql2?|sqlite3?|better-sqlite3)(?:/[\w/]+)?["']|require\(["'](?:mysql2?|sqlite3?|better-sqlite3)"""
)
SANITIZER = re.compile(r"\b(?:DOMPurify|sanitize|purify|xss)\b", re.I)
DOMPURIFY_IMPORT = 'import DOMPurify from "isomorphic-dompurify";'


@dataclass
class _Patch:
    edits: list[tuple[int, int, str]]


def scan_sinks(sf: SourceFile) -> list[Finding]:
    tree = parse(sf)
    if tree is None:
        return []
    root = tree.root_node
    out: list[Finding] = []
    for node in walk(root):
        match node.type:
            case "call_expression":
                out.extend(_check_call(sf, node))
            case "new_expression":
                if text(node.child_by_field_name("constructor")) == "Function" and _has_dynamic_arg(
                    node
                ):
                    out.append(_eval_finding(sf, node, "new Function()"))
            case "jsx_attribute":
                if f := _check_dangerous_html(sf, root, node):
                    out.append(f)
            case "assignment_expression":
                if f := _check_inner_html(sf, node):
                    out.append(f)
    return out


# --- SQL injection -------------------------------------------------------------------------


def _check_call(sf: SourceFile, call: Node) -> list[Finding]:
    name = callee_name(call)
    args = call.child_by_field_name("arguments")
    first = args.named_children[0] if args is not None and args.named_children else None
    if first is None:
        return []

    if name == "eval" and _is_dynamic(first):
        return [_eval_finding(sf, call, "eval()")]

    if name in SQL_CALLEES and first.type == "template_string" and _has_substitution(first):
        if SQL_SHAPE.search(_template_literal_text(first)):
            return [_sql_finding(sf, call, first, name)]

    if name in SHELL_CALLEES and _is_child_process_call(sf, call) and _is_dynamic_string(first):
        return [_shell_finding(sf, call)]

    return []


def _is_child_process_call(sf: SourceFile, call: Node) -> bool:
    """`exec(...)` imported from child_process, or `child_process.exec(...)` — not `regex.exec`."""
    if "child_process" not in sf.text:
        return False
    fn = call.child_by_field_name("function")
    if fn is None:
        return False
    if fn.type == "identifier":
        return True
    obj = fn.child_by_field_name("object") if fn.type == "member_expression" else None
    return obj is not None and text(obj) in ("child_process", "cp", "childProcess")


def _sql_finding(sf: SourceFile, call: Node, tmpl: Node, callee: str) -> Finding:
    patch = _sql_patch(sf, call, tmpl, callee)
    return _finding(
        sf,
        call,
        patch,
        rule_id="sql-string-interpolation",
        severity=Severity.CRITICAL,
        category="Injection",
        title="SQL Injection via Template String",
        cwe="CWE-89",
        explanation=(
            "User-controlled values are interpolated straight into the SQL text, so a crafted input "
            "can rewrite the query. Pass them as bound parameters so the driver escapes them."
        ),
    )


def _sql_patch(sf: SourceFile, call: Node, tmpl: Node, callee: str) -> _Patch | None:
    pieces = _template_pieces(tmpl)
    if pieces is None:
        return None
    args = call.child_by_field_name("arguments")
    assert args is not None

    if callee in PRISMA_SAFE:
        # prisma.$queryRawUnsafe(`...${x}`) -> prisma.$queryRaw`...${x}` (tagged = parameterized)
        sql, params = _parameterize(pieces, lambda _i, p: "${" + p + "}")
        if sql is None or len(args.named_children) != 1:
            return None
        fn = call.child_by_field_name("function")
        prop = fn.child_by_field_name("property") if fn is not None else None
        if prop is None:
            return None
        return _Patch(
            [
                (prop.start_byte, prop.end_byte, PRISMA_SAFE[callee]),
                (args.start_byte, args.end_byte, "`" + sql + "`"),
            ]
        )

    if len(args.named_children) != 1:
        return None  # already passes a params argument; let a human look
    mysql = bool(MYSQL_STYLE.search(sf.text))
    sql, params = _parameterize(pieces, lambda i, _p: "?" if mysql else f"${i}")
    if sql is None:
        return None
    replacement = f"{json.dumps(sql)}, [{', '.join(params)}]"
    return _Patch([(tmpl.start_byte, tmpl.end_byte, replacement)])


def _template_pieces(tmpl: Node) -> list[tuple[str, str]] | None:
    """[("lit", "SELECT ..."), ("expr", "id"), ...] or None if escapes make rewriting unsafe."""
    pieces: list[tuple[str, str]] = []
    for child in tmpl.children:
        if child.type == "string_fragment":
            pieces.append(("lit", text(child)))
        elif child.type == "template_substitution":
            inner = child.named_children
            if len(inner) != 1:
                return None
            pieces.append(("expr", text(inner[0])))
        elif child.type == "escape_sequence":
            return None
    return pieces


def _parameterize(pieces: list[tuple[str, str]], placeholder) -> tuple[str | None, list[str]]:
    """Turn interpolations into bound params. A quoted region containing interpolation
    (`'%${q}%'`) becomes ONE param whose value is a JS template of the region's contents."""
    sql: list[str] = []
    params: list[str] = []
    quoted: list[tuple[str, str]] | None = None

    def emit(param: str) -> None:
        params.append(param)
        sql.append(placeholder(len(params), param))

    for kind, value in pieces:
        if kind == "expr":
            if quoted is None:
                emit(value)
            else:
                quoted.append(("expr", value))
            continue
        for ch in value:
            if quoted is None:
                if ch == "'":
                    quoted = []
                else:
                    sql.append(ch)
            elif ch == "'":
                if any(k == "expr" for k, _ in quoted):
                    emit(_as_js_template(quoted))
                else:
                    sql.append("'" + "".join(v for _, v in quoted) + "'")
                quoted = None
            else:
                quoted.append(("lit", ch))

    if quoted is not None:
        return None, []
    return "".join(sql), params


def _as_js_template(parts: list[tuple[str, str]]) -> str:
    if len(parts) == 1 and parts[0][0] == "expr":
        return parts[0][1]
    body = "".join(v.replace("`", "\\`") if k == "lit" else "${" + v + "}" for k, v in parts)
    return "`" + body + "`"


# --- XSS -----------------------------------------------------------------------------------


def _check_dangerous_html(sf: SourceFile, root: Node, attr: Node) -> Finding | None:
    name = attr.named_children[0] if attr.named_children else None
    if name is None or text(name) != "dangerouslySetInnerHTML":
        return None
    html_value = _html_value(attr)
    if html_value is None or not _is_dynamic(html_value):
        return None
    if SANITIZER.search(text(html_value)):
        return None

    edits = [
        (html_value.start_byte, html_value.end_byte, f"DOMPurify.sanitize({text(html_value)})")
    ]
    if "DOMPurify" not in sf.text:
        offset = _import_insertion_point(root)
        insert = DOMPURIFY_IMPORT + "\n" if offset == 0 else "\n" + DOMPURIFY_IMPORT
        edits.append((offset, offset, insert))

    return _finding(
        sf,
        attr,
        _Patch(edits),
        rule_id="react-dangerously-set-inner-html",
        severity=Severity.HIGH,
        category="Cross-Site Scripting",
        title="Unsanitized dangerouslySetInnerHTML",
        cwe="CWE-79",
        explanation=(
            "Raw HTML from data is injected into the page, so a stored `<script>` or `onerror=` payload "
            "runs in every visitor's session. Sanitize it with DOMPurify (add `isomorphic-dompurify`)."
        ),
    )


def _html_value(attr: Node) -> Node | None:
    expr = next((c for c in attr.named_children if c.type == "jsx_expression"), None)
    obj = expr.named_children[0] if expr is not None and expr.named_children else None
    if obj is None or obj.type != "object":
        return None
    for pair in obj.named_children:
        if pair.type == "pair" and text(pair.child_by_field_name("key")).strip("'\"") == "__html":
            return pair.child_by_field_name("value")
    return None


def _check_inner_html(sf: SourceFile, assign: Node) -> Finding | None:
    left = assign.child_by_field_name("left")
    right = assign.child_by_field_name("right")
    if left is None or right is None or left.type != "member_expression":
        return None
    prop = left.child_by_field_name("property")
    if text(prop) not in ("innerHTML", "outerHTML"):
        return None
    if not _is_dynamic(right):
        return None
    if SANITIZER.search(text(right)):
        return None
    patch = (
        _Patch([(prop.start_byte, prop.end_byte, "textContent")])
        if text(prop) == "innerHTML"
        else None
    )
    return _finding(
        sf,
        assign,
        patch,
        rule_id="dom-inner-html",
        severity=Severity.HIGH,
        category="Cross-Site Scripting",
        title=f"Dynamic {text(prop)} Assignment",
        cwe="CWE-79",
        explanation=(
            f"Assigning dynamic data to `{text(prop)}` parses it as HTML, so attacker-supplied markup "
            "executes. Use `textContent` for text, or sanitize with DOMPurify if markup is required."
        ),
    )


def _import_insertion_point(root: Node) -> int:
    """Byte offset after the last import (or a leading "use client" directive); 0 for the top."""
    last_import = None
    directive_end = None
    for child in root.named_children:
        if child.type == "import_statement":
            last_import = child
        elif child.type == "expression_statement" and directive_end is None and last_import is None:
            first = child.named_children[0] if child.named_children else None
            if first is not None and first.type == "string":
                directive_end = child
    anchor = last_import or directive_end
    return 0 if anchor is None else anchor.end_byte


# --- eval / shell --------------------------------------------------------------------------


def _eval_finding(sf: SourceFile, node: Node, what: str) -> Finding:
    return _finding(
        sf,
        node,
        None,
        rule_id="dynamic-code-eval",
        severity=Severity.HIGH,
        category="Injection",
        title=f"Dynamic Code Execution via {what}",
        cwe="CWE-95",
        explanation=(
            f"`{what}` runs whatever string it receives as code, so any user influence over that "
            "string is remote code execution. Replace it with `JSON.parse` or an explicit lookup table."
        ),
    )


def _shell_finding(sf: SourceFile, call: Node) -> Finding:
    return _finding(
        sf,
        call,
        None,
        rule_id="shell-command-injection",
        severity=Severity.CRITICAL,
        category="Injection",
        title="OS Command Injection",
        cwe="CWE-78",
        explanation=(
            "A shell command is built from dynamic values, so input like `; rm -rf /` runs extra "
            "commands. Use `execFile`/`spawn` with an argument array and no shell."
        ),
    )


# --- shared --------------------------------------------------------------------------------


def _finding(
    sf: SourceFile,
    node: Node,
    patch: _Patch | None,
    *,
    rule_id: str,
    severity: Severity,
    category: str,
    title: str,
    cwe: str,
    explanation: str,
) -> Finding:
    lo, hi = line_start(node), line_end(node)
    fixed = diff = None
    if patch is not None:
        patched = apply_edits(sf.text, patch.edits)
        if sf.language and parses_cleanly(sf.language, patched):
            diff = unified_diff(sf.path, sf.text, patched) or None
            fixed = _changed_region(sf.text, patched, lo, hi)
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=category,
        title=title,
        cwe_id=cwe,
        file_path=sf.path,
        line_start=lo,
        line_end=hi,
        snippet_original=sf.snippet(lo, hi, context=0),
        snippet_fixed=fixed,
        unified_diff=diff,
        explanation=explanation,
    )


def _changed_region(original: str, patched: str, lo: int, hi: int) -> str:
    """The patched version of lines lo..hi (accounts for lines inserted above, e.g. imports)."""
    shift = len(patched.splitlines()) - len(original.splitlines())
    return "\n".join(patched.splitlines()[lo - 1 + shift : hi + shift])


def _is_dynamic(node: Node) -> bool:
    """Anything except a plain string literal or a template literal with no `${}`."""
    if node.type == "string":
        return False
    return not (node.type == "template_string" and not _has_substitution(node))


def _has_substitution(node: Node) -> bool:
    return any(c.type == "template_substitution" for c in node.children)


def _has_dynamic_arg(node: Node) -> bool:
    args = node.child_by_field_name("arguments")
    return args is not None and any(
        _is_dynamic_string(a) or a.type == "identifier" for a in args.named_children
    )


def _is_dynamic_string(node: Node) -> bool:
    if node.type == "template_string":
        return _has_substitution(node)
    if node.type == "binary_expression":
        return any(c.type not in ("string", "+") for c in node.children)
    return node.type in ("identifier", "member_expression", "call_expression")


def _template_literal_text(tmpl: Node) -> str:
    return "".join(text(c) for c in tmpl.children if c.type == "string_fragment")
