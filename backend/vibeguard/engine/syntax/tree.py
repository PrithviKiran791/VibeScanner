"""Thin Tree-sitter helpers shared by sink detection and route extraction."""

from __future__ import annotations

from collections.abc import Iterator
from functools import cache

from tree_sitter import Node, Parser, Tree
from tree_sitter_language_pack import get_parser

from vibeguard.engine.models import SourceFile

JS_FAMILY = frozenset({"javascript", "typescript", "tsx"})


@cache
def _parser(language: str) -> Parser:
    return get_parser(language)


def parse(sf: SourceFile) -> Tree | None:
    if sf.language not in JS_FAMILY:
        return None
    return _parser(sf.language).parse(sf.text.encode("utf-8"))


def parses_cleanly(language: str, text: str) -> bool:
    return not _parser(language).parse(text.encode("utf-8")).root_node.has_error


def walk(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def text(node: Node | None) -> str:
    return node.text.decode("utf-8") if node is not None and node.text is not None else ""


def line_start(node: Node) -> int:
    return node.start_point[0] + 1


def line_end(node: Node) -> int:
    return node.end_point[0] + 1


def callee_name(call: Node) -> str:
    """`foo(...)` -> "foo", `a.b.query(...)` -> "query"."""
    fn = call.child_by_field_name("function")
    if fn is None:
        return ""
    if fn.type == "member_expression":
        return text(fn.child_by_field_name("property"))
    return text(fn)


def apply_edits(source: str, edits: list[tuple[int, int, str]]) -> str:
    """Apply (start_byte, end_byte, replacement) edits; edits must not overlap."""
    buf = source.encode("utf-8")
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        buf = buf[:start] + repl.encode("utf-8") + buf[end:]
    return buf.decode("utf-8")


def has_directive(block: Node, directive: str) -> bool:
    """True if the first statement of a program/statement_block is the string `directive`."""
    for child in block.named_children:
        if child.type == "comment":
            continue
        if child.type == "expression_statement" and child.named_children:
            first = child.named_children[0]
            return first.type == "string" and text(first).strip("'\"") == directive
        return False
    return False
