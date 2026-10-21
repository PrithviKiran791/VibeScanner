"""Semantic relevance pruning (app_flow Pass 2).

Extract only the code an attacker can reach — route handlers, server actions, Express routes,
middleware — and tag each unit with cheap signals so the LLM budget goes to the riskiest code.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from tree_sitter import Node

from vibeguard.engine.models import CodeUnit, SourceFile
from vibeguard.engine.syntax.tree import has_directive, line_end, line_start, parse, text, walk

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
EXPRESS_RECEIVERS = frozenset({"app", "router", "server", "api", "routes"})
EXPRESS_METHODS = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "all": None,
}

APP_ROUTE = re.compile(r"(?:^|/)app/(?:.+/)?route\.[jt]sx?$")
PAGES_API = re.compile(r"(?:^|/)pages/api/.+\.[jt]sx?$")
MIDDLEWARE = re.compile(r"^(?:src/)?middleware\.[jt]s$")

AUTH_SIGNAL = re.compile(
    r"getServerSession|\bauth\(\)|currentUser|getUser\(|requireAuth|requireUser|withAuth|"
    r"verifyToken|jwt\.verify|isAuthenticated|getToken\(|clerk|lucia|req\.user|ctx\.user|"
    r"session\??\.user"
)
DB_SIGNAL = re.compile(
    r"\bprisma\.|\bdb\.|\.query\(|supabase|\.from\(|knex|mongoose|drizzle|\.findUnique|"
    r"\.findFirst|\.findMany|\.findOne|\.findById|\.insert|\.upsert|\.execute\(|sql`"
)
INPUT_SIGNAL = re.compile(
    r"\bparams\b|searchParams|req\.body|req\.query|req\.params|request\.json\(|\.formData\(|"
    r"formData\.get|\.json\(\)"
)
MUTATION_SIGNAL = re.compile(r"\.(?:create|update|delete|upsert|insert|destroy|remove|save)\w*\(")


def extract_units(sf: SourceFile) -> list[CodeUnit]:
    tree = parse(sf)
    if tree is None:
        return []
    root = tree.root_node
    imports = [text(c) for c in root.named_children if c.type == "import_statement"]

    found: list[tuple[str, str, str | None, Node]] = []  # (kind, name, method, node)
    path = sf.path

    if APP_ROUTE.search(path):
        found += [("route_handler", n, n, node) for n, node in _exports(root) if n in HTTP_METHODS]
    elif PAGES_API.search(path):
        found += [("api_route", n, None, node) for n, node in _exports(root) if n == "default"]
    elif MIDDLEWARE.search(path):
        found += [
            ("middleware", n, None, node)
            for n, node in _exports(root)
            if n in ("middleware", "default")
        ]

    if has_directive(root, "use server"):
        found += [("server_action", n, None, node) for n, node in _exports(root) if n != "default"]
    else:
        found += [("server_action", n, None, node) for n, node in _inline_server_actions(root)]

    found += list(_express_routes(root))

    units: list[CodeUnit] = []
    seen: set[tuple[int, int]] = set()
    for kind, name, method, node in found:
        span = (node.start_byte, node.end_byte)
        if span in seen:
            continue
        seen.add(span)
        code = text(node)
        units.append(
            CodeUnit(
                unit_id=f"{path}#{name}@{line_start(node)}",
                file_path=path,
                kind=kind,
                name=name,
                http_method=method,
                line_start=line_start(node),
                line_end=line_end(node),
                code=code,
                is_mutation=(method in MUTATING)
                or kind == "server_action"
                or bool(MUTATION_SIGNAL.search(code)),
                has_auth_signal=bool(AUTH_SIGNAL.search(code)),
                touches_db=bool(DB_SIGNAL.search(code)),
                reads_input=bool(INPUT_SIGNAL.search(code)) or kind == "server_action",
                imports=imports,
            )
        )
    return units


def select_for_llm(units: list[CodeUnit], max_units: int) -> list[CodeUnit]:
    """Keep units that can plausibly hide an auth/logic bug, riskiest first."""
    relevant = [
        u for u in units if u.kind == "middleware" or u.touches_db or u.is_mutation or u.reads_input
    ]
    relevant.sort(key=lambda u: (-u.priority, u.file_path, u.line_start))
    return relevant[:max_units]


def _exports(root: Node) -> Iterator[tuple[str, Node]]:
    """Yield (exported name, node to analyze) for top-level exports."""
    for stmt in root.named_children:
        if stmt.type != "export_statement":
            continue
        is_default = any(c.type == "default" for c in stmt.children)
        decl = stmt.child_by_field_name("declaration")
        if decl is None:
            value = stmt.child_by_field_name("value")
            if is_default and value is not None:
                yield "default", stmt
            continue
        if decl.type in ("function_declaration", "generator_function_declaration"):
            yield ("default" if is_default else text(decl.child_by_field_name("name"))), stmt
        elif decl.type == "lexical_declaration":
            for declarator in decl.named_children:
                if declarator.type == "variable_declarator":
                    yield text(declarator.child_by_field_name("name")), stmt


def _inline_server_actions(root: Node) -> Iterator[tuple[str, Node]]:
    """Functions whose body starts with "use server" (actions defined inside components)."""
    for node in walk(root):
        if node.type not in ("function_declaration", "arrow_function", "function_expression"):
            continue
        body = node.child_by_field_name("body")
        if (
            body is not None
            and body.type == "statement_block"
            and has_directive(body, "use server")
        ):
            name = text(node.child_by_field_name("name"))
            if not name and node.parent is not None and node.parent.type == "variable_declarator":
                name = text(node.parent.child_by_field_name("name"))
            yield name or "anonymous_action", node


def _express_routes(root: Node) -> Iterator[tuple[str, str, str | None, Node]]:
    for node in walk(root):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        receiver = text(fn.child_by_field_name("object"))
        verb = text(fn.child_by_field_name("property"))
        if receiver not in EXPRESS_RECEIVERS or verb not in EXPRESS_METHODS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None or not args.named_children or args.named_children[0].type != "string":
            continue
        route = text(args.named_children[0]).strip("'\"`")
        yield "express_route", f"{verb.upper()} {route}", EXPRESS_METHODS[verb], node
