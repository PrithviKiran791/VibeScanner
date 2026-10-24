"""Code Quality Score: deterministic "vibe-coding smell" analysis.

Five metrics, each scored 0-100 from smells per 1,000 lines of code (so a big repo isn't
punished for being big), then blended into one score and a letter grade:

- Modularity: files over 400 lines, functions over 80 lines.
- Type safety: `any`, `@ts-ignore` / `@ts-nocheck`; untyped Python route handlers.
- Error hygiene: catch / except blocks that swallow the error (empty, or only log it).
- Cleanliness: console.log / print / debugger leftovers, commented-out code, unused imports.
- Architecture: database calls or raw fetch inside UI components, if-nesting deeper than 4.

JS/TS go through Tree-sitter, Python through the stdlib `ast`. Smells become QUALITY findings,
grouped per file and rule so one chatty file can't flood the list. Fixes are offered only where
they are mechanical: deleting debug statements, and rethrowing from catch blocks that swallow.
Test files are skipped: logging and loose types are normal there.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from tree_sitter import Node

from vibeguard.engine.diff import unified_diff
from vibeguard.engine.models import (
    Finding,
    FindingDomain,
    QualityBreakdown,
    QualityReport,
    Severity,
    SourceFile,
)
from vibeguard.engine.syntax.tree import (
    JS_FAMILY,
    apply_edits,
    has_directive,
    line_end,
    line_start,
    parse,
    parses_cleanly,
    text,
    walk,
)

MAX_FILE_LINES = 400
MAX_FUNCTION_LINES = 80
MAX_IF_DEPTH = 4
MIN_COMMENTED_BLOCK = 10
MAX_QUALITY_FINDINGS = 60

METRICS = ("modularity", "type_safety", "error_hygiene", "cleanliness", "architecture")
CATEGORY = {
    "modularity": "Modularity",
    "type_safety": "Type Safety",
    "error_hygiene": "Error Hygiene",
    "cleanliness": "Cleanliness",
    "architecture": "Architecture",
}
# Score points lost per weighted smell per 1,000 lines, by metric
SENSITIVITY = {
    "modularity": 5.0,
    "type_safety": 4.0,
    "error_hygiene": 8.0,
    "cleanliness": 2.0,
    "architecture": 5.0,
}
BLEND = {
    "modularity": 0.20,
    "type_safety": 0.20,
    "error_hygiene": 0.25,
    "cleanliness": 0.15,
    "architecture": 0.20,
}
GRADES = ((90, "A"), (80, "B"), (65, "C"), (50, "D"))

_TEST_PATH = re.compile(
    r"(^|/)(__tests__|__mocks__|tests?|spec|e2e|cypress|fixtures?)(/|$)"
    r"|\.(test|spec|stories)\.[^/]+$|(^|/)(test_[^/]+|[^/]+_test|conftest)\.py$"
    r"|\.d\.ts$|(^|/)[^/]+\.config\.[cm]?[jt]s$"
)
_DB_ROOTS = frozenset(
    {"prisma", "db", "supabase", "knex", "pool", "mongoose", "sequelize", "drizzle", "sql"}
)
_CONSOLE_DEBUG = frozenset({"log", "debug", "info", "trace", "table", "dir"})
_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
    }
)
_ROUTE_DECORATORS = frozenset({"get", "post", "put", "patch", "delete", "route", "api_route"})
_CODE_LIKE = re.compile(
    r"[;{}]\s*$|^\s*(if|for|while|return|const|let|var|def|class|import|from|function|await)\b"
    r"|\w+\s*=\s*\S|\w+\([^)]*\)"
)


@dataclass
class _Smell:
    metric: str
    rule: str
    weight: float
    line_start: int
    line_end: int
    severity: Severity
    name: str | None = None  # enclosing function, for titles


@dataclass
class _FileSmells:
    sf: SourceFile
    smells: list[_Smell] = field(default_factory=list)
    # rule -> (start_byte, end_byte, replacement) edits that fix every occurrence in the file
    edits: dict[str, list[tuple[int, int, str]]] = field(default_factory=lambda: defaultdict(list))
    # Python edits are whole-line: rule -> {line number: replacement lines (None = delete)}
    line_edits: dict[str, dict[int, list[str] | None]] = field(
        default_factory=lambda: defaultdict(dict)
    )

    def add(self, *args, **kwargs) -> None:
        self.smells.append(_Smell(*args, **kwargs))


def analyze_quality(files: Iterable[SourceFile]) -> tuple[QualityReport | None, list[Finding]]:
    """Score the repo and return its QUALITY findings (None if there's no JS/TS/Python)."""
    per_file: list[_FileSmells] = []
    total_loc = 0
    for sf in files:
        if sf.language not in JS_FAMILY and sf.language != "python":
            continue
        if _TEST_PATH.search(sf.path.lower()):
            continue
        loc = sum(1 for line in sf.lines if line.strip())
        if loc == 0:
            continue
        total_loc += loc
        fs = _FileSmells(sf)
        if sf.language == "python":
            _analyze_python(fs)
        else:
            _analyze_js(fs)
        _commented_out_code(fs)
        per_file.append(fs)

    if total_loc == 0:
        return None, []

    kloc = max(1.0, total_loc / 1000)
    points: dict[str, float] = dict.fromkeys(METRICS, 0.0)
    smell_count = 0
    for fs in per_file:
        for s in fs.smells:
            points[s.metric] += s.weight
            smell_count += 1
    sub = {m: max(0, min(100, round(100 - SENSITIVITY[m] * points[m] / kloc))) for m in METRICS}
    score = round(sum(BLEND[m] * sub[m] for m in METRICS))
    report = QualityReport(
        score=score,
        grade=grade_for(score),
        breakdown=QualityBreakdown(
            **sub,
            total_loc=total_loc,
            files_scanned=len(per_file),
            code_smells_count=smell_count,
        ),
    )

    findings = [f for fs in per_file for f in _findings(fs)]
    findings.sort(key=lambda f: (-f.severity.rank, f.file_path, f.line_start))
    return report, findings[:MAX_QUALITY_FINDINGS]


def grade_for(score: int) -> str:
    for floor, grade in GRADES:
        if score >= floor:
            return grade
    return "F"


# --- JavaScript / TypeScript -------------------------------------------------------------------


def _analyze_js(fs: _FileSmells) -> None:
    sf = fs.sf
    tree = parse(sf)
    if tree is None:
        return
    root = tree.root_node
    loc = sum(1 for line in sf.lines if line.strip())
    _large_file(fs, loc)
    is_ts = sf.language in ("typescript", "tsx")
    is_route = _is_route_file(sf.path) or has_directive(root, "use server")
    is_client = has_directive(root, "use client")
    has_jsx = any(n.type.startswith("jsx_") for n in walk(root))
    used = _js_identifier_uses(root) if not sf.path.endswith(".d.ts") else None
    jsx_cache: dict[tuple[int, int], bool] = {}

    for node in walk(root):
        t = node.type
        if t in _FUNCTION_TYPES:
            length = line_end(node) - line_start(node) + 1
            if length > MAX_FUNCTION_LINES:
                fs.add(
                    "modularity",
                    "long-function",
                    2.0 + (length - MAX_FUNCTION_LINES) / MAX_FUNCTION_LINES,
                    line_start(node),
                    line_start(node),
                    Severity.MEDIUM if length > 2 * MAX_FUNCTION_LINES else Severity.LOW,
                    _js_function_name(node),
                )
        elif t == "predefined_type" and is_ts and text(node) == "any":
            fs.add("type_safety", "any", 1.0, line_start(node), line_end(node), Severity.LOW)
        elif t == "comment":
            body = text(node)
            if "@ts-nocheck" in body:
                fs.add(
                    "type_safety",
                    "ts-nocheck",
                    5.0,
                    line_start(node),
                    line_end(node),
                    Severity.MEDIUM,
                )
            elif "@ts-ignore" in body:
                fs.add(
                    "type_safety", "ts-ignore", 2.0, line_start(node), line_end(node), Severity.LOW
                )
        elif t == "catch_clause":
            _js_catch(fs, node, is_route)
        elif t == "debugger_statement":
            fs.add(
                "cleanliness", "debugger", 3.0, line_start(node), line_end(node), Severity.MEDIUM
            )
            _remove_statement(fs, "debugger", node)
        elif t == "call_expression":
            if _is_console_debug(node):
                fs.add(
                    "cleanliness",
                    "console-log",
                    1.0,
                    line_start(node),
                    line_end(node),
                    Severity.LOW,
                )
                if node.parent is not None and node.parent.type == "expression_statement":
                    _remove_statement(fs, "console-log", node.parent)
            if has_jsx and not is_route:
                _js_ui_coupling(fs, node, is_client, jsx_cache)
        elif t == "if_statement" and _js_if_depth(node) == MAX_IF_DEPTH + 1:
            fs.add(
                "architecture",
                "deep-nesting",
                2.0,
                line_start(node),
                line_start(node),
                Severity.LOW,
                _js_enclosing_name(node),
            )
        elif t == "import_statement" and used is not None:
            for name, spec in _js_imported_names(node):
                if name != "React" and used.get(name, 0) == 0:
                    fs.add(
                        "cleanliness",
                        "unused-import",
                        0.5,
                        line_start(spec),
                        line_end(spec),
                        Severity.INFO,
                        name,
                    )


def _js_catch(fs: _FileSmells, node: Node, is_route: bool) -> None:
    body = node.child_by_field_name("body")
    if body is None:
        return
    statements = [c for c in body.named_children if c.type != "comment"]
    param = node.child_by_field_name("parameter")
    name = text(param) if param is not None and param.type == "identifier" else None
    fn = _js_enclosing_name(node)
    indent = _indent_of(fs.sf, line_start(node))

    if not statements:
        weight, rule = 3.0, "empty-catch"
        severity = Severity.HIGH if is_route else Severity.MEDIUM
        if not body.named_children:  # truly empty (a comment means someone chose to ignore it)
            err = name or "err"
            fs.edits[rule].append(
                (
                    node.start_byte,
                    node.end_byte,
                    f"catch ({err}) {{\n{indent}  throw {err};\n{indent}}}",
                )
            )
    elif all(_is_console_statement(s) for s in statements):
        weight, rule = 2.0, "log-only-catch"
        severity = Severity.MEDIUM if is_route else Severity.LOW
        if name is not None:
            last = statements[-1]
            fs.edits[rule].append(
                (
                    last.end_byte,
                    last.end_byte,
                    f"\n{_indent_of(fs.sf, line_start(last))}throw {name};",
                )
            )
    else:
        return
    fs.add("error_hygiene", rule, weight, line_start(node), line_end(node), severity, fn)


def _js_ui_coupling(
    fs: _FileSmells, call: Node, is_client: bool, cache: dict[tuple[int, int], bool]
) -> None:
    component = _js_enclosing_component(call, cache)
    if component is None:
        return
    fn = call.child_by_field_name("function")
    if fn is None:
        return
    if fn.type == "member_expression" and _member_root(fn) in _DB_ROOTS:
        fs.add(
            "architecture",
            "db-in-component",
            5.0,
            line_start(call),
            line_end(call),
            Severity.HIGH,
            component,
        )
    elif is_client and fn.type == "identifier" and text(fn) == "fetch":
        fs.add(
            "architecture",
            "fetch-in-component",
            2.0,
            line_start(call),
            line_end(call),
            Severity.LOW,
            component,
        )


def _is_console_debug(call: Node) -> bool:
    fn = call.child_by_field_name("function")
    return (
        fn is not None
        and fn.type == "member_expression"
        and text(fn.child_by_field_name("object")) == "console"
        and text(fn.child_by_field_name("property")) in _CONSOLE_DEBUG
    )


def _is_console_statement(stmt: Node) -> bool:
    if stmt.type != "expression_statement" or not stmt.named_children:
        return False
    call = stmt.named_children[0]
    fn = call.child_by_field_name("function") if call.type == "call_expression" else None
    return (
        fn is not None
        and fn.type == "member_expression"
        and text(fn.child_by_field_name("object")) == "console"
    )


def _remove_statement(fs: _FileSmells, rule: str, stmt: Node) -> None:
    """Delete a statement that sits alone on its line(s) inside a block (else: no fix)."""
    if stmt.parent is None or stmt.parent.type not in ("statement_block", "program"):
        return
    sf = fs.sf
    lo, hi = line_start(stmt), line_end(stmt)
    block = "\n".join(sf.lines[lo - 1 : hi]).strip()
    if block != text(stmt).strip():
        return  # shares its line with other code
    start = _line_start_byte(sf, lo)
    end = _line_start_byte(sf, hi + 1)
    fs.edits[rule].append((start, end, ""))


def _js_if_depth(node: Node) -> int:
    """Nesting depth of an if within its function, not counting `else if` chains as nesting."""
    depth = 1
    # `else if` parses as if > else_clause > if: the owning if is the same level, not a parent
    skip_owner = node.parent is not None and node.parent.type == "else_clause"
    cur = node.parent
    while cur is not None and cur.type not in _FUNCTION_TYPES:
        if cur.type == "if_statement":
            if skip_owner:
                skip_owner = False
            else:
                depth += 1
            skip_owner = cur.parent is not None and cur.parent.type == "else_clause"
        cur = cur.parent
    return depth


def _js_enclosing_name(node: Node) -> str | None:
    cur = node.parent
    while cur is not None:
        if cur.type in _FUNCTION_TYPES:
            return _js_function_name(cur)
        cur = cur.parent
    return None


def _js_function_name(fn: Node) -> str | None:
    name = fn.child_by_field_name("name")
    if name is not None:
        return text(name)
    parent = fn.parent
    if parent is not None and parent.type in (
        "variable_declarator",
        "pair",
        "assignment_expression",
    ):
        target = (
            parent.child_by_field_name("name")
            or parent.child_by_field_name("key")
            or parent.child_by_field_name("left")
        )
        return text(target) or None
    if parent is not None and parent.type == "export_statement":
        return "default export"
    return None


def _js_enclosing_component(node: Node, cache: dict[tuple[int, int], bool]) -> str | None:
    """Name of the outermost function around `node` that renders JSX and looks like a component."""
    found = None
    cur = node.parent
    while cur is not None:
        if cur.type in _FUNCTION_TYPES:
            name = _js_function_name(cur)
            if name == "default export" or (name is not None and name[:1].isupper()):
                key = (cur.start_byte, cur.end_byte)
                if key not in cache:
                    cache[key] = any(n.type.startswith("jsx_") for n in walk(cur))
                if cache[key]:
                    found = name
        cur = cur.parent
    return found


def _member_root(member: Node) -> str:
    cur = member
    while cur.type in ("member_expression", "call_expression"):
        nxt = (
            cur.child_by_field_name("object")
            if cur.type == "member_expression"
            else cur.child_by_field_name("function")
        )
        if nxt is None:
            break
        cur = nxt
    return text(cur) if cur.type == "identifier" else ""


def _js_imported_names(stmt: Node) -> list[tuple[str, Node]]:
    out: list[tuple[str, Node]] = []
    for clause in stmt.named_children:
        if clause.type != "import_clause":
            continue
        for part in clause.named_children:
            if part.type == "identifier":
                out.append((text(part), part))
            elif part.type == "namespace_import":
                ident = next((c for c in part.named_children if c.type == "identifier"), None)
                if ident is not None:
                    out.append((text(ident), ident))
            elif part.type == "named_imports":
                for spec in part.named_children:
                    if spec.type != "import_specifier":
                        continue
                    local = spec.child_by_field_name("alias") or spec.child_by_field_name("name")
                    if local is not None:
                        out.append((text(local), spec))
    return out


def _js_identifier_uses(root: Node) -> dict[str, int]:
    uses: dict[str, int] = defaultdict(int)
    for n in walk(root):
        if n.type in (
            "identifier",
            "type_identifier",
            "shorthand_property_identifier",
        ) and not _inside(n, "import_statement"):
            uses[text(n)] += 1
    return uses


def _inside(node: Node, kind: str) -> bool:
    cur = node.parent
    while cur is not None:
        if cur.type == kind:
            return True
        cur = cur.parent
    return False


def _is_route_file(path: str) -> bool:
    p = path.lower()
    return "/api/" in f"/{p}" or bool(re.search(r"(^|/)route\.[cm]?[jt]sx?$", p))


# --- Python ------------------------------------------------------------------------------------


def _analyze_python(fs: _FileSmells) -> None:
    sf = fs.sf
    try:
        tree = ast.parse(sf.text)
    except (SyntaxError, ValueError):
        return
    loc = sum(1 for line in sf.lines if line.strip())
    _large_file(fs, loc)
    is_script = (
        "__main__" in sf.text
        or sf.path.rsplit("/", 1)[-1] in ("manage.py", "setup.py", "cli.py")
        or "/scripts/" in f"/{sf.path}"
    )
    is_route = _is_route_file(sf.path)
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            length = (node.end_lineno or node.lineno) - node.lineno + 1
            if length > MAX_FUNCTION_LINES:
                fs.add(
                    "modularity",
                    "long-function",
                    2.0 + (length - MAX_FUNCTION_LINES) / MAX_FUNCTION_LINES,
                    node.lineno,
                    node.lineno,
                    Severity.MEDIUM if length > 2 * MAX_FUNCTION_LINES else Severity.LOW,
                    node.name,
                )
            if _is_py_route(node) and _py_untyped(node):
                fs.add(
                    "type_safety",
                    "untyped-route",
                    1.0,
                    node.lineno,
                    node.lineno,
                    Severity.LOW,
                    node.name,
                )
            for sub in ast.walk(node):
                if isinstance(sub, ast.If) and _py_if_depth(node, sub) == MAX_IF_DEPTH + 1:
                    fs.add(
                        "architecture",
                        "deep-nesting",
                        2.0,
                        sub.lineno,
                        sub.lineno,
                        Severity.LOW,
                        node.name,
                    )
        elif isinstance(node, ast.ExceptHandler):
            owner = _py_innermost(functions, node.lineno)
            in_route = is_route or any(
                _is_py_route(f) and f.lineno <= node.lineno <= (f.end_lineno or f.lineno)
                for f in functions
            )
            _py_except(fs, node, in_route, owner.name if owner else None)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
            and not is_script
        ):
            fs.add(
                "cleanliness",
                "print",
                1.0,
                node.lineno,
                node.end_lineno or node.lineno,
                Severity.LOW,
            )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "breakpoint"
        ):
            fs.add("cleanliness", "debugger", 3.0, node.lineno, node.lineno, Severity.MEDIUM)

    if not sf.path.endswith("__init__.py"):
        _py_unused_imports(fs, tree)


def _py_except(fs: _FileSmells, handler: ast.ExceptHandler, is_route: bool, fn: str | None) -> None:
    body = handler.body
    sf = fs.sf
    if all(isinstance(s, ast.Pass) or _is_ellipsis(s) for s in body):
        rule, weight = "empty-catch", 3.0
        severity = Severity.HIGH if is_route else Severity.MEDIUM
        if (
            len(body) == 1
            and body[0].lineno == body[0].end_lineno
            and body[0].lineno != handler.lineno
        ):
            line = body[0].lineno
            fs.line_edits[rule][line] = [_indent_of(sf, line) + "raise"]
    elif all(_is_print_stmt(s) for s in body):
        rule, weight = "log-only-catch", 2.0
        severity = Severity.MEDIUM if is_route else Severity.LOW
        last = body[-1]
        if last.lineno != handler.lineno:
            end = last.end_lineno or last.lineno
            fs.line_edits[rule][end] = [sf.lines[end - 1], _indent_of(sf, last.lineno) + "raise"]
    else:
        return
    fs.add(
        "error_hygiene",
        rule,
        weight,
        handler.lineno,
        handler.end_lineno or handler.lineno,
        severity,
        fn,
    )


def _is_ellipsis(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is Ellipsis
    )


def _is_print_stmt(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Name)
        and stmt.value.func.id == "print"
    )


def _is_py_route(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr in _ROUTE_DECORATORS:
            return True
    return False


def _py_untyped(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    args = [
        a
        for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
        if a.arg not in ("self", "cls")
    ]
    return fn.returns is None or any(a.annotation is None for a in args)


def _py_innermost(
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef], line: int
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    around = [f for f in functions if f.lineno <= line <= (f.end_lineno or f.lineno)]
    return max(around, key=lambda f: f.lineno, default=None)


def _py_if_depth(fn: ast.AST, target: ast.If) -> int:
    """Depth of `target` among Ifs under `fn`; `elif` doesn't count as nesting."""

    def visit(node: ast.AST, depth: int) -> int | None:
        for child in ast.iter_child_nodes(node):
            if isinstance(
                child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef
            ):
                continue
            if isinstance(child, ast.If):
                is_elif = isinstance(node, ast.If) and node.orelse == [child]
                d = depth if is_elif else depth + 1
                if child is target:
                    return d
                found = visit(child, d)
            else:
                found = visit(child, depth)
            if found is not None:
                return found
        return None

    return visit(fn, 0) or 0


def _py_unused_imports(fs: _FileSmells, tree: ast.Module) -> None:
    imported: list[tuple[str, int]] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.append(((alias.asname or alias.name).split(".")[0], node.lineno))
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for alias in node.names:
                if alias.name != "*":
                    imported.append((alias.asname or alias.name, node.lineno))
    if not imported:
        return
    used: set[str] = set()
    strings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append(node.value)  # __all__, string annotations
    blob = "\n".join(strings)
    for name, line in imported:
        if name not in used and not re.search(rf"\b{re.escape(name)}\b", blob):
            fs.add("cleanliness", "unused-import", 0.5, line, line, Severity.INFO, name)


# --- shared ------------------------------------------------------------------------------------


def _large_file(fs: _FileSmells, loc: int) -> None:
    if loc > MAX_FILE_LINES:
        fs.add(
            "modularity",
            "large-file",
            4.0 + (loc - MAX_FILE_LINES) / MAX_FILE_LINES,
            1,
            1,
            Severity.MEDIUM if loc > 2 * MAX_FILE_LINES else Severity.LOW,
            str(loc),
        )


def _commented_out_code(fs: _FileSmells) -> None:
    marker = "#" if fs.sf.language == "python" else "//"
    run: list[int] = []
    for i, line in enumerate([*fs.sf.lines, ""], start=1):
        stripped = line.strip()
        if stripped.startswith(marker) and not stripped.startswith(("///", "#!", "# type:", "#:")):
            run.append(i)
            continue
        if len(run) > MIN_COMMENTED_BLOCK:
            bodies = [fs.sf.lines[n - 1].strip()[len(marker) :] for n in run]
            if sum(1 for b in bodies if _CODE_LIKE.search(b)) * 2 >= len(bodies):
                fs.add(
                    "cleanliness",
                    "commented-out-code",
                    3.0,
                    run[0],
                    run[-1],
                    Severity.LOW,
                    str(len(run)),
                )
        run = []


def _indent_of(sf: SourceFile, line: int) -> str:
    raw = sf.lines[line - 1] if 0 < line <= len(sf.lines) else ""
    return raw[: len(raw) - len(raw.lstrip())]


def _line_start_byte(sf: SourceFile, line: int) -> int:
    """Byte offset where 1-based `line` starts (len(text) past the end)."""
    data = sf.text.encode("utf-8")
    if line <= 1:
        return 0
    pos = 0
    for _ in range(line - 1):
        nxt = data.find(b"\n", pos)
        if nxt == -1:
            return len(data)
        pos = nxt + 1
    return pos


# --- findings ----------------------------------------------------------------------------------

_COPY: dict[str, tuple[str, str]] = {
    # rule -> (title, explanation); {n} = count, {name} = function/import name, {extra} = detail
    "large-file": (
        "Monolithic file ({extra} lines)",
        "Files this size are usually one prompt's worth of generated code. Split it by "
        "responsibility so changes stay reviewable and testable.",
    ),
    "long-function": (
        "Oversized function {name}",
        "Functions over 80 lines mix several jobs, which hides bugs and makes them hard to "
        "test. Extract the steps into named helpers.",
    ),
    "any": (
        "{n} uses of `any`",
        "`any` switches the type checker off, so wrong payloads and typos reach runtime. Use "
        "a real type, or `unknown` plus a check where the shape is genuinely open.",
    ),
    "ts-ignore": (
        "{n} @ts-ignore comments",
        "Each one silences a type error instead of fixing it. Fix the type, or use "
        "@ts-expect-error with a reason so it fails once the error is gone.",
    ),
    "ts-nocheck": (
        "Type checking disabled for the whole file",
        "@ts-nocheck turns TypeScript off for every line here. Remove it and fix the errors "
        "it was hiding.",
    ),
    "untyped-route": (
        "Untyped route handler {name}",
        "Without parameter and return types the framework can't validate input or document "
        "the response. Annotate the handler.",
    ),
    "empty-catch": (
        "Swallowed exception in {name}",
        "The error is caught and dropped, so failures look like success and nothing gets "
        "logged or reported. Handle it, or let it propagate.",
    ),
    "log-only-catch": (
        "Exception only logged in {name}",
        "The error is printed and then execution carries on as if it worked. Rethrow it (or "
        "return an error response) after logging.",
    ),
    "console-log": (
        "{n} leftover console.log calls",
        "Debug logging ships to production, leaks data to the browser console and buries real "
        "logs. Remove it or use a logger with levels.",
    ),
    "print": (
        "{n} leftover print() calls",
        "Debug prints end up in production logs with no level or context. Remove them or use "
        "the logging module.",
    ),
    "debugger": (
        "Debugger statement left in code",
        "A debugger / breakpoint() call pauses execution wherever dev tools are attached. "
        "Delete it.",
    ),
    "commented-out-code": (
        "Commented-out code block ({extra} lines)",
        "Dead code in comments goes stale and confuses readers. Delete it; git keeps history.",
    ),
    "unused-import": (
        "{n} unused imports",
        "Unused imports add load time and noise, and often point at half-finished refactors. "
        "Remove them.",
    ),
    "db-in-component": (
        "Database call inside component {name}",
        "UI components that query the database directly mix data access with rendering and "
        "spread queries around the codebase. Move the query to a server-side data layer.",
    ),
    "fetch-in-component": (
        "Raw fetch inside client component {name}",
        "Fetching inline in a client component duplicates request logic and error handling. "
        "Move it into a typed API helper or data hook.",
    ),
    "deep-nesting": (
        "Deeply nested conditionals in {name}",
        "Ifs nested more than four deep are hard to follow and test. Return early or extract "
        "the branches.",
    ),
}
# Rules reported once per file (with a count) rather than once per occurrence
_GROUPED = frozenset({"any", "ts-ignore", "console-log", "print", "unused-import"})


def _findings(fs: _FileSmells) -> list[Finding]:
    sf = fs.sf
    by_rule: dict[str, list[_Smell]] = defaultdict(list)
    for s in fs.smells:
        by_rule[s.rule].append(s)

    out: list[Finding] = []
    for rule, smells in by_rule.items():
        diff = _diff_for(fs, rule)
        groups = [smells] if rule in _GROUPED else [[s] for s in smells]
        for group in groups:
            first = min(group, key=lambda s: s.line_start)
            title_t, explanation = _COPY[rule]
            names = sorted({s.name for s in group if s.name})
            if not names or rule == "unused-import":
                # Anonymous callback: "Swallowed exception", not "... in handler"
                title_t = re.sub(r"\s*(in |inside (client )?component )?\{name\}", "", title_t)
            title = title_t.format(
                n=len(group), name=names[0] if names else "", extra=first.name or ""
            )
            if rule == "unused-import" and names:
                explanation = f"Unused: {', '.join(names[:8])}. " + explanation
            out.append(
                Finding(
                    rule_id=f"quality/{rule}",
                    severity=max((s.severity for s in group), key=lambda s: s.rank),
                    category=CATEGORY[first.metric],
                    title=title,
                    file_path=sf.path,
                    line_start=first.line_start,
                    line_end=max(first.line_end, first.line_start),
                    snippet_original=sf.snippet(first.line_start, first.line_end, context=0),
                    # One fix per rule per file: attach it to the first finding only
                    unified_diff=diff if group is groups[0] else None,
                    explanation=explanation,
                    domain=FindingDomain.QUALITY,
                )
            )
    return out


def _diff_for(fs: _FileSmells, rule: str) -> str | None:
    sf = fs.sf
    if rule in fs.edits and fs.edits[rule]:
        edits = _non_overlapping(fs.edits[rule])
        patched = apply_edits(sf.text, edits)
        if sf.language in JS_FAMILY and parses_cleanly(sf.language, patched):
            return unified_diff(sf.path, sf.text, patched) or None
        return None
    if rule in fs.line_edits and fs.line_edits[rule]:
        eol = "\r\n" if "\r\n" in sf.text else "\n"
        lines = list(sf.lines)
        for line in sorted(fs.line_edits[rule], reverse=True):
            repl = fs.line_edits[rule][line]
            lines[line - 1 : line] = repl or []
        patched = eol.join(lines) + (eol if sf.text.endswith(("\n", "\r\n")) else "")
        try:
            ast.parse(patched)
        except SyntaxError:
            return None
        return unified_diff(sf.path, sf.text, patched) or None
    return None


def _non_overlapping(edits: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for e in sorted(set(edits)):
        if out and e[0] < out[-1][1]:
            continue
        out.append(e)
    return out
