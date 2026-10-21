"""Hallucinated dependency detection (slopsquatting): every declared package must exist upstream."""

from __future__ import annotations

import asyncio
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal, Protocol
from urllib.parse import quote

import httpx

from vibeguard.engine.diff import unified_diff
from vibeguard.engine.models import Finding, Severity, SourceFile

Ecosystem = Literal["npm", "pypi"]

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/pypi"

NPM_SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
# Specs that don't resolve through the public registry
NON_REGISTRY_SPEC = re.compile(
    r"^(?:file:|link:|workspace:|portal:|git\+|git:|github:|https?:|npm:)|/"
)
PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


class ExistenceCache(Protocol):
    """Redis-backed in the service (`npm:package:{name}`, 24h TTL); a dict for the CLI."""

    def get(self, key: str) -> bool | None: ...
    def set(self, key: str, exists: bool) -> None: ...


class MemoryCache:
    def __init__(self) -> None:
        self._data: dict[str, bool] = {}

    def get(self, key: str) -> bool | None:
        return self._data.get(key)

    def set(self, key: str, exists: bool) -> None:
        self._data[key] = exists


@dataclass(frozen=True)
class Declared:
    ecosystem: Ecosystem
    name: str
    file: SourceFile
    line: int


def collect_declared(files: list[SourceFile]) -> list[Declared]:
    out: list[Declared] = []
    for sf in files:
        name = PurePosixPath(sf.path).name
        if name == "package.json":
            out.extend(_from_package_json(sf))
        elif re.fullmatch(r"requirements(?:[-_.][\w-]+)?\.txt", name):
            out.extend(_from_requirements(sf))
    return out


def scan_dependencies(
    files: list[SourceFile],
    cache: ExistenceCache | None = None,
    timeout_s: float = 5.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[Finding]:
    declared = collect_declared(files)
    if not declared:
        return []
    cache = cache or MemoryCache()
    missing = _run_sync(_find_missing(declared, cache, timeout_s, transport))
    return [_finding(d) for d in declared if (d.ecosystem, d.name) in missing]


def _run_sync(coro):
    """asyncio.run, but safe when the caller already has a running loop (e.g. inside FastAPI)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


async def _find_missing(
    declared: list[Declared],
    cache: ExistenceCache,
    timeout_s: float,
    transport: httpx.AsyncBaseTransport | None,
) -> set[tuple[Ecosystem, str]]:
    unique = {(d.ecosystem, d.name) for d in declared}
    sem = asyncio.Semaphore(16)
    missing: set[tuple[Ecosystem, str]] = set()

    async with httpx.AsyncClient(timeout=timeout_s, transport=transport) as client:

        async def check(eco: Ecosystem, name: str) -> None:
            key = f"{eco}:package:{name.lower()}"
            cached = cache.get(key)
            if cached is None:
                async with sem:
                    cached = await _exists(client, eco, name)
                if cached is None:
                    return  # registry unreachable: no evidence either way, never a finding
                cache.set(key, cached)
            if not cached:
                missing.add((eco, name))

        await asyncio.gather(*(check(e, n) for e, n in unique))
    return missing


async def _exists(client: httpx.AsyncClient, eco: Ecosystem, name: str) -> bool | None:
    if eco == "npm":
        url = f"{NPM_REGISTRY}/{quote(name, safe='@')}"
    else:
        url = f"{PYPI_REGISTRY}/{quote(name)}/json"
    try:
        resp = await client.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError:
        return None
    if resp.status_code == 404:
        return False
    if resp.status_code == 200:
        return True
    return None


def _from_package_json(sf: SourceFile) -> list[Declared]:
    try:
        data = json.loads(sf.text)
    except json.JSONDecodeError:
        return []
    out: list[Declared] = []
    for section in NPM_SECTIONS:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str) or NON_REGISTRY_SPEC.search(spec):
                continue
            line = _json_key_line(sf, name, after=_json_key_line(sf, section) or 0)
            if line:
                out.append(Declared("npm", name, sf, line))
    return out


def _from_requirements(sf: SourceFile) -> list[Declared]:
    out: list[Declared] = []
    for lineno, line in enumerate(sf.lines, start=1):
        stripped = line.split("#", 1)[0].strip()
        if (
            not stripped
            or stripped.startswith(("-", "git+", "http"))
            or "@" in stripped.split(";")[0]
        ):
            continue
        m = PEP508_NAME.match(stripped)
        if m:
            out.append(Declared("pypi", m.group(1), sf, lineno))
    return out


def _json_key_line(sf: SourceFile, key: str, after: int = 0) -> int | None:
    needle = re.compile(rf'^\s*"{re.escape(key)}"\s*:')
    return next(
        (i for i, line in enumerate(sf.lines, start=1) if i > after and needle.match(line)), None
    )


def _finding(d: Declared) -> Finding:
    patched = _remove_line(d.file, d.line, json_aware=d.ecosystem == "npm")
    registry = "npm" if d.ecosystem == "npm" else "PyPI"
    return Finding(
        rule_id="hallucinated-dependency",
        severity=Severity.HIGH,
        category="Supply Chain",
        title=f"Hallucinated Package: {d.name}",
        cwe_id="CWE-1357",
        file_path=d.file.path,
        line_start=d.line,
        line_end=d.line,
        snippet_original=d.file.snippet(d.line, d.line),
        snippet_fixed="",
        unified_diff=unified_diff(d.file.path, d.file.text, patched),
        explanation=(
            f"`{d.name}` does not exist on {registry}; AI assistants invent package names like this, "
            "and attackers register them with malware (slopsquatting). Remove it and use the real "
            "package you meant."
        ),
    )


def _remove_line(sf: SourceFile, lineno: int, json_aware: bool) -> str:
    eol = "\r\n" if "\r\n" in sf.text else "\n"
    lines = list(sf.lines)
    del lines[lineno - 1]
    if json_aware:
        _fix_trailing_comma(lines, lineno - 1)
    out = eol.join(lines)
    return out + eol if sf.text.endswith(("\n", "\r\n")) else out


def _fix_trailing_comma(lines: list[str], removed_at: int) -> None:
    """If we removed the last entry of a JSON object, drop the comma on the new last entry."""
    nxt = _next_nonblank(lines, removed_at, step=1)
    if nxt is None or not lines[nxt].lstrip().startswith("}"):
        return
    prev = _next_nonblank(lines, removed_at - 1, step=-1)
    if prev is not None and lines[prev].rstrip().endswith(","):
        lines[prev] = lines[prev].rstrip()[:-1]


def _next_nonblank(lines: list[str], start: int, step: int) -> int | None:
    i = start
    while 0 <= i < len(lines):
        if lines[i].strip():
            return i
        i += step
    return None
