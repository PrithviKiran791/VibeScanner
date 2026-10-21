import json

import httpx

from tests.conftest import make_sf, registry_transport
from vibeguard.engine.static.deps import MemoryCache, collect_declared, scan_dependencies

PKG = """{
  "name": "demo",
  "scripts": {
    "next": "next dev"
  },
  "dependencies": {
    "next": "14.2.3",
    "local-lib": "file:../lib",
    "fake-pkg-xyz": "^1.0.0"
  },
  "devDependencies": {
    "typescript": "^5.4.0"
  }
}
"""


def test_collects_registry_deps_only_with_correct_lines():
    declared = collect_declared([make_sf("package.json", PKG)])
    assert {(d.name, d.line) for d in declared} == {
        ("next", 7),
        ("fake-pkg-xyz", 9),
        ("typescript", 12),
    }


def test_hallucinated_npm_package_flagged_and_patch_keeps_json_valid():
    sf = make_sf("package.json", PKG)
    [f] = scan_dependencies([sf], transport=registry_transport({"fake-pkg-xyz"}))
    assert f.title == "Hallucinated Package: fake-pkg-xyz" and f.line_start == 9
    # Removing the last entry must drop the comma on the line above
    assert '+    "local-lib": "file:../lib"\n' in f.unified_diff
    patched = json.loads(_apply(sf.text, f.unified_diff))
    assert "fake-pkg-xyz" not in patched["dependencies"]


def test_requirements_txt(tmp_path):
    sf = make_sf(
        "requirements.txt", "fastapi>=0.110\n# comment\nhallucinated-ml-utils==0.1\n-e .\n"
    )
    [f] = scan_dependencies([sf], transport=registry_transport({"hallucinated-ml-utils"}))
    assert f.line_start == 3


def test_registry_outage_is_never_a_finding():
    def boom(_req):
        raise httpx.ConnectError("down")

    sf = make_sf("package.json", PKG)
    assert scan_dependencies([sf], transport=httpx.MockTransport(boom)) == []


def test_cache_short_circuits_registry():
    cache = MemoryCache()
    cache.set("npm:package:next", True)
    cache.set("npm:package:typescript", True)
    cache.set("npm:package:fake-pkg-xyz", False)

    def fail(_req):
        raise AssertionError("registry should not be called")

    findings = scan_dependencies(
        [make_sf("package.json", PKG)], cache, transport=httpx.MockTransport(fail)
    )
    assert [f.title for f in findings] == ["Hallucinated Package: fake-pkg-xyz"]


def _apply(original: str, diff: str) -> str:
    """Minimal single-hunk patch applier for test assertions."""
    lines = original.splitlines()
    hunk = diff.splitlines()[2:]
    start = int(hunk[0].split()[1].split(",")[0][1:]) - 1
    new = [ln[1:] for ln in hunk[1:] if not ln.startswith("-")]
    old_len = sum(1 for ln in hunk[1:] if not ln.startswith("+"))
    return "\n".join(lines[:start] + new + lines[start + old_len :])
