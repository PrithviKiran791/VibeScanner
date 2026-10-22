"""The dashboard's Rules page lists every detector from frontend/src/lib/catalog.ts.
Fail if a backend rule exists that the page doesn't show."""

import re
import tomllib
from pathlib import Path

from vibeguard.engine.static import deps, secrets, sinks

REPO = Path(__file__).resolve().parents[2]
CATALOG = REPO / "frontend" / "src" / "lib" / "catalog.ts"


def _backend_rule_ids() -> set[str]:
    toml = tomllib.loads(
        (Path(secrets.__file__).parent / "rules" / "secrets.toml").read_text(encoding="utf-8")
    )
    ids = {r["id"] for r in toml["rules"]}
    for module in (secrets, sinks, deps):
        source = Path(module.__file__).read_text(encoding="utf-8")
        ids |= set(re.findall(r'rule_id="([a-z0-9-]+)"', source))
        ids |= set(re.findall(r'^\s*"([a-z0-9-]+)",\s*$', source, re.M)) & {
            "supabase-service-role",
            "public-env-secret",
        }
    return ids


def test_every_backend_rule_is_in_the_dashboard_catalog():
    catalog_ids = set(re.findall(r'id: "([a-z0-9-]+)"', CATALOG.read_text(encoding="utf-8")))
    missing = _backend_rule_ids() - catalog_ids
    assert not missing, f"add these rules to frontend/src/lib/catalog.ts: {sorted(missing)}"
