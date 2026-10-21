"""Build a runnable copy of the demo app with its planted secrets filled in.

No literal secret-shaped string lives in git (GitHub push protection would reject it). Template
files (`*.tmpl`) hold placeholders; this script assembles the fake values at runtime.

    python -m tests.fixtures.materialize ./demo_app     # then: vibeguard scan ./demo_app
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

SOURCE = Path(__file__).parent / "vulnerable_app"

# Split so the full pattern never appears in source. Fake, never valid.
DEMO_STRIPE_KEY = "sk_" + "live_" + "51VibeGuardDemoKeyNotReal" + "0" * 10

PLACEHOLDERS = {"__DEMO_STRIPE_KEY__": DEMO_STRIPE_KEY}


def build_demo_app(dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(SOURCE, dest)
    for tmpl in dest.rglob("*.tmpl"):
        text = tmpl.read_text(encoding="utf-8")
        for placeholder, value in PLACEHOLDERS.items():
            text = text.replace(placeholder, value)
        tmpl.with_suffix("").write_text(text, encoding="utf-8")
        tmpl.unlink()
    return dest


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "demo_app")
    print(build_demo_app(target))
