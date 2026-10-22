"""Export the vulnerable demo app as a standalone git repo, ready to publish for live demos.

    python -m tests.fixtures.export_demo ../vibeguard-demo-app

The fixture's fake `sk_live_` Stripe key would be blocked by GitHub push protection, so the
public copy reads Stripe from the environment and instead hardcodes a JWT signing secret: still
a hardcoded-secret finding, but not a provider pattern GitHub rejects. Nothing is pushed: the
script only creates and commits locally.
"""

from __future__ import annotations

import secrets
import subprocess
import sys
from pathlib import Path

from tests.fixtures.materialize import build_demo_app

STRIPE_FROM_ENV = """import Stripe from "stripe";

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2024-04-10",
});
"""

SESSION_TS = """import jwt from "jsonwebtoken";

// TODO: move to env before launch
const JWT_SECRET = "{secret}";

export function signSession(userId: string) {{
  return jwt.sign({{ sub: userId }}, JWT_SECRET, {{ expiresIn: "7d" }});
}}
"""

README = """# vibeguard-demo-app

> **Intentionally insecure.** Every bug here is planted, every credential is fake.
> Do not deploy this code. It exists to demo [VibeGuard](https://github.com/PrithviKiran791/VibeScanner).

A tiny Next.js app with the mistakes AI coding assistants make most often:

| Where | Planted issue | Found by |
| --- | --- | --- |
| `lib/session.ts` | Hardcoded JWT signing secret | static |
| `.env.local` | Committed env file; service-role key behind `NEXT_PUBLIC_` | static |
| `package.json` | Hallucinated package `react-secure-auth-helpers-pro` | static (npm registry) |
| `app/api/search/route.ts` | SQL built with a template string | static |
| `app/api/convert/route.ts` | Shell command injection | static |
| `components/Comment.tsx` | Unsanitized `dangerouslySetInnerHTML` | static |
| `app/api/user/[id]/route.ts` | IDOR: no ownership check | semantic (LLM) |
| `app/actions.ts` | Unauthenticated server action | semantic (LLM) |

Scan it from the VibeGuard dashboard with `<owner>/vibeguard-demo-app`.
"""


def export_demo(dest: Path) -> Path:
    if dest.exists() and any(dest.iterdir()):
        raise SystemExit(f"{dest} already exists and is not empty")
    build_demo_app(dest)

    (dest / "lib" / "stripe.ts").write_text(STRIPE_FROM_ENV, encoding="utf-8")
    (dest / "lib" / "session.ts").write_text(
        SESSION_TS.format(secret=secrets.token_hex(24)), encoding="utf-8"
    )
    (dest / "README.md").write_text(README, encoding="utf-8")
    (dest / ".gitignore").write_text("node_modules/\n.next/\n", encoding="utf-8")

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=dest, check=True, capture_output=True)

    git("init", "-b", "main")
    git("add", "-A")
    # .env.local is normally ignored by Next templates; here it is a deliberate finding
    git("add", "-f", ".env.local")
    # Commit as the user's git identity; fall back to a neutral one where none is set (CI)
    has_identity = (
        subprocess.run(["git", "config", "user.email"], cwd=dest, capture_output=True).returncode
        == 0
    )
    identity = (
        []
        if has_identity
        else ["-c", "user.name=VibeGuard Demo", "-c", "user.email=demo@vibeguard.invalid"]
    )
    git(*identity, "commit", "-m", "Intentionally vulnerable demo app for VibeGuard")
    return dest


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "vibeguard-demo-app").resolve()
    print(export_demo(target))
