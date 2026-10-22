# VibeGuard

A security scanner for AI-generated ("vibe-coded") web apps. It combines deterministic static analysis with a targeted LLM review, outputs a 0–100 **Hardening Index**, and produces ready-to-apply unified diffs.

Specs live in [`markdown/`](markdown/). Phases 1–3 are done: the core engine and CLI, the FastAPI + Celery + PostgreSQL/Redis service, and the Next.js dashboard with one-click fix PRs. See [`markdown/implementation.md`](markdown/implementation.md).

## Try it without Docker

```bash
cd backend && .venv/Scripts/python -m tests.fixtures.materialize ../demo_app && cd ..
backend/.venv/Scripts/python -m vibeguard.devserver --root .      # API on :8000 (SQLite + in-memory Redis + in-process worker)
npm --prefix frontend install && npm --prefix frontend run dev     # dashboard on :3000
```

Open `http://localhost:3000` and scan `acme/repo` for a GitHub repo, or paste the absolute path of `demo_app`. The dev server allows local paths under `--root`. Set `OPENROUTER_API_KEY` in `backend/.env` for the semantic pass, and `VIBEGUARD_GITHUB_TOKEN` (repo scope) for **Apply Fix (PR)**.

## How a scan works

| Pass | What runs | LLM tokens |
| --- | --- | --- |
| 1. Deterministic | Secret rules (adapted from Gitleaks), Supabase service-role JWTs, `NEXT_PUBLIC_*SECRET*` leaks, npm/PyPI checks for made-up packages, Tree-sitter sinks (SQL interpolation, `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `child_process`) | 0 |
| 2. Pruning | Tree-sitter extracts App Router handlers, Pages API routes, server actions, Express routes and middleware, then ranks them by risk signals | 0 |
| 3. Semantic | Only the pruned units go to the LLM (Gemma 4 31B via OpenRouter by default) in JSON mode, validated per finding; findings that don't match real lines are discarded | bounded |

Scoring is deterministic: `max(0, 100 − 25·critical − 12·high − 5·medium − 1·low)`.

## Quick start

```bash
cd backend
py -3.12 -m venv .venv
.venv/Scripts/pip install -e ".[openrouter,service,dev]"   # macOS/Linux: .venv/bin/pip

# Build the demo app (its fake secrets are assembled here, never committed literally)
.venv/Scripts/python -m tests.fixtures.materialize ../demo_app

# Deterministic only
.venv/Scripts/vibeguard scan ../demo_app --no-llm

# With the semantic pass (needs OPENROUTER_API_KEY in the environment or backend/.env)
.venv/Scripts/vibeguard scan https://github.com/<owner>/<repo> --json report.json --markdown report.md

# CI gate
.venv/Scripts/vibeguard scan . --fail-under 80

.venv/Scripts/python -m pytest
```

The model is set with `LLM_MODEL` (default `google/gemma-4-31b-it:free`, falling back to `LLM_FALLBACK_MODEL` on 429/5xx); see [`backend/.env.example`](backend/.env.example).

## Service (Phase 2)

```bash
docker compose -f docker/docker-compose.yml up -d          # PostgreSQL 16 + Redis
cd backend
.venv/Scripts/alembic upgrade head
.venv/Scripts/uvicorn vibeguard.api.main:app --reload
.venv/Scripts/celery -A vibeguard.worker.celery_app worker --pool=solo --loglevel=INFO   # --pool=solo on Windows
```

Or run everything in containers: `docker compose -f docker/docker-compose.yml --profile app up --build`.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/scans` | `{"repo_url": "https://github.com/o/r"}` or `{"local_path": ...}` (only when `VIBEGUARD_ALLOW_LOCAL_PATHS` + `VIBEGUARD_LOCAL_SCAN_ROOT` are set) plus optional `options: {llm, registry}`. Returns `202` + `QUEUED`; `409` if that repo is already being scanned. |
| `GET /api/v1/scans/{id}` | Status (`QUEUED → CLONING → ANALYZING_STATIC → ANALYZING_LLM → COMPLETED/FAILED`), live `progress` from Redis, score, counts. |
| `GET /api/v1/scans/{id}/findings` | Findings sorted by severity, with masked diffs and `remediation` coordinates. |
| `PATCH /api/v1/findings/{id}` | `{"status": "OPEN" \| "PATCH_APPLIED" \| "DISMISSED_FALSE_POSITIVE" \| "RESOLVED"}`. The score is recalculated from OPEN findings. |
| `GET /api/v1/scans?limit=20` | Scan history, newest first. |
| `POST /api/v1/findings/{id}/pull-request` | Rebuilds the fix on the default branch's current file and opens a PR (from a fork if the token can't push). Returns `201`, or `200` if a PR already exists. Errors: `409` if the file changed since the scan, `422` if there's no automated fix, `400` for non-GitHub scans, `503` if no `VIBEGUARD_GITHUB_TOKEN` is set, `502` for GitHub errors. |

Interactive docs: `http://localhost:8000/docs`. The test suite needs neither Docker nor a network: it uses SQLite migrated by Alembic, `fakeredis`, and the real Celery task run eagerly. Set `VIBEGUARD_TEST_DATABASE_URL` to run it against PostgreSQL.

## Layout

```
backend/vibeguard/engine/
  ingest/     file_index.py (ignore rules, 50MB cap) · workspace.py (shallow clone, safe ZIP, auto-wipe)
  static/     secrets.py + rules/secrets.toml · deps.py · sinks.py
  syntax/     tree.py (Tree-sitter helpers) · routes.py (entry-point extraction + pruning)
  llm/        provider.py · openrouter_provider.py · gemini_provider.py · schemas.py · validate.py · prompts/
  diff.py  merge.py  scoring.py  remediation.py  report.py  pipeline.py  cli.py  models.py
backend/vibeguard/db/       SQLAlchemy models, async/sync sessions, persistence, triage scoring
backend/vibeguard/worker/   Celery app, run_scan_task, Redis progress/lock/cache, payload contracts
backend/vibeguard/api/      FastAPI app, routes, schemas
backend/vibeguard/integrations/github.py   fix-PR flow (branch or fork, commit, PR)
backend/vibeguard/engine/patch.py          strict unified-diff re-applier (refuses on drift)
backend/vibeguard/devserver.py             Docker-free dev stack
backend/alembic/            migrations
frontend/src/app/           / (new scan + recent), /history, /scans/[id] (38/62 triage workspace)
frontend/src/components/    nav/ · scan/ · triage/ · inspector/ (DiffView) · ui/
frontend/src/lib/           typed API client, diff parser, polling hook (+ vitest)
backend/tests/fixtures/vulnerable_app/   intentionally insecure Next.js demo (secrets as *.tmpl)
docker/                     docker-compose.yml, backend.Dockerfile
```

`engine/` doesn't import FastAPI, Celery, or a database, so the Phase 2 service just wraps `pipeline.run_scan`.
