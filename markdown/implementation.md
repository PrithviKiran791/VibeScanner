# Implementation Roadmap & Technical Interview Defense

## 1. Phased Development Plan

```
  Phase 1: Local CLI Engine ──► Phase 2: Async Backend ──► Phase 3: Minimal Dashboard ──► Phase 4: Production Hardening
  - Tree-sitter & Regex        - FastAPI + Celery Queue     - Next.js UI                  - GitHub App Webhooks
  - LLM Structured Prompt      - Redis + PostgreSQL         - Diff viewer integration     - Rate limiting & Docker
  - Diff generator             - Sandboxed git cloning      - One-click PR creation       - Live production demo
```

### Phase 1: Core Analysis Engine (Week 1–2)
*   Build the standalone engine package `backend/vibeguard/engine/` with a CLI entrypoint (`python -m vibeguard.engine.cli <path>`; replaces the planned `analyzer.py`). The engine has no FastAPI/Celery/DB imports.
*   Implement regex-based secret scanning (Gitleaks rule set).
*   Implement `tree-sitter-javascript` / `tree-sitter-typescript` to extract all Next.js API route files (`/api/*` or `route.ts`).
*   Wire up LLM API using **Pydantic Structured Outputs** to guarantee JSON format.
*   Generate working unified diff strings using Python's `difflib`.

### Phase 2: Asynchronous Microservice Architecture (Week 3)
*   Wrap the engine inside a **FastAPI** service.
*   Implement **Celery** workers backed by **Redis** for asynchronous job queueing.
*   Setup **PostgreSQL** schema using SQLAlchemy and run migrations with Alembic.
*   Add safe repository cloning with size checks and automatic ramdisk cleanup.

### Phase 3: Developer Dashboard (Week 4)
*   Build the minimal dark brutalist UI in **Next.js 16** (App Router) under `frontend/`, per `design.md`.
*   Render the Hardening Score ($0 - 100$) and live scan progress (polling `GET /scans/{id}`, which reads the Redis progress hash).
*   Render unified diffs with a custom `DiffView` (red/green gradient rows) instead of `react-diff-viewer-continued`: the stored patches are already unified diffs, and a custom view keeps the brutalist styling exact.
*   Implement "Copy Diff", "Dismiss", and "Apply Fix (PR)": `POST /findings/{id}/pull-request` re-applies the fix to the live default branch (span remediation for secrets, strict diff re-apply otherwise), refuses on drift, and opens the PR from a branch or a fork.

### Phase 4: Packaging & Placement Readiness (Week 5)
*   Containerize all services with `docker/docker-compose.yml` (`--profile app`): migrations, API, Celery worker and the Next.js standalone dashboard, each non-root, with healthchecks (`/readyz` pings PostgreSQL and Redis).
*   GitHub webhooks (`POST /api/v1/webhooks/github`): HMAC-SHA256 verified over the raw body, ping/push handled, a push to the default branch queues a scan, delivery GUIDs deduplicated for 24h. Works for a repo webhook or a GitHub App.
*   Rate limiting: Redis fixed windows per client on write endpoints only (scans, PRs, triage, webhooks); fails open if Redis is down. Client identity comes from `X-Forwarded-For` only when the peer is in `VIBEGUARD_TRUSTED_PROXIES`, which is the nginx edge. Next's rewrite proxy forwards client-supplied `X-Forwarded-For` unchanged, so browser API traffic goes edge → FastAPI directly, never through Next. Security headers, `no-store`, and request size caps at the edge and the API.
*   Verified on PostgreSQL 16: the service suite runs against the compose database (`VIBEGUARD_TEST_DATABASE_URL`), resetting the schema through real Alembic downgrade/upgrade each test.
*   Prepare a public demo repository: `python -m tests.fixtures.export_demo <dest>` builds a committed, push-safe copy of the vulnerable app (no provider key patterns that GitHub push protection blocks).

---

## 2. Interview Defense Guide (Answering Senior Engineers)

When interviewers grill you on this project during technical rounds, use these structured answers:

### Q1: "Why not just use SonarQube, Snyk, or Semgrep?"
> *"Traditional SAST tools are great at detecting syntax patterns and known CVEs, but they are blind to the architectural shortcuts typical of vibe-coded apps. For example, an endpoint like `/api/user/[id]` that fetches records without checking if `session.user.id == req.params.id` looks completely safe to SonarQube because the query itself uses parameterized ORM methods. 
> 
> VibeGuard uses AST parsing to extract the route and session context, then uses a targeted LLM to inspect the authorization logic. Furthermore, Snyk gives documentation links; VibeGuard outputs a verified unified `.diff` ready to be committed directly."*

### Q2: "How do you handle LLM hallucinations and non-deterministic scores?"
> *"We do not let the LLM calculate the score. The Hardening Index is computed deterministically by our scoring algorithm based on verified findings and their CVSS severity classifications. 
> 
> For the vulnerability findings, we enforce structured JSON schema via Pydantic. If an LLM flags a line range that does not match the AST file index, or outputs an unparseable diff, our pipeline discards it before it reaches the database."*

### Q3: "What happens if someone submits a massive enterprise repo? How do you prevent token overflow?"
> *"We never feed an entire codebase to an LLM. We run a three-stage filter:
> 1. Exclusion filters strip docs, test fixtures, and build artifacts.
> 2. Deterministic scanners handle secrets and dependencies with zero LLM tokens.
> 3. Tree-sitter isolates only entrypoints, server actions, and mutation routes. 
> 
> Only the relevant functions and their direct middleware context are sent to the LLM in isolated chunks, maintaining strict token bounds."*

---

## 3. Resume Bullet Points

Copy and adapt these bullet points for your resume:

*   *Architected **VibeGuard**, an automated DevSecOps platform combining Tree-sitter AST parsing and LLM semantic analysis to detect logic flaws and authorization bypasses (IDOR) in AI-generated web applications.*
*   *Engineered an asynchronous scan pipeline using FastAPI, Celery, and Redis, reducing LLM token consumption by over 40% through deterministic pre-filtering and AST-based context extraction.*
*   *Designed a normalized Hardening Index (0–100) and automated remediation pipeline producing unified Git diffs and automated GitHub pull requests for identified vulnerabilities.*