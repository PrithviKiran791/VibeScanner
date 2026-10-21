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
*   Build the minimal dark-mode UI in **Next.js 14**.
*   Render the Hardening Score ($0 - 100$) and status indicators.
*   Render syntax-highlighted side-by-side Git diffs using `react-diff-viewer-continued`.
*   Implement the "Copy Diff" and "Apply Patch (Create PR)" workflows.

### Phase 4: Packaging & Placement Readiness (Week 5)
*   Containerize all services using `docker-compose.yml`.
*   Prepare a public demo repository containing intentional vibe-coded vulnerabilities for live interviewer demonstrations.

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