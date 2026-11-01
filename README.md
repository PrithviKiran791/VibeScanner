# VibeGuard

<p align="center">
  <strong>The First DevSecOps & Hardening Engine for AI-Generated & "Vibe-Coded" Web Applications</strong>
</p>

<p align="center">
  <img src="frontend/public/icons/shield.png" width="96" height="96" alt="VibeGuard Logo" />
</p>

<p align="center">
  <a href="#quick-start-guide"><img src="https://img.shields.io/badge/status-production--ready-10B981?style=for-the-badge&logoColor=white" alt="Status" /></a>
  <a href="#system-architecture"><img src="https://img.shields.io/badge/python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12" /></a>
  <a href="#frontend-architecture"><img src="https://img.shields.io/badge/Next.js-16.3-black?style=for-the-badge&logo=next.js&logoColor=white" alt="Next.js 16" /></a>
  <a href="#backend-architecture"><img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" /></a>
  <a href="#worker--job-scheduling"><img src="https://img.shields.io/badge/Celery-5.3+-37814A?style=for-the-badge&logo=celery&logoColor=white" alt="Celery" /></a>
  <a href="#database-schema"><img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL 16" /></a>
  <a href="#redis-caching--coordination"><img src="https://img.shields.io/badge/Redis-7-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis 7" /></a>
  <a href="#uiux-design-minimalist-dark-brutalism"><img src="https://img.shields.io/badge/design-Dark_Brutalism-EF4444?style=for-the-badge" alt="Dark Brutalism" /></a>
</p>

---

## Table of Contents

1. [Executive Summary & The "Vibe-Coding" Crisis](#executive-summary--the-vibe-coding-crisis)
2. [Core Architectural Principles](#core-architectural-principles)
   - [Hybrid Multi-Pass Scan Pipeline](#1-hybrid-multi-pass-scan-pipeline)
   - [Tree-Sitter Syntactic Pruning & AST Heuristics](#2-tree-sitter-syntactic-pruning--ast-heuristics)
   - [Hallucination Guard & Patch Verification](#3-hallucination-guard--patch-verification)
   - [Zero-Secret Storage Architecture](#4-zero-secret-storage-architecture)
   - [Deterministic Hardening Index (0–100)](#5-deterministic-hardening-index-0100)
3. [System Architecture](#system-architecture)
   - [Multi-Tier System Topology](#multi-tier-system-topology)
   - [End-to-End Scan Execution Flow](#end-to-end-scan-execution-flow)
   - [Automated Pull Request Lifecycle](#automated-pull-request-lifecycle)
4. [Component Deep-Dive](#component-deep-dive)
   - [Analysis Engine (`backend/vibeguard/engine/`)](#analysis-engine-backendvibeguardengine)
   - [API Gateway (`backend/vibeguard/api/`)](#api-gateway-backendvibeguardapi)
   - [Worker & Job Scheduling (`backend/vibeguard/worker/`)](#worker--job-scheduling-backendvibeguardworker)
   - [Database & Storage (`backend/vibeguard/db/`)](#database--storage-backendvibeguarddb)
   - [Frontend Dashboard (`frontend/`)](#frontend-dashboard-frontend)
5. [UI/UX Design: Minimalist Dark Brutalism](#uiux-design-minimalist-dark-brutalism)
6. [Quick Start Guide](#quick-start-guide)
   - [Option 1: Zero-Docker Dev Server (Recommended for Local Dev)](#option-1-zero-docker-dev-server-recommended-for-local-dev)
   - [Option 2: Full Docker Compose Microservices](#option-2-full-docker-compose-microservices)
   - [Option 3: Standalone CLI Scan](#option-3-standalone-cli-scan)
7. [Testing the Included Insecure Demo App](#testing-the-included-insecure-demo-app)
8. [CLI Reference & CI/CD Gate](#cli-reference--cicd-gate)
9. [REST API Reference & Webhooks](#rest-api-reference--webhooks)
10. [Configuration & Environment Variables](#configuration--environment-variables)
11. [Repository Layout](#repository-layout)
12. [Technical Interview Defense & Senior Engineering Q&A](#technical-interview-defense--senior-engineering-qa)

---

## Executive Summary & The "Vibe-Coding" Crisis

AI-powered code generators (Cursor, v0, Lovable, Claude Code, GitHub Copilot) allow developers to build full-stack web applications at unprecedented velocity ("vibe coding"). However, LLMs have distinct security blind spots that introduce severe, systemic vulnerabilities:

1. **Broken Object-Level Authorization (BOLA / IDOR):** LLMs routinely generate route handlers that query records directly by client-supplied route parameters (e.g. `db.user.findUnique({ where: { id: req.params.id } })`) with zero session identity validation.
2. **Secret Leakage & Client-Boundary Conflation:** Private API keys (Stripe, Supabase service roles) are frequently mixed into client components or leaked through `NEXT_PUBLIC_*SECRET*` variables.
3. **Slopsquatting & Hallucinated Dependencies:** LLMs invent believable package names in `package.json` that do not exist on npm or PyPI, leaving the repository open to supply-chain package takeover.
4. **Dangerous Injection Sinks:** Unchecked SQL template string interpolation, unescaped `dangerouslySetInnerHTML`, and direct shell invocations via `child_process.exec()`.
5. **Traditional SAST Failure:** Legacy SAST tools (SonarQube, Snyk) produce overwhelming walls of false positives, lack business-logic context, and provide generic documentation links rather than ready-to-merge Git patches.

**VibeGuard solves this.** It couples deterministic, token-free AST/Regex static analysis with a highly pruned, structured semantic LLM review. It calculates a deterministic **Hardening Index (0–100)** and produces **zero-touch, syntax-verified unified Git pull requests**.

---

## Core Architectural Principles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             VIBEGUARD ENGINE                                │
│                                                                             │
│   ┌─────────────────────┐   ┌──────────────────────┐   ┌─────────────────┐  │
│   │ Pass 1: Static AST  │   │ Pass 2: AST Pruning  │   │ Pass 3: LLM     │  │
│   │ • Regex & Entropy   │──►│ • Tree-sitter parse  │──►│ • JSON Schema   │  │
│   │ • Registry Audits   │   │ • Extract Endpoints  │   │ • Logic/BOLA    │  │
│   │ • Syntactic Sinks   │   │ • Heuristic Ranking  │   │ • Unified Diffs │  │
│   └─────────────────────┘   └──────────────────────┘   └─────────────────┘  │
│              │                         │                        │           │
│              ▼                         ▼                        ▼           │
│     [0 Token Overhead]        [~80% Boilerplate Drop]   [Bounded Context]   │
│              │                         │                        │           │
│              └─────────────────────────┼────────────────────────┘           │
│                                        ▼                                    │
│                       ┌─────────────────────────────────┐                   │
│                       │   Pass 4: Merge & Deduplicate   │                   │
│                       │   • Hallucination Guard Check   │                   │
│                       │   • Deterministic Score (0-100) │                   │
│                       │   • Span-Based Remediation      │                   │
│                       └─────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. Hybrid Multi-Pass Scan Pipeline

| Pass | Engine & Methodology | Target Vulnerabilities | Token Cost |
| :--- | :--- | :--- | :--- |
| **Pass 1: Deterministic Static** | Regex, Shannon entropy analysis (Gitleaks-ported rules), direct registry HTTP checks (npm/PyPI), Tree-sitter AST queries. | Leaked API keys, Supabase service roles, `NEXT_PUBLIC_*` leaks, hallucinated packages, raw SQL interpolation, `eval()`, `dangerouslySetInnerHTML`, command injection. | **0 tokens** (Instant) |
| **Pass 2: AST Relevance Pruning** | Tree-sitter AST extraction of Next.js App Router handlers (`app/**/route.ts`), Pages API (`pages/api/**`), Express routes, and `"use server"` actions. | Isolates attack surfaces; filters out docs, tests, styles, and static assets; ranks endpoints by risk signals. | **0 tokens** |
| **Pass 3: Semantic LLM Review** | Targeted LLM inference (Google Gemma 4 31B via OpenRouter, falling back to Gemma 26B, Nemotron, or dots) with strict JSON Schema output. | Broken Object-Level Authorization (BOLA/IDOR), client/server boundary leakage, missing mutation auth checks, business logic flaws. | **Strictly bounded** |
| **Pass 4: Merge & Scoring** | Collision detection, finding deduplication, AST patch syntax validation, mathematical Hardening Index calculation. | Deduplicates overlapping static/LLM findings, validates patch compilation, and produces final report. | **0 tokens** |

### 2. Tree-Sitter Syntactic Pruning & AST Heuristics

Sending entire codebases to an LLM exhausts token budgets, causes context dilution, and introduces non-deterministic hallucinations. VibeGuard's `vibeguard.engine.syntax.routes` module parses TypeScript/JavaScript source into an Abstract Syntax Tree using `tree-sitter-language-pack`.

The engine extracts only exposed entrypoints and tags each code unit with heuristic risk signals:
- **`DB_SIGNAL`:** Access to `prisma`, `supabase`, `drizzle`, `mongoose`, `db.query()`, etc.
- **`INPUT_SIGNAL`:** Presence of `params`, `searchParams`, `req.body`, `request.json()`.
- **`AUTH_SIGNAL`:** Checks for `getServerSession`, `currentUser`, `jwt.verify`, `requireAuth`.
- **`MUTATION_SIGNAL`:** Mutation operations (`.create()`, `.update()`, `.delete()`, `.upsert()`).

Only endpoints handling user input or database records without obvious auth guards are forwarded to the LLM, reducing LLM token consumption by **over 80%**.

### 3. Hallucination Guard & Patch Verification

To guarantee that the LLM never reports non-existent issues or invalid code:
1. **Enclosing Unit Check:** An LLM finding is rejected unless its reported line range is strictly contained inside a code unit actually sent to the model.
2. **Verbatim Evidence Matching:** The `vulnerable_code` snippet returned by the model must exist verbatim in the target file's lines.
3. **AST Patch Re-Parsing:** Every suggested patch is applied in memory and re-parsed with Tree-sitter. If the patch introduces a syntax error, the patch is discarded while preserving the finding description.

### 4. Zero-Secret Storage Architecture

VibeGuard operates under a strict zero-retention security policy for credentials:
- **No Secret Persistence:** Discovered API keys and secrets are **never** stored in the database.
- **Masked Diffs for Display:** Finding diffs stored in PostgreSQL have secret characters masked (`****************`).
- **Span-Based PR Remediation:** Instead of raw diffs, secret findings store a `remediations` record with relative coordinates (`file_path`, `line`, `col_start`, `col_end`, `replacement`, `verify_rule`).
- When dispatching a GitHub PR, the worker pulls a fresh copy of the default branch, executes the verification rule to ensure the secret is still present at that exact coordinate, replaces it with `process.env.VARIABLE_NAME`, and leaves the secret out of VibeGuard's database entirely.

### 5. Deterministic Hardening Index (0–100)

The LLM is **never** permitted to calculate or influence the security score. The **Hardening Index** is calculated mathematically:

$$\text{Hardening Index} = \max\left(0, 100 - \sum_{f \in \text{Open Security Findings}} \text{Penalty}(f.\text{severity})\right)$$

| Severity | Penalty Points | Typical Vulnerability Examples |
| :--- | :---: | :--- |
| **CRITICAL** | **−25 pts** | IDOR/BOLA authorization bypass, exposed live API key, remote code execution (RCE). |
| **HIGH** | **−12 pts** | Hallucinated dependency (slopsquatting), missing CSRF on mutation, raw SQL injection. |
| **MEDIUM** | **−5 pts** | Missing rate limiting on sensitive route, unescaped HTML sink (`dangerouslySetInnerHTML`). |
| **LOW** | **−1 pt** | Deprecated cryptographic method, permissive TypeScript `any`, unhandled error disclosure. |
| **INFO** | **0 pts** | Informational architecture notices and non-blocking security recommendations. |

**Score Banding:**
- **80 – 100:** `HARDENED` (Green theme, secure for deployment)
- **60 – 79:** `NEEDS WORK` (Neutral theme, moderate risks present)
- **0 – 59:** `AT RISK` (Red theme, critical exploits present)

*Reactivity:* Triage actions (dismissing a false positive or applying a patch) dynamically recalculate the score across all open findings in real-time.

---

## System Architecture

### Multi-Tier System Topology

```mermaid
flowchart TD
    subgraph ClientLayer ["Client & Edge Layer"]
        Browser["Next.js Web Dashboard (:3000)"]
        CLIClient["VibeGuard CLI Client"]
        GHHook["GitHub Push Webhook"]
        Nginx["Nginx Edge Proxy (:3000)"]
    end

    subgraph ServiceLayer ["FastAPI Service Layer (:8000)"]
        API["FastAPI Application"]
        AuthModule["Firebase JWT JWKS Verifier"]
        RateLimiter["Redis Fixed-Window Rate Limiter"]
        LockMgr["Concurrency Lock Manager"]
    end

    subgraph BrokerLayer ["State & Message Broker"]
        RedisPubSub["Redis 7 (Jobs, Progress, Locks)"]
        CeleryQueue["Celery Task Queue"]
    end

    subgraph WorkerLayer ["Distributed Scan Sandboxes"]
        Worker["Celery Worker (Pool: Solo / Fork)"]
        Workspace["Ephemeral Ramdisk Sandbox (/tmp/scans)"]
        StaticEngine["Deterministic Static & AST Engine"]
        TreeSitter["Tree-sitter AST Route Pruner"]
        LLMGuard["Hallucination & Syntax Guard"]
    end

    subgraph ExternalServices ["External Providers & Storage"]
        OpenRouter["OpenRouter / Google Gemma LLM"]
        GitHubAPI["GitHub REST API (PR & Fork Engine)"]
        Postgres[("PostgreSQL 16 (Relational Store)")]
        NPMRegistry["npm / PyPI Live Registries"]
    end

    Browser -->|HTTP / Poll| Nginx
    CLIClient -->|Direct CLI Scan| StaticEngine
    GHHook -->|HMAC-SHA256 Push| Nginx
    Nginx -->|/api/*| API
    Nginx -->|/*| Browser

    API --> AuthModule
    API --> RateLimiter
    API --> LockMgr
    API -->|Enqueue Job| CeleryQueue
    API -->|Write Scan Record| Postgres

    CeleryQueue --> Worker
    Worker --> Workspace
    Workspace --> StaticEngine
    StaticEngine --> NPMRegistry
    StaticEngine --> TreeSitter
    TreeSitter --> LLMGuard
    LLMGuard --> OpenRouter
    Worker -->|Update Progress Hash| RedisPubSub
    Worker -->|Commit Findings & Score| Postgres
    Worker -->|Auto-wipe Clone| Workspace

    API -->|One-Click Fix PR| GitHubAPI
    GitHubAPI -->|Open Pull Request| Browser
```

### End-to-End Scan Execution Flow

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant UI as Next.js Dashboard
    participant API as FastAPI Gateway
    participant Redis as Redis Broker
    participant Celery as Celery Worker
    participant Engine as Hybrid Engine
    participant LLM as OpenRouter (Gemma)
    participant DB as PostgreSQL

    Dev->>UI: Enter repo URL (e.g. acme/vibe-app)
    UI->>API: POST /api/v1/scans {"repo_url": "..."}
    API->>API: Verify Firebase JWT & Check Allowlist
    API->>Redis: Check concurrency lock (scan:lock:{repo})
    API->>DB: Insert Scan record (Status: QUEUED)
    API->>Celery: Enqueue run_scan_task(scan_id)
    API-->>UI: 202 Accepted {scan_id, status: "QUEUED"}

    Celery->>Redis: Acquire lock & update progress (10% - CLONING)
    Celery->>Engine: Shallow clone repo (depth=1, max 50MB)
    Celery->>Redis: Update progress (30% - ANALYZING_STATIC)
    Engine->>Engine: Pass 1: Scan Secrets, Check npm/PyPI, Query Sinks
    
    Celery->>Redis: Update progress (60% - ANALYZING_LLM)
    Engine->>Engine: Pass 2: Tree-sitter AST extraction & route pruning
    Engine->>LLM: Pass 3: Post filtered route chunks (JSON Schema mode)
    LLM-->>Engine: Structured JSON findings with diffs
    Engine->>Engine: Pass 4: Validate line ranges & verify patch AST
    Engine->>Engine: Merge static + LLM findings, compute Hardening Index

    Celery->>DB: Persist Findings, Remediations, and Hardening Score
    Celery->>DB: Update Scan (Status: COMPLETED, duration_ms)
    Celery->>Redis: Release lock & set progress (100% - COMPLETED)
    Celery->>Engine: Wipe sandbox workspace directory

    loop Every 1 Second
        UI->>API: GET /api/v1/scans/{id}
        API->>Redis: Read live progress hash
        API-->>UI: Return status, percentage, and metrics
    end

    UI->>Dev: Render 38/62 Triage Workspace & Hardening Score
```

### Automated Pull Request Lifecycle

When a developer clicks **Apply Fix (PR)** in the dashboard:

```mermaid
flowchart TD
    Start["User clicks 'Apply Fix (PR)'"] --> FetchFinding["API fetches finding & remediation row"]
    FetchFinding --> CheckSource{"Is Scan Source GITHUB?"}
    CheckSource -- No --> Err400["400 Bad Request: PRs require GitHub scans"]
    CheckSource -- Yes --> FetchCurrent["GitHub API: Fetch current file on default branch"]

    FetchCurrent --> HasDiff{"Does finding have automated fix?"}
    HasDiff -- No --> Err422["422 Unprocessable: Manual fix required"]
    HasDiff -- Yes --> CheckKind{"Is finding a Secret or Code Diff?"}

    CheckKind -- Secret Span --> VerifyRule["Re-execute verify_rule on target file span"]
    VerifyRule -- No match --> Err409["409 Conflict: Secret already modified/rotated"]
    VerifyRule -- Matches --> ReplaceSpan["Swap secret span with process.env.VAR_NAME"]

    CheckKind -- Code Diff --> StrictApply["apply_unified_diff(current_file, stored_diff)"]
    StrictApply -- Context drift --> Err409
    StrictApply -- Clean match --> PatchedCode["Generate patched file content"]

    ReplaceSpan --> CheckPerms{"Does VIBEGUARD_GITHUB_TOKEN have push access?"}
    PatchedCode --> CheckPerms

    CheckPerms -- Direct Collaborator --> CreateBranch["Create branch 'vibeguard/{rule}-{id}' on repo"]
    CheckPerms -- External Open-Source --> ForkRepo["Fork repo to token user account"]
    ForkRepo --> PollFork["Poll until fork is ready"]
    PollFork --> CreateBranchFork["Create branch on fork"]

    CreateBranch --> CommitChanges["Commit patched file to branch"]
    CreateBranchFork --> CommitChanges

    CommitChanges --> OpenPR["Open Pull Request to base repo default branch"]
    OpenPR --> SavePR["Save pull_requests row (prevents duplicates)"]
    SavePR --> Return201["201 Created: Return PR Number & GitHub URL"]
```

---

## Component Deep-Dive

### Analysis Engine (`backend/vibeguard/engine/`)

The analysis engine is completely isolated from HTTP frameworks, Celery, and databases. It can run anywhere as a standalone CLI or embedded Python library:

*   [`ingest/workspace.py`](backend/vibeguard/engine/ingest/workspace.py): Creates an isolated temporary directory, executes shallow git clones (`--depth 1`, `--single-branch`, no submodules), unpacks safe ZIP archives, enforces a 50MB source budget, and ensures deterministic deletion via `Workspace.cleanup()`.
*   [`ingest/file_index.py`](backend/vibeguard/engine/ingest/file_index.py): Filters out binary formats, build outputs (`dist/`, `.next/`, `build/`), dependency folders (`node_modules/`, `venv/`), lockfiles, and documentation.
*   [`static/secrets.py`](backend/vibeguard/engine/static/secrets.py) & [`rules/secrets.toml`](backend/vibeguard/engine/static/rules/secrets.toml): Regex patterns ported from Gitleaks and TruffleHog covering Stripe, AWS, GitHub, OpenAI, Supabase, Anthropic, Slack, and generic JWT tokens, paired with Shannon entropy scoring.
*   [`static/deps.py`](backend/vibeguard/engine/static/deps.py): Parses `package.json` and `requirements.txt`. Queries npm (`registry.npmjs.org`) and PyPI (`pypi.org`) with a 24-hour Redis cache to detect hallucinated dependencies (slopsquatting).
*   [`static/sinks.py`](backend/vibeguard/engine/static/sinks.py): AST queries detecting unsafe Prisma methods (`$queryRawUnsafe`), SQL string interpolation, raw `eval()`, `child_process.exec()`, and unescaped `dangerouslySetInnerHTML`. Automatically generates DOMPurify sanitization patches.
*   [`syntax/routes.py`](backend/vibeguard/engine/syntax/routes.py): Tree-sitter entry point extractor for Next.js App Router, Pages router, and Express. Computes risk signals.
*   [`llm/`](backend/vibeguard/engine/llm/): Pluggable LLM interface supporting OpenRouter (OpenAI-compatible) and Google GenAI (Gemini). Enforces strict Pydantic JSON schemas.
*   [`llm/validate.py`](backend/vibeguard/engine/llm/validate.py): Hallucination guard ensuring evidence matches real file lines and suggested patches re-parse cleanly in Tree-sitter.
*   [`patch.py`](backend/vibeguard/engine/patch.py): Strict unified diff applier that rejects patches if the target file has drifted.
*   [`scoring.py`](backend/vibeguard/engine/scoring.py): Mathematical Hardening Index computation.

### API Gateway (`backend/vibeguard/api/`)

Built with FastAPI (Python 3.12+), asynchronous SQLAlchemy 2.0, and Pydantic v2:

*   [`main.py`](backend/vibeguard/api/main.py): Application factory, CORS configuration, security headers, exception handlers, and health endpoints (`/healthz` for liveness, `/readyz` for PostgreSQL and Redis readiness).
*   [`auth.py`](backend/vibeguard/api/auth.py): Verifies Firebase Authentication JWTs against Google's public JWKS certificates (`securetoken.google.com`) using RS256. Enforces strict email, domain, or GitHub account ID allowlists. Fails closed if unconfigured.
*   [`ratelimit.py`](backend/vibeguard/api/ratelimit.py): Fixed-window rate limiter in Redis. Evaluates client IPs by parsing `X-Forwarded-For` right-to-left against configured CIDR trusted proxy subnets (`VIBEGUARD_TRUSTED_PROXIES`).
*   [`webhooks.py`](backend/vibeguard/api/webhooks.py): Handles GitHub push webhooks. Authenticates payloads with HMAC-SHA256 (`X-Hub-Signature-256`), deduplicates events using `X-GitHub-Delivery` GUIDs (24h TTL in Redis), and automatically queues scans for default branch commits.
*   [`routes.py`](backend/vibeguard/api/routes.py): REST endpoints for starting scans, querying live progress, listing findings, triage state mutation, and opening GitHub fix pull requests.

### Worker & Job Scheduling (`backend/vibeguard/worker/`)

*   [`celery_app.py`](backend/vibeguard/worker/celery_app.py): Configures Celery with Redis broker and result backend.
*   [`tasks.py`](backend/vibeguard/worker/tasks.py): Contains `run_scan_task`, orchestrating repository ingest, static passes, LLM analysis, database commits, and ramdisk cleanup.
*   [`state.py`](backend/vibeguard/worker/state.py): Updates live Redis hash keys (`scan:job:{scan_id}`) with percentages and step names (`CLONING`, `ANALYZING_STATIC`, `ANALYZING_LLM`, `COMPLETED`, `FAILED`).
*   [`contracts.py`](backend/vibeguard/worker/contracts.py): Type-safe task payload schemas.

### Database & Storage (`backend/vibeguard/db/`)

PostgreSQL 16 relational storage with Alembic migrations (`backend/alembic/versions/`):

```sql
-- Core Schema Entities
repositories (id, name, url UNIQUE, default_branch, is_private, created_at)
scans        (id, repo_id, source_type, commit_hash, status, hardening_score,
              total_findings, critical_count, high_count, medium_count, low_count,
              files_scanned, llm_used, warnings, quality_score, quality_grade, duration_ms)
findings     (id, scan_id, domain [SECURITY|QUALITY], rule_id, severity, category,
              title, cwe_id, file_path, line_start, line_end, snippet_original,
              snippet_fixed, unified_diff, explanation, source, status)
remediations (id, finding_id UNIQUE, kind, file_path, line, col_start, col_end,
              replacement, env_var_name, expected_text, verify_rule)
pull_requests(id, finding_id UNIQUE, pr_number, pr_url, branch_name, created_at)
users        (id, firebase_uid UNIQUE, email, name, picture, github_id, created_at)
```

### Frontend Dashboard (`frontend/`)

Built with Next.js 16 (App Router), React 19, TypeScript, and Tailwind CSS:

*   **38% / 62% Split Triage Workspace** ([`src/components/scan/ScanWorkspace.tsx`](frontend/src/components/scan/ScanWorkspace.tsx)):
    *   *Left Pane (38%):* Domain tabs (All, Security, Quality), interactive findings distribution chart, and scrollable finding card list.
    *   *Right Pane (62%):* Inspector showing CWE badge, "Why It Matters" root cause explainer, interactive unified diff viewer, and remediation action bar.
*   **Diff View Component** ([`src/components/inspector/DiffView.tsx`](frontend/src/components/inspector/DiffView.tsx)): Custom brutalist diff renderer displaying syntax-highlighted, red/green industrial gradient rows for deleted/added code with line numbers.
*   **12-Piece Custom Icon System** ([`src/components/ui/AppIcon.tsx`](frontend/src/components/ui/AppIcon.tsx)): Standardized pixel-crisp Next.js Image component mapping all 12 platform assets (`shield`, `security`, `scanner`, `coding`, `github`, `clone`, `staticPass`, `semanticPass`, `fix`, `success`, `failed`, `social`).
*   **Neobrutalist Design Kit:** Neobrutalism Button, Spinner, Progress, Menubar, and interactive WebGL canvas background (`ShapeWaves`).
*   **Live Progress Polling:** React hook polling `GET /api/v1/scans/{id}` reading the worker's Redis progress hash every 1000ms.

---

## UI/UX Design: Minimalist Dark Brutalism

VibeGuard strictly follows a **Minimalist Dark Brutalist** aesthetic:

*   **Geometry:** `0px` border radius on cards, panels, navbars, badges, and code blocks (`rounded-none`). Form inputs and buttons use `rounded-ctl` (`10px`). Layout dividers use `2px` solid borders.
*   **Hard Offset Shadows:** No soft blurs. Physical offsets provide depth:
    *   Neutral border: `4px 4px 0px #27272A`
    *   Critical exploit: `4px 4px 0px #EF4444`
    *   Hardened / CTA: `4px 4px 0px #059669`
    *   Active pressed state: `transform: translate(2px, 2px)` with shadow collapsing to `2px 2px 0px`.
*   **Strict Color Palette:**
    *   `obsidian` (`#09090B`): Primary canvas and fixed navigation.
    *   `carbon` (`#121216`): Structural blocks and finding cards.
    *   `graphite` (`#1E1E24`): Inputs, button backgrounds, and hover fills.
    *   `hairline` (`#27272A`): Structural dividers and neutral borders.
    *   `bone` (`#FAFAFA`): High-contrast primary typography.
    *   `ash` (`#A1A1AA`): Secondary metadata, file paths, and descriptions.
    *   `risk` (`#EF4444`): Vulnerable code, deleted diff rows, critical alerts.
    *   `secure` (`#10B981`): Hardened state, added diff rows, primary action buttons.
*   **Dual Typography Hierarchy:**
    *   *Headings, Scores, Stamps, Buttons:* **Asap** (700/800 uppercase, `letter-spacing: 0.06em`).
    *   *Body, Explanations, Code, Diffs:* **Open Sans** (400/500/600, tabular figures).

---

## Quick Start Guide

### Option 1: Zero-Docker Dev Server (Recommended for Local Dev)

The dev server runs SQLite (auto-migrated via Alembic), an in-memory Redis instance (`fakeredis`), and an in-process scan worker thread. No Docker, PostgreSQL, or cloud services required.

```powershell
# 1. Clone the repository
git clone https://github.com/your-username/VibeCoded_Vulnerability_Scanner.git
cd VibeCoded_Vulnerability_Scanner

# 2. Set up Backend Python Virtual Environment
cd backend
py -3.12 -m venv .venv
.venv\Scripts\pip install -e ".[openrouter,service,dev]"
cd ..

# 3. Build the Insecure Demo App Fixtures
backend\.venv\Scripts\python -m tests.fixtures.materialize demo_app

# 4. Launch Backend Dev Server (Terminal 1)
backend\.venv\Scripts\python -m vibeguard.devserver --root .
# API live on http://127.0.0.1:8000 with Swagger docs at /docs

# 5. Launch Frontend Dashboard (Terminal 2)
npm --prefix frontend install
npm --prefix frontend run dev
# Dashboard live on http://localhost:3000
```

> **Note:** To enable the LLM semantic pass, set `OPENROUTER_API_KEY=your_key` in `backend/.env`. To enable **Apply Fix (PR)**, set `VIBEGUARD_GITHUB_TOKEN=your_pat` (repo scope).

---

### Option 2: Full Docker Compose Microservices

Runs the complete containerized production topology: PostgreSQL 16, Redis 7, Alembic migration container, Celery worker, FastAPI app, Next.js frontend, and an Nginx reverse proxy edge on `http://localhost:3000`.

```powershell
# 1. Configure environment
cp docker/.env.example docker/.env
# Edit docker/.env to provide OPENROUTER_API_KEY, VIBEGUARD_GITHUB_TOKEN, etc.

# 2. Build and launch all services
docker compose -f docker/docker-compose.yml --profile app up --build -d

# 3. View status and logs
docker compose -f docker/docker-compose.yml ps
docker compose -f docker/docker-compose.yml logs -f api worker
```

*Edge Routing:*
- `http://localhost:3000/api/*` $\rightarrow$ FastAPI Gateway (`api:8000`)
- `http://localhost:3000/*` $\rightarrow$ Next.js Dashboard (`dashboard:3000`)
- Direct API debug access: `http://localhost:8000/docs`

---

### Option 3: Standalone CLI Scan

Scan local directories or public GitHub repos directly from your terminal with zero server overhead:

```powershell
cd backend

# Scan local codebase (deterministic only, zero tokens)
.venv\Scripts\vibeguard scan ..\demo_app --no-llm

# Scan with LLM Semantic Review and export JSON & Markdown reports
.venv\Scripts\vibeguard scan https://github.com/owner/repo --json report.json --markdown report.md

# Run test suite
.venv\Scripts\python -m pytest
```

---

## Testing the Included Insecure Demo App

VibeGuard includes a deliberately vulnerable full-stack Next.js application (`demo_app/`) specifically structured to trigger every detection capability:

1. **Materialize the demo app fixtures:**
   ```powershell
   backend\.venv\Scripts\python -m tests.fixtures.materialize demo_app
   ```
2. **Scan the demo app:**
   - In the Dashboard (`http://localhost:3000`), paste the absolute path to `demo_app`.
   - Or use the CLI: `backend\.venv\Scripts\vibeguard scan demo_app`.
3. **Observed Detections:**
   - **Critical:** Live hardcoded Stripe Secret Key in `lib/stripe.ts` (Gitleaks rule).
   - **Critical:** BOLA/IDOR vulnerability in `app/api/user/[id]/route.ts` (LLM Semantic Review).
   - **Critical:** Raw SQL command injection in `app/api/search/route.ts` (AST Sink Pass).
   - **High:** Hallucinated package in `package.json` (Registry Audit).
   - **High:** Command injection via `child_process.exec()` in `app/api/convert/route.ts`.
   - **Medium:** Unescaped XSS sink via `dangerouslySetInnerHTML` in `components/Comment.tsx`.

---

## CLI Reference & CI/CD Gate

The CLI supports exit-code thresholds, making it suitable for CI/CD pipeline enforcement:

```text
Usage: vibeguard scan [OPTIONS] TARGET

Arguments:
  TARGET                  Local directory path or GitHub repository URL.

Options:
  --no-llm                Run deterministic static pass only (0 tokens).
  --no-registry           Skip live npm/PyPI registry availability lookups.
  --json PATH             Export detailed vulnerability findings to a JSON file.
  --markdown PATH         Export an executive audit summary as Markdown.
  --fail-under INTEGER    Exit with status 1 if Hardening Index is below this score.
  --diff-only             Output only the unified diff patches for detected flaws.
```

### GitHub Actions Workflow Example (`.github/workflows/security.yml`)

```yaml
name: VibeGuard Security Gate

on:
  pull_request:
    branches: [main]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install VibeGuard
        run: |
          pip install git+https://github.com/your-username/VibeCoded_Vulnerability_Scanner.git#subdirectory=backend

      - name: Run Scan & Enforce Hardening Index >= 80
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        run: |
          vibeguard scan . --fail-under 80 --markdown audit-report.md

      - name: Attach Audit Report to PR
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            if (fs.existsSync('audit-report.md')) {
              const body = fs.readFileSync('audit-report.md', 'utf8');
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: body
              });
            }
```

---

## REST API Reference & Webhooks

All write endpoints require a Bearer token (`Authorization: Bearer <firebase_jwt>`) when Firebase is configured.

| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/scans` | Start a new scan (`repo_url` or `local_path`, options: `llm`, `registry`). | `202 Accepted`, `409 Conflict` (if scan running) |
| `GET` | `/api/v1/scans` | List scan history, sorted newest first (`?limit=20`). | `200 OK` |
| `GET` | `/api/v1/scans/{id}` | Fetch scan status, live Redis progress (`0–100%`), and score counts. | `200 OK`, `404 Not Found` |
| `GET` | `/api/v1/scans/{id}/findings` | Retrieve all findings, severity metadata, masked diffs, and PR links. | `200 OK`, `404 Not Found` |
| `PATCH`| `/api/v1/findings/{id}` | Update triage status (`OPEN`, `PATCH_APPLIED`, `DISMISSED_FALSE_POSITIVE`, `RESOLVED`). Recalculates score. | `200 OK`, `404 Not Found` |
| `POST` | `/api/v1/findings/{id}/pull-request` | Rebuilds fix on default branch and opens a GitHub Pull Request. | `201 Created`, `200 OK` (exists), `409 Conflict` (drift) |
| `GET` | `/api/v1/me` | Fetch authenticated user principal profile. | `200 OK`, `401 Unauthorized` |
| `POST` | `/api/v1/webhooks/github` | Ingest GitHub push webhook events (HMAC-SHA256 authenticated). | `200 OK`, `400 Bad Request`, `401 Unauthorized` |
| `GET` | `/healthz` | Kubernetes liveness probe. | `200 OK` |
| `GET` | `/readyz` | Readiness probe (verifies PostgreSQL and Redis socket connectivity). | `200 OK`, `503 Service Unavailable` |

---

## Configuration & Environment Variables

All settings can be specified via environment variables or a `.env` file:

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `VIBEGUARD_DATABASE_URL` | `sqlite:///backend/.dev/vibeguard.db` | PostgreSQL connection string (`postgresql+psycopg://user:pass@host:5432/db`). |
| `VIBEGUARD_REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL for Celery, caching, locks, and progress state. |
| `OPENROUTER_API_KEY` | *None* | API key for OpenRouter LLM semantic inference. If omitted, scans are static-only. |
| `LLM_MODEL` | `google/gemma-4-31b-it:free` | Primary model identifier. |
| `LLM_FALLBACK_MODEL` | `google/gemma-4-26b-a4b-it:free` | Fallback model tried when OpenRouter returns 429 rate limit or 5xx. |
| `VIBEGUARD_GITHUB_TOKEN` | *None* | GitHub Personal Access Token (repo scope) used to fork, branch, and open PRs. |
| `VIBEGUARD_GITHUB_WEBHOOK_SECRET`| *None* | Shared secret for verifying GitHub push webhook HMAC-SHA256 signatures. |
| `VIBEGUARD_ALLOW_LOCAL_PATHS` | `false` | Enable scanning server-side local directory paths (local dev only). |
| `VIBEGUARD_LOCAL_SCAN_ROOT` | Current working dir | Boundary root folder restricting allowed local scan paths. |
| `VIBEGUARD_FIREBASE_PROJECT_ID` | *None* | Firebase project ID for verifying client authorization tokens. |
| `VIBEGUARD_AUTH_ALLOWED_EMAILS` | `[]` | JSON array of whitelisted user email addresses. |
| `VIBEGUARD_AUTH_ALLOWED_DOMAINS`| `[]` | JSON array of whitelisted corporate domains (e.g. `["@company.com"]`). |
| `VIBEGUARD_TRUSTED_PROXIES` | `["127.0.0.1"]` | JSON array of trusted proxy CIDRs allowed to vouch for `X-Forwarded-For`. |

---

## Repository Layout

```text
.
├── backend/
│   ├── alembic/                         # Database schema migration scripts (0001 - 0005)
│   ├── tests/                           # Service, engine, diff, and fixture test suites
│   │   └── fixtures/                    # Materialization scripts for vulnerable demo apps
│   ├── vibeguard/
│   │   ├── api/                         # FastAPI application, auth, routes, and webhooks
│   │   ├── db/                          # SQLAlchemy models, sessions, and triage scoring
│   │   ├── engine/                      # Core analysis engine (zero external service dependencies)
│   │   │   ├── ingest/                  # Git shallow clone, ZIP unpack, 50MB file index
│   │   │   ├── static/                  # Gitleaks regex rules, npm/PyPI check, AST sinks
│   │   │   ├── syntax/                  # Tree-sitter AST route extraction & pruning
│   │   │   ├── llm/                     # OpenRouter/Gemini provider, schemas, hallucination guard
│   │   │   ├── diff.py                  # difflib patch generation
│   │   │   ├── patch.py                 # Strict unified diff re-applier
│   │   │   ├── scoring.py               # Deterministic Hardening Index calculation
│   │   │   └── pipeline.py              # Multi-pass scan pipeline orchestrator
│   │   ├── integrations/                # GitHub API client (fork, branch, commit, PR)
│   │   ├── worker/                      # Celery worker, tasks, Redis progress hash state
│   │   ├── config.py                    # Pydantic Settings configuration management
│   │   └── devserver.py                 # Zero-Docker development server (SQLite + fakeredis)
│   └── pyproject.toml                   # Python dependencies and build metadata
├── demo_app/                            # Intentionally vulnerable full-stack Next.js app
├── docker/                              # Multi-service containerization
│   ├── backend.Dockerfile               # Multi-stage non-root Python runtime
│   ├── docker-compose.yml               # PostgreSQL, Redis, Celery, API, Dashboard, Nginx
│   └── nginx.conf                       # Reverse proxy edge configuration
├── frontend/                            # Next.js 16 App Router web dashboard
│   ├── public/icons/                    # 12-piece standardized platform icon asset suite
│   ├── src/
│   │   ├── app/                         # App Router pages (/, /scan, /scans/[id], /rules, /docs)
│   │   ├── components/                  # Brutalist UI components, Inspector, DiffView
│   │   │   ├── auth/                    # Firebase Auth Provider, RequireAuth, GitHub login
│   │   │   ├── inspector/               # Unified diff visualizer and remediation action bar
│   │   │   ├── scan/                    # ScanWorkspace (38/62 split), NewScanForm, ScanProgress
│   │   │   └── ui/                      # Neobrutalism buttons, spinner, progress, AppIcon
│   │   └── lib/                         # Typed API client, session management, formatters
│   ├── tailwind.config.ts               # Brutalist theme tokens (obsidian, risk, secure)
│   └── package.json                     # Frontend dependencies
├── icons/                               # Master source icon image directory
└── markdown/                            # Architectural specs, PRD, and design requirements
```

---

## Technical Interview Defense & Senior Engineering Q&A

### Q1: "Why not just run SonarQube, Snyk, or Semgrep?"
> **Answer:** Traditional SAST tools rely on predefined syntactic taint-analysis rules and CVE databases. They excel at catching known syntax bugs, but are completely blind to the architectural shortcuts typical of vibe-coded applications. For example, an endpoint like `/api/user/[id]` that fetches records using `db.user.findUnique({ where: { id: req.params.id } })` looks clean to SonarQube because the query uses parameterized ORM methods without SQL injection. However, it is a severe BOLA/IDOR vulnerability because it never checks if `session.user.id == req.params.id`. VibeGuard uses Tree-sitter AST to prune and extract route entrypoints and session context, then uses a targeted LLM to inspect business logic. Furthermore, while legacy tools provide generic documentation links, VibeGuard outputs a verified, ready-to-merge unified Git pull request.

### Q2: "How do you prevent LLM hallucinations and non-deterministic scores?"
> **Answer:** We never allow the LLM to calculate or influence the security score. The Hardening Index is computed deterministically by our mathematical algorithm based on confirmed findings and their CVSS severity classifications. For vulnerability detection, we implement a multi-stage Hallucination Guard:
> 1. We require strict JSON Schema outputs validated through Pydantic.
> 2. The finding must fall strictly within the line boundaries of a code unit actually sent to the model.
> 3. The claimed vulnerable code snippet must exist verbatim in the target file.
> 4. The suggested patch is re-parsed with Tree-sitter. If the patch introduces a syntax error, it is discarded immediately.

### Q3: "What prevents token overflow on large repositories?"
> **Answer:** We never feed entire repositories to an LLM. We run a three-stage filter:
> 1. Ingestion exclusion filters strip lockfiles, media, build artifacts, test suites, and node_modules.
> 2. Deterministic static scanners handle secrets, package registries, and common injection sinks with zero LLM tokens.
> 3. Tree-sitter isolates only exposed entrypoints (Next.js route handlers, server actions, Express routes) and tags them with heuristic risk signals (mutations, database calls, missing auth tokens).
> Only high-risk code units are sent to the LLM in isolated chunks within a strict token budget.

### Q4: "How do you securely handle discovered API keys and secrets?"
> **Answer:** We follow a zero-retention policy. Plaintext secret values are never written to disk or persisted to the PostgreSQL database. When a secret is detected, its representation in database storage has the secret value replaced with asterisks. For automated remediation, we store only coordinate metadata (`file_path`, `line`, `col_start`, `col_end`, `verify_rule`). When dispatching a PR, the worker pulls a fresh copy of the default branch directly from GitHub, executes the regex verification rule to confirm the secret is still present at that exact offset, swaps it with `process.env.VARIABLE_NAME`, and opens the PR. The secret never touches VibeGuard's database.

---

<p align="center">
  <strong>VibeGuard</strong> · Built with precision for the modern AI software development era.
</p>
