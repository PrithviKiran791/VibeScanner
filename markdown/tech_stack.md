# Tech Stack Specification

## 1. Architectural Philosophy
VibeGuard relies on a **hybrid processing model**: deterministic analysis handles secrets, syntax, and package validity at near-zero latency and cost, while structured LLM calls focus solely on semantic authorization and business logic flows.

```
┌─────────────────────────────────────────────────────────────┐
│                       Frontend (Next.js)                    │
│           Minimal Dark Mode Dashboard & Diff Viewer         │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / WebSocket
┌──────────────────────────────▼──────────────────────────────┐
│                    FastAPI Backend Router                   │
│         Auth, Repository Management, Scan Dispatcher        │
└──────────────────────────────┬──────────────────────────────┘
                               │ Async Tasks (Celery)
┌──────────────────────────────▼──────────────────────────────┐
│                     Redis Message Broker                    │
└──────────────────────────────┬──────────────────────────────┘
                               │ Worker Jobs
┌──────────────────────────────▼──────────────────────────────┐
│                   Distributed Scan Worker                   │
│  ┌──────────────────────┐            ┌───────────────────┐  │
│  │ Tree-sitter / Semgrep│ ─────────► │ LLM Context Engine│  │
│  │ AST Parsing & RegEx  │            │ (Structured JSON) │  │
│  └──────────────────────┘            └───────────────────┘  │
└──────────────────────────────┬──────────────────────────────┘
                               │ Write Results
┌──────────────────────────────▼──────────────────────────────┐
│                   PostgreSQL (Supabase / RDS)               │
│               Scan Metadata, Findings, Metrics              │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Technology Selection Matrix

| Layer | Technology | Decision Rationale |
| :--- | :--- | :--- |
| **Frontend Framework** | **Next.js 14+ (App Router, TypeScript)** | High-density server-side rendering, native API routes for proxying, optimized asset delivery. |
| **UI & Styling** | **Tailwind CSS 3.4 + Lucide Icons** | Minimalist dark brutalist system (see `design.md`): zero radius, hard offset shadows, red/black/grey/green only. |
| **Diff Viewer** | **`react-diff-viewer-continued`** or custom Monaco view | High-performance syntax-highlighted side-by-side and unified git diff visualization. |
| **Backend API** | **FastAPI (Python 3.11+)** | High-throughput asynchronous endpoints, native Pydantic v2 data validation, native integration with security and AST libraries. |
| **Task Queue** | **Celery + Redis** | Decouples CPU/LLM intensive scan workflows from the HTTP request cycle; guarantees scalability and progress reporting. |
| **Static Code Analysis** | **Tree-sitter & Semgrep Core** | Tree-sitter provides language-agnostic AST parsing for source file filtering; Semgrep executes deterministic rules. |
| **Package Verification** | **Direct Registry API (npm/PyPI)** | Validates imported packages against live registry registries to identify hallucinated packages (slopsquatting). |
| **LLM Inference** | **Pluggable provider (`LLMProvider` interface). Default: Google Gemma 4 31B (`google/gemma-4-31b-it:free`) via OpenRouter's OpenAI-compatible API, falling back to `google/gemma-4-26b-a4b-it:free` on 429/5xx. Optional: Gemini via `google-genai`.** | Free, 262K context. JSON mode (`response_format: json_object`) plus per-finding Pydantic validation; the hallucination guard and Tree-sitter patch check are provider-independent. The engine runs deterministic-only when no key is configured. |
| **Database** | **PostgreSQL** | Relational schema ideal for normalized vulnerability findings, severity categories, and historical hardening trends. |
| **Containerization** | **Docker & Docker Compose** | Reproducible development, isolated worker execution sandboxes, and cloud-ready microservices. |

---

## 3. Core Libraries & Dependencies

### Backend (`backend/pyproject.toml`)
Phase 1 (engine) core:
```text
pydantic>=2.6
pydantic-settings>=2.2
tree-sitter>=0.23
tree-sitter-language-pack>=0.7     # replaces unmaintained tree-sitter-languages
httpx>=0.27                        # git itself runs via subprocess (portable clone timeout)
openai>=3.26                       # optional extra: [openrouter] (OpenAI-compatible client for OpenRouter)
google-genai>=1.0                  # optional extra: [gemini]; replaces deprecated google-generativeai
```
Phase 2 (`[service]` extra): `fastapi`, `uvicorn[standard]`, `celery[redis]`, `redis`, `sqlalchemy[asyncio]>=2.0`, `alembic`, `psycopg[binary]` (one URL drives both the async API engine and the sync worker engine). Tests (`[dev]`): `pytest-asyncio`, `aiosqlite`, `fakeredis`.

Model config: `OPENROUTER_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL`, `LLM_FALLBACK_MODEL` (each also accepts the `VIBEGUARD_` prefix).

> **Semgrep & Gitleaks** run inside the worker Docker image (Semgrep has no native Windows build). The engine's built-in regex rules (ported from the Gitleaks rule set) and Tree-sitter sink queries work everywhere; external binaries are used opportunistically when present on `PATH`.

### Frontend (`package.json`)
```json
{
  "dependencies": {
    "next": "^14.2.0",
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "lucide-react": "^0.363.0",
    "clsx": "^2.1.0",
    "tailwind-merge": "^2.2.2",
    "react-diff-viewer-continued": "^3.3.1"
  }
}
```