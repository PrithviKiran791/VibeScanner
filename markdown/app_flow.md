# Application Architecture & Execution Flow

## 1. High-Level Scan Pipeline

```
  [User Action]
        │
        ├──► 1. Trigger Scan (GitHub URL / Local Directory / ZIP)
        │
  [FastAPI Router]
        │
        ├──► 2. Create Scan Record (Status: QUEUED)
        ├──► 3. Push job to Redis queue
        │
  [Celery Worker Sandbox]
        │
        ├──► 4. Repository Cloned (Depth = 1, Submodules Ignored)
        ├──► 5. Filter ignore patterns (.git, node_modules, dist, *.lock)
        │
        ├──► 6. Pass 1: Deterministic Static Scan
        │       ├─ Secret detection (Gitleaks heuristics)
        │       ├─ Supply chain check (Package registry resolution)
        │       └─ Sink detection (AST queries for raw SQL, eval, dangerous HTML)
        │
        ├──► 7. Pass 2: Semantic Relevance Pruning
        │       └─ Tree-sitter extracts route handlers, server actions, and middleware
        │
        ├──► 8. Pass 3: LLM Contextual Security Analysis
        │       ├─ Batch filtered endpoints into structured prompt
        │       └─ Receive structured JSON with verified CWEs, explanations & diffs
        │
        ├──► 9. Aggregation & Scoring
        │       ├─ Merge & deduplicate findings
        │       └─ Compute Hardening Index (0-100)
        │
  [Database & Notifications]
        │
        ├──► 10. Persist Findings & Metrics to PostgreSQL
        ├──► 11. Emit WebSocket event: SCAN_COMPLETED
        │
  [User Review & Remediation]
        │
        ├──► 12. Dashboard renders findings & unified Git diff
        └──► 13. User clicks "Apply Patch" -> Dispatches automated Git PR
```

---

## 2. Step-by-Step Execution Lifecycle

### Phase 1: Ingestion & Sandbox Isolation
1. The user initiates a scan via the dashboard or CLI by passing a GitHub repository URL or directory archive.
2. The API creates a unique `scan_id`, validates the URL, and schedules a Celery worker task.
3. The worker clones the repository into a temporary ramdisk directory (`/tmp/scans/{scan_id}`).
4. Files matching exclusion criteria (`node_modules`, `.next`, `dist`, lockfiles, image binaries) are stripped from the file index.

### Phase 2: Deterministic Fast-Scan
Before calling external AI APIs, the worker executes three deterministic checks:
1. **Secret Scanning:** Scans for high-entropy strings and common provider regex patterns (Stripe keys, AWS keys, JWT secrets, Supabase service roles).
2. **Hallucinated Package Auditing:** Parses `package.json` dependencies and verifies their existence against `https://registry.npmjs.org/<package>`. Non-200 responses are tagged as **Hallucinated Dependencies** (Potential Supply-Chain Hijack).
3. **AST Sink Extraction:** Tree-sitter parses JavaScript/TypeScript files, producing an AST of functions containing database operations, server-side route definitions, and external calls.

### Phase 3: Semantic LLM Analysis
1. Endpoints flagged as handling user input or authentication are packaged into a security analysis prompt.
2. The prompt requires strict JSON schema output (using Pydantic validation):
   * Vulnerability category (OWASP Top 10 / CWE).
   * Exact line range and vulnerable code snippet.
   * Root cause explanation focused on vibe-coding pitfalls (e.g., trust of unvalidated client state).
   * Remediated code snippet producing a valid unified patch.

### Phase 4: Scoring & Deduplication
1. Overlapping findings between static analysis and LLM analysis are merged.
2. The **Hardening Index** is calculated by subtracting severity-based penalties from a baseline of 100.
3. Findings, score, and duration are committed to PostgreSQL.
4. The temporary directory is wiped from the worker environment.

### Phase 5: Client Presentation & One-Click Patching
1. The minimal dashboard updates via WebSocket or polling, presenting the score, findings list, and remediation workspace.
2. The user inspects the unified Git diff.
3. If GitHub permissions are configured, clicking **Apply Patch** invokes the GitHub API to fork/branch the repository, commit the patch, and open a Pull Request.