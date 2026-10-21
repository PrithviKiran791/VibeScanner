# Product Requirements Document (PRD)

## 1. Executive Summary & Vision
**Product Name:** VibeGuard (AI-Assisted DevSecOps & Hardening Engine)  
**Target Users:** Full-stack developers, engineering teams, and creators building applications with generative AI tools (Cursor, v0, Lovable, Claude Code).  
**Core Value Proposition:** Fast-prototyped "vibe-coded" applications frequently ship with severe business logic flaws, unprotected API endpoints, exposed client-side environment secrets, and hallucinated dependencies. VibeGuard combines deterministic static analysis (AST/Semgrep) with semantic LLM inspection to detect high-impact vulnerabilities, compute a normalized Hardening Index (0–100), and generate zero-touch unified Git patches.

---

## 2. Problem Statement
The emergence of AI code generation tools has drastically reduced development time but introduced distinct security blind spots:
1. **Broken Object-Level Authorization (BOLA/IDOR):** AI route handlers frequently query records directly by request parameters (e.g., `db.user.findUnique({ where: { id: req.params.id } })`) without validating session identity.
2. **Secret Leakage:** Client-side environment variables and private API keys (Stripe, Supabase service roles) are frequently mixed into public bundles.
3. **Slopsquatting & Hallucinated Packages:** AI models generate import statements for nonexistent packages, leaving repositories vulnerable to package squatting attacks.
4. **Tool Fatigue:** Existing enterprise SAST tools (SonarQube, Snyk) generate overwhelming walls of false positives, lack business-logic awareness, and provide generic advice rather than ready-to-merge unified Git diffs.

---

## 3. Product Goals & Success Metrics
| Goal | Metric | Target |
| :--- | :--- | :--- |
| **Scan Latency** | End-to-end scan time for typical repo ($\le 100$ source files) | $\le 15$ seconds |
| **Actionable Remediations** | Findings with valid, syntactically correct Git patches | $\ge 90\%$ |
| **False-Positive Reduction** | Deterministic pre-filtering before LLM evaluation | $\ge 40\%$ token cost savings |
| **Scoring Consistency** | Standardized Hardening Index formula | Deterministic $0 - 100$ score |

---

## 4. User Personas
*   **The Vibe-Coder / Student:** Needs an immediate, clear checklist and automatic pull request to fix insecure code before demoing or deploying to production.
*   **The Tech Placement Interviewer / Senior Engineer:** Evaluates the project's architecture, observing how it handles distributed tasks, token rate-limiting, AST analysis, and security taxonomy (OWASP Top 10, CWE).

---

## 5. Functional Requirements

### 5.1 Repository Ingestion
*   **FR-1.1:** Support public and authenticated private GitHub repository cloning via shallow clone (`--depth 1`).
*   **FR-1.2:** Support direct `.zip` file upload or raw code file ingestion through API.
*   **FR-1.3:** Enforce safe repo size boundaries (maximum 50MB unpack size, excluding `node_modules`, `.git`, and build assets).

### 5.2 Hybrid Scan Pipeline
*   **FR-2.1 (Deterministic Pass):** Fast scan for high-confidence signatures:
    *   Hardcoded secrets (regex & entropy analysis via Gitleaks rules).
    *   Dependency verification against official registries (npm, PyPI) to detect hallucinated dependencies.
    *   Syntactic sinks (e.g., `eval()`, `dangerouslySetInnerHTML`, raw SQL string interpolation).
*   **FR-2.2 (AST & Scope Pruning):** Tree-sitter AST extraction to parse route handlers, middleware, and database access points, filtering out non-security critical boilerplate before LLM ingestion.
*   **FR-2.3 (Contextual Semantic Pass):** Targeted LLM prompts targeting logic bugs:
    *   Missing authentication/authorization checks on mutation routes.
    *   Prompt injection vulnerabilities in downstream AI calls.
    *   Client/Server boundary leakage (e.g., Next.js `"use server"`/`"use client"` security misconfigurations).

### 5.3 Hardening Index & Scoring Engine
*   **FR-3.1:** Replace inverted scoring with a standard **Hardening Index** from $0$ (Completely Compromised) to $100$ (Fully Hardened).
*   **FR-3.2:** Deduct points deterministically based on severity:
    *   Critical Vulnerability (e.g., IDOR, RCE, Leaked Secret): $-25$ pts each.
    *   High Severity (e.g., Missing CSRF, Hallucinated Import): $-12$ pts each.
    *   Medium Severity (e.g., Missing Rate Limit, Loose CORS): $-5$ pts each.
    *   Low / Code Smell (e.g., Permissive TS types, unhandled errors): $-1$ pt each.
    *   *Formula Floor:* $\text{Score} = \max(0, 100 - \sum \text{Penalties})$.

### 5.4 Remediation & Export
*   **FR-4.1:** Output a clean, unified Git diff (`.diff` patch) for each confirmed vulnerability.
*   **FR-4.2:** Provide a single-click action to create a GitHub Pull Request with the remediation.
*   **FR-4.3:** Export audit report as a downloadable JSON artifact or Markdown summary.

---

## 6. Non-Functional Requirements
*   **Security & Isolation:** Uploaded codebases must be processed in ephemeral sandboxes and scrubbed immediately after scan completion. Raw code must not be retained in database storage; the only code persisted is the finding's ±3-line snippet and its unified diff (secret values are redacted before storage).
*   **Reliability:** Scan requests must be handled via an asynchronous message queue with worker timeouts (max 60 seconds per job).
*   **Cost Control:** Maximum token budget per repository scan strictly bounded by chunking and AST-filtered context extraction.