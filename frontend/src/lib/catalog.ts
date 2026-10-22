// Every detector VibeGuard runs, for the Rules and Docs pages.
// Mirrors backend/vibeguard/engine/static/* and the LLM prompt. backend/tests/test_catalog.py
// fails if a backend rule id is missing here, so this list can't silently drift.

import type { Severity } from "./types";

export type Pass = "secrets" | "sinks" | "supply-chain" | "semantic";

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  pass: Pass;
  /** What it looks for, in one or two plain sentences. */
  detects: string;
  /** What the generated fix does, or null when a human has to fix it. */
  fix: string | null;
}

export const PASSES: { id: Pass; title: string; engine: string; summary: string }[] = [
  {
    id: "secrets",
    title: "Secrets & Credential Leaks",
    engine: "Regex rules (Gitleaks-derived) + entropy + JWT decoding",
    summary:
      "Runs on every text file, including committed .env files. Secret values are masked in every snippet and diff; fixes are stored as span coordinates so the raw key is never saved.",
  },
  {
    id: "sinks",
    title: "Code Injection Sinks",
    engine: "Tree-sitter AST (JavaScript, TypeScript, TSX)",
    summary:
      "Parses the code instead of grepping it, so a literal string in eval() or a RegExp.exec() call is not a false alarm. Every generated patch is re-parsed and dropped if it doesn't compile.",
  },
  {
    id: "supply-chain",
    title: "Supply Chain",
    engine: "Live npm / PyPI registry lookups, cached 24h in Redis",
    summary:
      "Checks every dependency in package.json and requirements*.txt actually exists. A registry outage is never reported as a finding.",
  },
  {
    id: "semantic",
    title: "Semantic Review (LLM)",
    engine: "Gemma 4 31B via OpenRouter, JSON mode, per-finding validation",
    summary:
      "Only route handlers, server actions, Express routes and middleware are sent to the model. Findings whose code doesn't match the real file are discarded before they reach you.",
  },
];

export const RULES: Rule[] = [
  // --- secrets ---------------------------------------------------------------------------
  {
    id: "aws-access-key-id",
    title: "Exposed AWS Access Key",
    severity: "CRITICAL",
    cwe: "CWE-798",
    pass: "secrets",
    detects: "AWS access key IDs (AKIA / ASIA / ABIA / ACCA prefixes).",
    fix: "Replaces the literal with process.env.AWS_ACCESS_KEY_ID.",
  },
  {
    id: "stripe-secret-key",
    title: "Exposed Stripe Secret Key",
    severity: "CRITICAL",
    cwe: "CWE-798",
    pass: "secrets",
    detects: "Live Stripe secret and restricted keys (sk_live_ / rk_live_).",
    fix: "Replaces the literal with process.env.STRIPE_SECRET_KEY.",
  },
  {
    id: "github-token",
    title: "Exposed GitHub Token",
    severity: "CRITICAL",
    cwe: "CWE-798",
    pass: "secrets",
    detects: "Classic (ghp_, gho_, ghu_, ghs_, ghr_) and fine-grained (github_pat_) tokens.",
    fix: "Replaces the literal with process.env.GITHUB_TOKEN.",
  },
  {
    id: "anthropic-api-key",
    title: "Exposed Anthropic API Key",
    severity: "CRITICAL",
    cwe: "CWE-798",
    pass: "secrets",
    detects: "Anthropic API and admin keys (sk-ant-…).",
    fix: "Replaces the literal with process.env.ANTHROPIC_API_KEY.",
  },
  {
    id: "openrouter-api-key",
    title: "Exposed OpenRouter API Key",
    severity: "CRITICAL",
    cwe: "CWE-798",
    pass: "secrets",
    detects: "OpenRouter keys (sk-or-v1- followed by 64 hex characters).",
    fix: "Replaces the literal with process.env.OPENROUTER_API_KEY.",
  },
  {
    id: "openai-api-key",
    title: "Exposed OpenAI API Key",
    severity: "CRITICAL",
    cwe: "CWE-798",
    pass: "secrets",
    detects: "OpenAI project, service-account and legacy keys.",
    fix: "Replaces the literal with process.env.OPENAI_API_KEY.",
  },
  {
    id: "google-api-key",
    title: "Exposed Google API Key",
    severity: "HIGH",
    cwe: "CWE-798",
    pass: "secrets",
    detects: "Google Cloud / Firebase API keys (AIza…).",
    fix: "Replaces the literal with process.env.GOOGLE_API_KEY.",
  },
  {
    id: "slack-token",
    title: "Exposed Slack Token",
    severity: "HIGH",
    cwe: "CWE-798",
    pass: "secrets",
    detects: "Slack bot, user, app and refresh tokens (xox…).",
    fix: "Replaces the literal with process.env.SLACK_TOKEN.",
  },
  {
    id: "private-key",
    title: "Committed Private Key",
    severity: "CRITICAL",
    cwe: "CWE-798",
    pass: "secrets",
    detects: "PEM private key blocks: RSA, EC, DSA, OpenSSH and PGP.",
    fix: null,
  },
  {
    id: "generic-secret-assignment",
    title: "Hardcoded Secret",
    severity: "HIGH",
    cwe: "CWE-798",
    pass: "secrets",
    detects:
      "A variable named like secret, password, api_key or token assigned a 16+ character literal with Shannon entropy ≥ 3.5. Placeholders such as your_api_key or changeme are ignored.",
    fix: "Replaces the literal with process.env.APP_SECRET.",
  },
  {
    id: "supabase-service-role",
    title: "Exposed Supabase Service Role Key",
    severity: "CRITICAL",
    cwe: "CWE-798",
    pass: "secrets",
    detects:
      "JWTs whose decoded payload has role = service_role. These bypass Row Level Security. The public anon key is ignored.",
    fix: "Replaces the literal with process.env.SUPABASE_SERVICE_ROLE_KEY.",
  },
  {
    id: "public-env-secret",
    title: "Server Secret Exposed To Client Bundle",
    severity: "CRITICAL",
    cwe: "CWE-200",
    pass: "secrets",
    detects:
      "A NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ or PUBLIC_ variable whose name says SECRET, SERVICE_ROLE, PRIVATE, PASSWORD or DATABASE_URL. Bundlers inline these into browser JavaScript.",
    fix: "Drops the public prefix so the value stays on the server.",
  },
  // --- sinks -----------------------------------------------------------------------------
  {
    id: "sql-string-interpolation",
    title: "SQL Injection via Template String",
    severity: "CRITICAL",
    cwe: "CWE-89",
    pass: "sinks",
    detects:
      "A template string shaped like SQL with ${…} interpolation passed to query, execute, raw, $queryRawUnsafe and similar calls.",
    fix: "Rewrites to bound parameters: $1 for node-postgres, ? for MySQL/SQLite, a tagged $queryRaw for Prisma. Quoted '%${q}%' becomes one parameter.",
  },
  {
    id: "react-dangerously-set-inner-html",
    title: "Unsanitized dangerouslySetInnerHTML",
    severity: "HIGH",
    cwe: "CWE-79",
    pass: "sinks",
    detects: "Dynamic values passed as __html, unless already wrapped in a sanitizer.",
    fix: "Wraps the value in DOMPurify.sanitize() and adds the isomorphic-dompurify import.",
  },
  {
    id: "dom-inner-html",
    title: "Dynamic innerHTML Assignment",
    severity: "HIGH",
    cwe: "CWE-79",
    pass: "sinks",
    detects: "Assigning a non-literal value to element.innerHTML or outerHTML.",
    fix: "Switches innerHTML to textContent.",
  },
  {
    id: "dynamic-code-eval",
    title: "Dynamic Code Execution",
    severity: "HIGH",
    cwe: "CWE-95",
    pass: "sinks",
    detects: "eval() or new Function() on anything other than a constant string.",
    fix: null,
  },
  {
    id: "shell-command-injection",
    title: "OS Command Injection",
    severity: "CRITICAL",
    cwe: "CWE-78",
    pass: "sinks",
    detects:
      "child_process exec / execSync / spawnSync called with an interpolated or concatenated command string.",
    fix: null,
  },
  // --- supply chain ----------------------------------------------------------------------
  {
    id: "hallucinated-dependency",
    title: "Hallucinated Package",
    severity: "HIGH",
    cwe: "CWE-1357",
    pass: "supply-chain",
    detects:
      "A declared dependency that returns 404 from npm or PyPI. AI assistants invent these, and attackers register the names with malware (slopsquatting).",
    fix: "Removes the line and keeps package.json valid (drops the trailing comma if needed).",
  },
];

export const SEMANTIC_CATEGORIES: { name: string; example: string }[] = [
  {
    name: "Broken Access Control",
    example: "IDOR: /api/user/[id] returns any user's record without checking the session.",
  },
  {
    name: "Broken Authentication",
    example: "A route or server action that changes data with no sign-in check at all.",
  },
  { name: "Injection", example: "Untrusted input reaching a query or command the static pass can't see." },
  {
    name: "Prompt Injection",
    example: "User input concatenated into an LLM prompt whose output is trusted or given tools.",
  },
  {
    name: "Client/Server Boundary Leak",
    example: "Returning password hashes, tokens or whole database rows to the browser.",
  },
  {
    name: "Mass Assignment",
    example: "Spreading the request body into an update, so a caller can set role or isAdmin.",
  },
  {
    name: "Business Logic",
    example: "Trusting a client-supplied price, quantity or user id; state changes over GET.",
  },
  {
    name: "Security Misconfiguration",
    example: "Permissive CORS or disabled checks on a sensitive path.",
  },
];

export const PENALTIES: { severity: Severity; points: number; examples: string }[] = [
  { severity: "CRITICAL", points: 25, examples: "IDOR, RCE, leaked live secret, SQL injection" },
  { severity: "HIGH", points: 12, examples: "XSS sink, hallucinated package, unauthenticated mutation" },
  { severity: "MEDIUM", points: 5, examples: "Limited data exposure, missing rate limit on auth" },
  { severity: "LOW", points: 1, examples: "Minor hardening" },
];

export function rulesFor(pass: Pass): Rule[] {
  return RULES.filter((r) => r.pass === pass);
}
