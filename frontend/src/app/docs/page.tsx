import type { Metadata } from "next";
import Link from "next/link";

import { C, CodeBlock, OnThisPage, Page, PageHeader, Panel, Section } from "@/components/page/Page";
import { cn } from "@/lib/format";

export const metadata: Metadata = { title: "Docs · VibeGuard" };

const TOC = [
  { id: "overview", label: "Overview" },
  { id: "quick-start", label: "Quick start" },
  { id: "pipeline", label: "How a scan works" },
  { id: "hardening-index", label: "Hardening Index" },
  { id: "triage", label: "Triage" },
  { id: "pull-requests", label: "Fix pull requests" },
  { id: "api", label: "API" },
  { id: "cli", label: "CLI" },
  { id: "authentication", label: "Authentication" },
  { id: "configuration", label: "Configuration" },
  { id: "webhooks", label: "Webhooks" },
  { id: "security", label: "Security model" },
  { id: "demo-app", label: "Demo app" },
];

const PIPELINE = [
  {
    step: "Ingest",
    detail:
      "Shallow clone (depth 1, no submodules, no symlinks) into a throwaway directory, with a 30s timeout and a 200MB cap. node_modules, build output, lockfiles and binaries are skipped, and the remaining source must fit in 50MB.",
  },
  {
    step: "Static pass",
    detail:
      "Secret rules, npm/PyPI existence checks, and Tree-sitter sink detection over JS/TS. Costs no LLM tokens.",
  },
  {
    step: "Pruning",
    detail:
      "Tree-sitter extracts route handlers, server actions, Express routes and middleware, then ranks them by risk signals so the riskiest code is reviewed first.",
  },
  {
    step: "Semantic pass",
    detail:
      "The ranked units go to the LLM in chunks, within the scan's deadline. Every finding is checked against the real file before it's accepted.",
  },
  {
    step: "Merge & score",
    detail:
      "Overlapping static and LLM findings are merged, duplicates collapsed, and the Hardening Index computed. The clone is deleted however the scan ends.",
  },
];

const ENDPOINTS: { method: string; path: string; what: string }[] = [
  { method: "POST", path: "/api/v1/scans", what: "Start a scan: {repo_url} or {local_path}, optional options {llm, registry}. 202 queued, 409 if that repo is already being scanned." },
  { method: "GET", path: "/api/v1/scans", what: "Scan history, newest first (?limit=1–100)." },
  { method: "GET", path: "/api/v1/scans/{id}", what: "Status, live progress, Hardening Index and severity counts." },
  { method: "GET", path: "/api/v1/scans/{id}/findings", what: "Findings by severity, with diffs, remediation coordinates and any PR." },
  { method: "PATCH", path: "/api/v1/findings/{id}", what: "Set status (OPEN, PATCH_APPLIED, DISMISSED_FALSE_POSITIVE, RESOLVED). Returns the recalculated score." },
  { method: "POST", path: "/api/v1/findings/{id}/pull-request", what: "Apply the fix on a branch and open a PR. 201 created, 200 if one already exists, 409 if the file changed." },
  { method: "GET", path: "/api/v1/me", what: "The signed-in user." },
  { method: "POST", path: "/api/v1/webhooks/github", what: "GitHub push webhook (HMAC-signed). A push to the default branch queues a scan." },
  { method: "GET", path: "/healthz · /readyz", what: "Liveness, and readiness (PostgreSQL + Redis reachable)." },
];

const SETTINGS: { name: string; purpose: string }[] = [
  { name: "OPENROUTER_API_KEY", purpose: "Enables the semantic pass. Without it, scans are static-only." },
  { name: "LLM_MODEL / LLM_FALLBACK_MODEL", purpose: "Primary model (google/gemma-4-31b-it:free) and the one tried on 429/5xx." },
  { name: "LLM_FALLBACK_MODELS", purpose: "JSON list tried next, in order (default: free NVIDIA Nemotron and dots models), so a saturated Gemma pool doesn't skip semantic review." },
  { name: "SCAN_DEADLINE_S", purpose: "Analysis time budget in seconds (default 150; free models need about a minute per chunk)." },
  { name: "VIBEGUARD_GITHUB_TOKEN", purpose: "Clones private repos and opens fix PRs. Needs repo scope." },
  { name: "VIBEGUARD_GITHUB_WEBHOOK_SECRET", purpose: "Turns on the webhook endpoint and verifies its signatures." },
  { name: "VIBEGUARD_FIREBASE_PROJECT_ID", purpose: "Firebase project whose ID tokens the API accepts." },
  { name: "VIBEGUARD_AUTH_ALLOWED_EMAILS / _DOMAINS", purpose: "Who may sign in. Empty means nobody (fails closed)." },
  { name: "VIBEGUARD_RATE_LIMIT_*_PER_MINUTE", purpose: "Per-client limits on scans (10), PRs (5), triage (60) and webhooks (120)." },
  { name: "VIBEGUARD_TRUSTED_PROXIES", purpose: "Proxies whose X-Forwarded-For is trusted. In Docker, only the nginx edge." },
  { name: "VIBEGUARD_DATABASE_URL / VIBEGUARD_REDIS_URL", purpose: "PostgreSQL and Redis connections." },
  { name: "VIBEGUARD_ALLOW_LOCAL_PATHS + _LOCAL_SCAN_ROOT", purpose: "Allow scanning server-side folders, only inside that root. Off by default." },
];

const CLI_OPTIONS: [string, string][] = [
  ["--no-llm", "Static checks only."],
  ["--no-registry", "Skip the npm / PyPI existence checks."],
  ["--json FILE", "Write the full report as JSON."],
  ["--markdown FILE", "Write a Markdown report."],
  ["--fail-under N", "Exit 1 if the Hardening Index is below N (CI gate)."],
  ["--no-diff", "Don't print patches to the terminal."],
];

const STATUSES = [
  { name: "OPEN", effect: "Counts toward the score.", tone: "risk" },
  { name: "PATCH_APPLIED", effect: "A fix PR was opened. Stops counting.", tone: "secure" },
  { name: "DISMISSED_FALSE_POSITIVE", effect: "Not a real issue. Stops counting.", tone: "neutral" },
  { name: "RESOLVED", effect: "Fixed some other way. Stops counting.", tone: "secure" },
] as const;

export default function DocsPage() {
  return (
    <Page>
      <PageHeader eyebrow="Documentation" title="Docs">
        How VibeGuard finds problems in AI-generated web apps, how to act on what it finds, and how
        to run and configure it.
      </PageHeader>
      <OnThisPage items={TOC} />

      <Section
        id="overview"
        title="Overview"
        lead={
          <p>
            VibeGuard scans Next.js, React and Express code for the mistakes AI coding assistants
            make most: hardcoded keys, server secrets leaking into the browser, invented npm
            packages, SQL and shell injection, unsanitized HTML, and routes that never check who is
            calling. Each finding gets a plain-English explanation and, where possible, a patch
            you can open as a pull request.
          </p>
        }
      >
        <div className="grid gap-3 sm:grid-cols-3">
          <Fact title="Deterministic first" body="Static rules catch the high-confidence issues for free. The LLM only reviews server entry points." />
          <Fact title="Nothing invented" body="LLM findings must quote the real vulnerable lines, and patches that don't parse are dropped." />
          <Fact title="Secrets stay secret" body="Keys are masked in every snippet and diff. Fixes are stored as coordinates, never as the key." />
        </div>
      </Section>

      <Section id="quick-start" title="Quick start">
        <ol className="space-y-3">
          <Step n={1}>
            Go to{" "}
            <Link href="/scan" className="text-secure underline-offset-4 hover:underline">
              Audit → New Code Scan
            </Link>{" "}
            and enter <C>owner/repo</C> or a full GitHub URL.
          </Step>
          <Step n={2}>Watch the progress: clone, static pass, semantic pass. Most repos finish in under 15 seconds.</Step>
          <Step n={3}>Triage in the workspace. Findings are listed on the left, ordered by severity; the root cause and fix are on the right.</Step>
          <Step n={4}>Click Apply Fix (PR) to open a pull request, Copy Diff to apply it yourself, or dismiss false positives.</Step>
        </ol>
      </Section>

      <Section
        id="pipeline"
        title="How a scan works"
        lead={<p>Each scan runs on a Celery worker with a hard 60-second budget. Progress is pushed to Redis, which the dashboard polls every second.</p>}
      >
        <ol className="grid gap-3">
          {PIPELINE.map((p, i) => (
            <li key={p.step}>
              <Panel className="flex gap-4 p-4">
                <span className="grid h-8 w-8 shrink-0 place-items-center border-2 border-bone font-heading text-[13px] font-extrabold">
                  {i + 1}
                </span>
                <span>
                  <span className="stamp block text-[14px]">{p.step}</span>
                  <span className="mt-1 block text-[14px] leading-relaxed text-ash">{p.detail}</span>
                </span>
              </Panel>
            </li>
          ))}
        </ol>
        <p className="mt-4 text-[13px] text-ash">
          The full list of checks is on the{" "}
          <Link href="/rules" className="text-secure underline-offset-4 hover:underline">
            Rules
          </Link>{" "}
          page.
        </p>
      </Section>

      <Section
        id="hardening-index"
        title="Hardening Index"
        lead={
          <p>
            A 0 to 100 score computed by code, never by the LLM: 100 minus 25 per critical, 12 per
            high, 5 per medium and 1 per low open finding, with a floor of 0. Scores of 80 and up
            show green, 59 and below red. Triage changes the score immediately.
          </p>
        }
      >
        <Panel className="px-5 py-4">
          <p className="code text-[15px]">score = max(0, 100 − 25·critical − 12·high − 5·medium − 1·low)</p>
        </Panel>
        <p className="mt-3 text-[13px] text-ash">
          Penalties and examples:{" "}
          <Link href="/rules#scoring" className="text-secure underline-offset-4 hover:underline">
            Rules → Hardening Index
          </Link>
          .
        </p>
      </Section>

      <Section id="triage" title="Triage" lead={<p>Only open findings cost points, so the score always reflects what&apos;s left to fix.</p>}>
        <div className="grid gap-3 sm:grid-cols-2">
          {STATUSES.map((s) => (
            <Panel
              key={s.name}
              className={cn(
                "p-4",
                s.tone === "risk" && "border-risk/60",
                s.tone === "secure" && "border-secure/60",
              )}
            >
              <p className="code text-bone">{s.name}</p>
              <p className="mt-1 text-[14px] text-ash">{s.effect}</p>
            </Panel>
          ))}
        </div>
      </Section>

      <Section
        id="pull-requests"
        title="Fix pull requests"
        lead={
          <p>
            Apply Fix (PR) never pushes a stale patch. It reads the file&apos;s current copy on your
            default branch, rebuilds the fix on it, and refuses (409) if the code has changed
            since the scan.
          </p>
        }
      >
        <ul className="space-y-3 text-[14px] leading-relaxed text-bone/85">
          <Bullet>
            <b className="text-bone">Code fixes</b> are re-applied as the stored diff. Context lines
            must match exactly, though the hunk may have moved if lines were added above it.
          </Bullet>
          <Bullet>
            <b className="text-bone">Secret fixes</b> use stored coordinates (line, column span,
            replacement). The span is checked to still hold a matching secret before it&apos;s
            replaced with <C>process.env.NAME</C>. The PR description reminds you to rotate the
            key, which is still in git history.
          </Bullet>
          <Bullet>
            If the token can push, the fix goes on a <C>vibeguard/…</C> branch. Otherwise the
            repo is forked and the PR opened from the fork.
          </Bullet>
          <Bullet>One PR per finding. Clicking again returns the existing PR instead of opening another.</Bullet>
          <Bullet>Requires a GitHub scan and <C>VIBEGUARD_GITHUB_TOKEN</C> on the server.</Bullet>
        </ul>
      </Section>

      <Section
        id="api"
        title="API"
        lead={
          <p>
            JSON over HTTPS. Every <C>/api/v1</C> route except the webhook needs a signed-in user:
            send the Firebase ID token as <C>Authorization: Bearer …</C>. Interactive reference:{" "}
            <a href="http://localhost:8000/docs" target="_blank" rel="noreferrer" className="text-secure underline-offset-4 hover:underline">
              /docs on the API
            </a>
            .
          </p>
        }
      >
        <ul className="divide-y-2 divide-hairline border-2 border-hairline bg-carbon">
          {ENDPOINTS.map((e) => (
            <li key={e.method + e.path} className="grid gap-1 p-4 sm:grid-cols-[72px_minmax(0,300px)_1fr] sm:gap-4">
              <span className={cn("stamp text-[12px]", e.method === "GET" ? "text-ash" : "text-secure")}>{e.method}</span>
              <span className="code break-all text-bone">{e.path}</span>
              <span className="text-[14px] leading-relaxed text-ash">{e.what}</span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-[13px] text-ash">
          Writes are rate-limited per client and return <C>429</C> with <C>Retry-After</C> when
          exceeded. Reads aren&apos;t limited.
        </p>
      </Section>

      <Section id="cli" title="CLI" lead={<p>The same engine, without the server. Useful in CI.</p>}>
        <div className="grid gap-3">
          <CodeBlock label="Scan a folder, a GitHub repo or a .zip">{`vibeguard scan ./my-app
vibeguard scan https://github.com/owner/repo
vibeguard scan upload.zip`}</CodeBlock>
          <ul className="divide-y-2 divide-hairline border-2 border-hairline bg-carbon">
            {CLI_OPTIONS.map(([flag, what]) => (
              <li key={flag} className="grid gap-1 px-4 py-3 sm:grid-cols-[180px_1fr] sm:gap-4">
                <span className="code text-bone">{flag}</span>
                <span className="text-[14px] text-ash">{what}</span>
              </li>
            ))}
          </ul>
        </div>
      </Section>

      <Section
        id="authentication"
        title="Authentication"
        lead={
          <p>
            Sign-in uses Firebase Authentication (Google, or email and password). The dashboard sends
            each request&apos;s Firebase ID token to the API, which checks it against Google&apos;s
            signing keys and then against an allowlist. Rules and Docs are public; scans, findings
            and the audit view require sign-in.
          </p>
        }
      >
        <ol className="space-y-3">
          <Step n={1}>
            In the <a href="https://console.firebase.google.com" target="_blank" rel="noreferrer" className="text-secure underline-offset-4 hover:underline">Firebase console</a>, create a project, open Authentication → Sign-in method, and enable <b className="text-bone">GitHub</b>, <b className="text-bone">Google</b> and <b className="text-bone">Email/Password</b>. For GitHub, create an OAuth app at GitHub → Settings → Developer settings, paste its client ID and secret into Firebase, and set the app&apos;s callback URL to the one Firebase shows.
          </Step>
          <Step n={2}>
            Project settings → Your apps → add a <b className="text-bone">Web app</b>, then copy its config into <C>frontend/.env.local</C>:
          </Step>
        </ol>
        <div className="mt-3 grid gap-3">
          <CodeBlock label="frontend/.env.local (public values, inlined into the browser bundle)">{`NEXT_PUBLIC_FIREBASE_API_KEY=AIza...
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=your-project
NEXT_PUBLIC_FIREBASE_APP_ID=1:1234:web:abcd`}</CodeBlock>
        </div>
        <ol className="mt-4 space-y-3" start={3}>
          <Step n={3}>
            Tell the API which project to trust and who may sign in, in <C>backend/.env</C>:
          </Step>
        </ol>
        <div className="mt-3 grid gap-3">
          <CodeBlock label="backend/.env">{`VIBEGUARD_FIREBASE_PROJECT_ID=your-project
VIBEGUARD_AUTH_ALLOWED_EMAILS=["you@gmail.com"]
VIBEGUARD_AUTH_ALLOWED_DOMAINS=[]
# GitHub sign-ins: numeric ids from https://api.github.com/users/<login>
VIBEGUARD_AUTH_ALLOWED_GITHUB_IDS=["1234567"]`}</CodeBlock>
        </div>
        <ol className="mt-4 space-y-3" start={4}>
          <Step n={4}>
            Restart the API and the dashboard. <C>localhost</C> is an authorized domain by default; add your production domain under Authentication → Settings.
          </Step>
        </ol>
        <ul className="mt-6 space-y-3 text-[14px] leading-relaxed text-bone/85">
          <Bullet>It fails closed: with no project ID the API answers 503, and with an empty allowlist nobody gets in.</Bullet>
          <Bullet>Email/password accounts must verify their address before the API accepts them, so nobody can sign up with an email they don&apos;t own.</Bullet>
          <Bullet>Firebase never marks GitHub emails as verified, so GitHub users are allowlisted by their GitHub account id instead of their email.</Bullet>
          <Bullet>Every scan belongs to the person who started it: history, findings, triage, PRs and delete only work on your own scans, and anyone else&apos;s scan answers 404. Webhook scans go to whoever last scanned that repo by hand.</Bullet>
          <Bullet>PRs still use the server&apos;s GitHub token, so allowlist only people you&apos;d trust with it.</Bullet>
          <Bullet>For local hacking without Firebase, leave both sides unset: the Docker-free devserver runs with auth disabled.</Bullet>
        </ul>
      </Section>

      <Section
        id="configuration"
        title="Configuration"
        lead={
          <p>
            Environment variables, read from <C>backend/.env</C> (gitignored). Most also accept the{" "}
            <C>VIBEGUARD_</C> prefix. Template: <C>backend/.env.example</C>.
          </p>
        }
      >
        <ul className="divide-y-2 divide-hairline border-2 border-hairline bg-carbon">
          {SETTINGS.map((s) => (
            <li key={s.name} className="grid gap-1 p-4 sm:grid-cols-[minmax(0,320px)_1fr] sm:gap-4">
              <span className="code break-all text-bone">{s.name}</span>
              <span className="text-[14px] leading-relaxed text-ash">{s.purpose}</span>
            </li>
          ))}
        </ul>
      </Section>

      <Section
        id="webhooks"
        title="Webhooks"
        lead={<p>Scan automatically on every push to your default branch. Works as a repository webhook or a GitHub App.</p>}
      >
        <ol className="space-y-3">
          <Step n={1}>Set <C>VIBEGUARD_GITHUB_WEBHOOK_SECRET</C> on the server to a long random string.</Step>
          <Step n={2}>
            In GitHub: Settings → Webhooks → Add webhook. Payload URL{" "}
            <C>https://your-host/api/v1/webhooks/github</C>, content type <C>application/json</C>,
            the same secret, and the push event only.
          </Step>
          <Step n={3}>GitHub&apos;s ping should get <C>pong</C>. From then on, each push to the default branch queues a scan.</Step>
        </ol>
        <p className="mt-4 text-[13px] leading-relaxed text-ash">
          The signature (HMAC-SHA256) is checked before the payload is read. Redeliveries are
          ignored for 24 hours, and pushes to other branches or branch deletions are skipped.
        </p>
      </Section>

      <Section id="security" title="Security model">
        <div className="grid gap-3 sm:grid-cols-2">
          <Fact title="Ephemeral sandboxes" body="Code is cloned into a throwaway folder (a RAM disk in Docker) and deleted when the scan ends, whether it succeeds or fails. Only the ±3-line snippet and the diff are stored." />
          <Fact title="Signed-in, allowlisted users" body="The API accepts Firebase ID tokens, verifying signature, audience, issuer and expiry. Only allowlisted emails or domains get in. An empty allowlist lets nobody in." />
          <Fact title="Rate limits that can't be spoofed" body="Limits are per client, counted in Redis. Client IPs come from X-Forwarded-For only via the nginx edge, which overwrites the header." />
          <Fact title="Untrusted code stays untrusted" body="Scanned code and comments are sent to the LLM as data. The model is told never to follow instructions found in them." />
          <Fact title="Safe archives and paths" body="ZIPs are checked for path traversal, symlinks and size bombs. Scanning server-side folders is off by default and confined to one directory." />
          <Fact title="Hardened responses" body="nosniff, DENY framing, no-store and a strict CSP on the API, plus request size caps at both the edge and the API." />
        </div>
      </Section>

      <Section
        id="demo-app"
        title="Demo app"
        lead={<p>An intentionally vulnerable Next.js app for live demos. Every credential in it is fake.</p>}
      >
        <CodeBlock label="Export it as a standalone, push-safe repo">{`cd backend
.venv/Scripts/python -m tests.fixtures.export_demo ../../vibeguard-demo-app`}</CodeBlock>
        <p className="mt-3 text-[14px] leading-relaxed text-ash">
          Push it to a new public repo and scan <C>you/vibeguard-demo-app</C>. It contains a
          hardcoded JWT secret, a service-role key behind <C>NEXT_PUBLIC_</C>, a made-up package,
          SQL and shell injection, unsanitized HTML, an IDOR and an unauthenticated server action.
        </p>
      </Section>
    </Page>
  );
}

function Fact({ title, body }: { title: string; body: string }) {
  return (
    <Panel className="p-4">
      <p className="stamp text-[13px]">{title}</p>
      <p className="mt-1.5 text-[14px] leading-relaxed text-ash">{body}</p>
    </Panel>
  );
}

function Step({ n, children }: { n: number; children: React.ReactNode }) {
  return (
    <li className="flex gap-3 text-[15px] leading-relaxed text-bone/85">
      <span className="grid h-6 w-6 shrink-0 place-items-center border-2 border-secure font-heading text-[12px] font-extrabold text-secure">
        {n}
      </span>
      <span>{children}</span>
    </li>
  );
}

function Bullet({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex gap-3">
      <span aria-hidden className="mt-2 h-1.5 w-1.5 shrink-0 bg-secure" />
      <span>{children}</span>
    </li>
  );
}
