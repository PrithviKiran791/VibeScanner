"use client";

import { Check, Copy, ExternalLink, GitPullRequest, KeyRound } from "lucide-react";
import { useState } from "react";

import { DiffView, SnippetView } from "@/components/inspector/DiffView";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { api } from "@/lib/api";
import { cn, isSevere, location } from "@/lib/format";
import type { Finding, FindingUpdateResult, ScanSource } from "@/lib/types";

/** Right column: root cause + unified diff + the three actions (design.md §6). */
export function Inspector(props: {
  finding: Finding;
  sourceType: ScanSource;
  onUpdate: (result: FindingUpdateResult) => void;
}) {
  const f = props.finding;
  const [busy, setBusy] = useState<"pr" | "status" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const isSecret = f.remediation?.verify_rule != null;
  const canFix = Boolean(f.unified_diff || f.remediation);
  const prBlocker = !canFix
    ? "This finding has no automated fix"
    : props.sourceType !== "GITHUB"
      ? "Pull requests need a GitHub scan"
      : null;

  async function run(kind: "pr" | "status", fn: () => Promise<FindingUpdateResult>) {
    setBusy(kind);
    setError(null);
    try {
      props.onUpdate(await fn());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy(null);
    }
  }

  async function copy() {
    if (!f.unified_diff) return;
    try {
      await navigator.clipboard.writeText(f.unified_diff);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setError("Clipboard is unavailable in this browser");
    }
  }

  return (
    <article className="flex min-h-full flex-col" aria-labelledby="finding-title">
      <header
        className={cn(
          "border-b-2 px-5 py-6 sm:px-8",
          isSevere(f.severity) && f.status === "OPEN" ? "border-risk bg-grad-risk" : "border-hairline",
        )}
      >
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} />
          {f.cwe_id && <Tag>{f.cwe_id}</Tag>}
          <Tag>{f.source === "LLM" ? "Semantic" : f.source === "MERGED" ? "Static + Semantic" : "Static"}</Tag>
          {f.status !== "OPEN" && (
            <Tag className={f.status === "DISMISSED_FALSE_POSITIVE" ? "" : "border-secure text-secure"}>
              {f.status === "DISMISSED_FALSE_POSITIVE" ? "Dismissed" : "Patched"}
            </Tag>
          )}
        </div>
        <h1 id="finding-title" className="stamp mt-4 text-[22px] leading-tight sm:text-[26px]">
          {f.title}
        </h1>
        <p className="code mt-2 break-all text-ash">{location(f.file_path, f.line_start)}</p>
      </header>

      <div className="flex-1 space-y-8 px-5 py-6 sm:px-8">
        <section>
          <h2 className="stamp mb-2 text-[12px] text-ash">Why It Matters</h2>
          <p className="max-w-[75ch] text-[15px] leading-relaxed text-bone/90">
            <InlineCode text={f.explanation} />
          </p>
        </section>

        {isSecret && f.remediation?.env_var_name && (
          <section className="flex gap-3 border-2 border-risk/60 p-4">
            <KeyRound size={18} className="mt-0.5 shrink-0 text-risk" aria-hidden />
            <p className="text-[14px] leading-relaxed text-bone/90">
              Rotate this credential now: it is in git history even after the fix. Then set{" "}
              <code className="code text-bone">{f.remediation.env_var_name}</code> in your deployment.
              The value is masked below; the pull request is built from the live file, so nothing
              secret is stored or sent.
            </p>
          </section>
        )}

        <section>
          <h2 className="stamp mb-3 text-[12px] text-ash">{f.unified_diff ? "Suggested Fix" : "Code"}</h2>
          {f.unified_diff ? (
            <DiffView diff={f.unified_diff} path={f.file_path} />
          ) : (
            <>
              <SnippetView code={f.snippet_original} path={f.file_path} firstLine={snippetStart(f)} />
              <p className="mt-3 text-[13px] text-ash">No automated patch for this one. Fix it by hand.</p>
            </>
          )}
        </section>
      </div>

      <footer className="sticky bottom-0 border-t-2 border-hairline bg-obsidian px-5 py-4 sm:px-8">
        {error && (
          <p role="alert" className="mb-3 text-[13px] text-risk">
            {error}
          </p>
        )}
        <div className="flex flex-wrap items-center gap-3">
          {f.pull_request ? (
            <a className="btn btn-primary" href={f.pull_request.pr_url} target="_blank" rel="noreferrer">
              <GitPullRequest size={16} strokeWidth={2.5} aria-hidden />
              View PR #{f.pull_request.pr_number}
              <ExternalLink size={14} aria-hidden />
            </a>
          ) : (
            <button
              type="button"
              className="btn btn-primary"
              disabled={Boolean(prBlocker) || busy !== null}
              title={prBlocker ?? undefined}
              onClick={() => run("pr", () => api.openPullRequest(f.id))}
            >
              <GitPullRequest size={16} strokeWidth={2.5} aria-hidden />
              {busy === "pr" ? "Opening PR" : "Apply Fix (PR)"}
            </button>
          )}
          <button type="button" className="btn btn-neutral" disabled={!f.unified_diff} onClick={copy}>
            {copied ? <Check size={16} aria-hidden /> : <Copy size={16} aria-hidden />}
            {copied ? "Copied" : "Copy Diff"}
          </button>
          <button
            type="button"
            className="ml-auto text-[13px] text-ash underline-offset-4 hover:text-bone hover:underline disabled:opacity-40"
            disabled={busy !== null}
            onClick={() =>
              run("status", () =>
                api.updateFinding(f.id, f.status === "OPEN" ? "DISMISSED_FALSE_POSITIVE" : "OPEN"),
              )
            }
          >
            {f.status === "OPEN" ? "Dismiss as false positive" : "Reopen"}
          </button>
        </div>
        {prBlocker && !f.pull_request && <p className="mt-2 text-[12px] text-ash">{prBlocker}.</p>}
      </footer>
    </article>
  );
}

/** Explanations (from rules and the LLM) mark identifiers with `backticks`. */
function InlineCode({ text }: { text: string }) {
  return text.split(/(`[^`\n]+`)/).map((part, i) =>
    part.length > 2 && part.startsWith("`") && part.endsWith("`") ? (
      <code key={i} className="code break-all border border-hairline bg-graphite px-1 text-bone">
        {part.slice(1, -1)}
      </code>
    ) : (
      part
    ),
  );
}

function Tag({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "stamp inline-flex h-[22px] items-center border-2 border-hairline px-2 text-[11px] text-ash",
        className,
      )}
    >
      {children}
    </span>
  );
}

/** Snippets carry up to 3 lines of context before the finding (fewer at the top of a file). */
function snippetStart(f: Finding): number {
  const extra = f.snippet_original.split("\n").length - (f.line_end - f.line_start + 1);
  const before = Math.max(0, Math.min(3, f.line_start - 1, Math.ceil(extra / 2)));
  return f.line_start - before;
}
