"use client";

import { ArrowDownRight, ArrowRight, ArrowUpRight } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { Panel, Section } from "@/components/page/Page";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import { type AuditSummary, type RecurringIssue, recurringIssues, summarize } from "@/lib/audit";
import { cn, relativeTime, scoreBand, shortTarget } from "@/lib/format";
import type { Finding } from "@/lib/types";

const HISTORY = 100;
const REPOS_FOR_ISSUES = 8;
const SCORE_TEXT = { secure: "text-secure", neutral: "text-bone", risk: "text-risk" } as const;

export function AuditOverview() {
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [issues, setIssues] = useState<RecurringIssue[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const s = summarize(await api.listScans(HISTORY));
        if (!alive) return;
        setSummary(s);
        // Findings from each repo's latest scan (bounded, worst repos first)
        const picked = s.repos.slice(0, REPOS_FOR_ISSUES);
        const lists = await Promise.all(picked.map((r) => api.listFindings(r.latest.id)));
        if (!alive) return;
        setIssues(recurringIssues(new Map<string, Finding[]>(picked.map((r, i) => [r.target, lists[i]!]))));
      } catch (err) {
        if (alive) setError(err instanceof Error ? err.message : "Could not load the audit");
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  if (error) {
    return <Panel className="border-risk p-6 text-[14px] text-risk">{error}</Panel>;
  }
  if (!summary) {
    return (
      <div className="flex items-center gap-3 text-[14px] text-ash">
        <Spinner className="size-4 text-secure" />
        Loading audit…
      </div>
    );
  }
  if (summary.repos.length === 0) {
    return (
      <Panel className="p-8 text-center">
        <p className="stamp text-[18px]">Nothing to audit yet</p>
        <p className="mt-2 text-[14px] text-ash">Finished scans show up here, grouped by repository.</p>
        <Link href="/scan" className="btn btn-primary mt-6">
          Start a scan <ArrowRight size={16} aria-hidden />
        </Link>
      </Panel>
    );
  }

  const band = scoreBand(summary.averageScore);
  return (
    <>
      <div className="mb-14 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Panel
          className={cn(
            "p-5",
            band === "secure" && "border-secure bg-grad-secure",
            band === "risk" && "border-risk bg-grad-risk",
          )}
        >
          <p className="stamp text-[11px] text-ash">Average Hardening Index</p>
          <p className={cn("mt-2 font-heading text-[44px] font-extrabold leading-none tabular-nums", SCORE_TEXT[band])}>
            {summary.averageScore}
          </p>
          <p className="mt-2 text-[12px] text-ash">Latest scan of each repo</p>
        </Panel>
        <Panel className="p-5">
          <p className="stamp text-[11px] text-ash">Open findings</p>
          <p className="mt-2 font-heading text-[44px] font-extrabold leading-none tabular-nums">{summary.open.total}</p>
          <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-[12px]">
            <span className="text-risk">{summary.open.critical} critical</span>
            <span className="text-risk/80">{summary.open.high} high</span>
            <span className="text-ash">{summary.open.medium} medium</span>
            <span className="text-ash">{summary.open.low} low</span>
          </div>
        </Panel>
        <Panel className="p-5">
          <p className="stamp text-[11px] text-ash">Repositories</p>
          <p className="mt-2 font-heading text-[44px] font-extrabold leading-none tabular-nums">{summary.totals.repos}</p>
          <p className="mt-2 text-[12px] text-ash">{summary.totals.scans} scans in history</p>
        </Panel>
        <Panel className="p-5">
          <p className="stamp text-[11px] text-ash">Scan outcomes</p>
          <ul className="mt-3 space-y-1 text-[13px]">
            <li className="flex justify-between"><span className="text-ash">Completed</span><span className="tabular-nums">{summary.totals.completed}</span></li>
            <li className="flex justify-between"><span className="text-ash">Running</span><span className="tabular-nums">{summary.totals.running}</span></li>
            <li className="flex justify-between"><span className="text-ash">Failed</span><span className={cn("tabular-nums", summary.totals.failed > 0 && "text-risk")}>{summary.totals.failed}</span></li>
          </ul>
        </Panel>
      </div>

      <Section id="repositories" title="Repositories" lead={<p>Lowest score first: that&apos;s where to start.</p>}>
        <ul className="divide-y-2 divide-hairline border-2 border-hairline bg-carbon">
          {summary.repos.map((r) => {
            const b = scoreBand(r.latest.hardening_score);
            return (
              <li key={r.target}>
                <Link
                  href={`/scans/${r.latest.id}`}
                  className="grid grid-cols-[1fr_auto] items-center gap-x-4 gap-y-2 px-5 py-4 transition-colors hover:bg-graphite sm:grid-cols-[1fr_200px_90px_70px]"
                >
                  <span className="min-w-0">
                    <span className="block truncate text-[14px] font-semibold">{shortTarget(r.target)}</span>
                    <span className="block text-[12px] text-ash">
                      {r.scans} scan{r.scans === 1 ? "" : "s"} · last {relativeTime(r.latest.created_at)}
                      {r.latest.created_by ? ` · by ${r.latest.created_by}` : ""}
                    </span>
                  </span>
                  <span className="hidden gap-3 text-[12px] sm:flex">
                    <span className={r.latest.counts.critical ? "text-risk" : "text-ash"}>{r.latest.counts.critical} crit</span>
                    <span className={r.latest.counts.high ? "text-risk/80" : "text-ash"}>{r.latest.counts.high} high</span>
                    <span className="text-ash">{r.latest.counts.medium + r.latest.counts.low} other</span>
                  </span>
                  <Delta value={r.delta} />
                  <span className={cn("text-right font-heading text-[24px] font-extrabold tabular-nums", SCORE_TEXT[b])}>
                    {r.latest.hardening_score}
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </Section>

      <Section
        id="recurring"
        title="Recurring issues"
        lead={<p>Open findings across the latest scans, most widespread first. Fixing the top rows improves the most repos at once.</p>}
      >
        {issues === null ? (
          <div className="flex items-center gap-3 text-[14px] text-ash">
            <Spinner className="size-4 text-secure" />
            Collecting findings…
          </div>
        ) : issues.length === 0 ? (
          <Panel className="border-secure bg-grad-secure p-5 text-[14px] text-secure">No open findings in the latest scans.</Panel>
        ) : (
          <ul className="divide-y-2 divide-hairline border-2 border-hairline bg-carbon">
            {issues.map((i) => (
              <li key={i.ruleId} className="grid grid-cols-[auto_1fr_auto] items-center gap-4 px-5 py-4">
                <SeverityBadge severity={i.severity} />
                <span className="min-w-0">
                  <span className="stamp block truncate text-[14px]">{i.title}</span>
                  <Link
                    href={i.ruleId.startsWith("llm-") ? "/rules#semantic" : `/rules#rule-${i.ruleId}`}
                    className="code text-ash underline-offset-4 hover:text-bone hover:underline"
                  >
                    {i.ruleId}
                  </Link>
                </span>
                <span className="text-right text-[12px] text-ash">
                  <span className="block font-heading text-[18px] font-extrabold text-bone tabular-nums">{i.occurrences}</span>
                  in {i.repos} repo{i.repos === 1 ? "" : "s"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </>
  );
}

function Delta({ value }: { value: number | null }) {
  if (value === null) return <span className="hidden text-right text-[12px] text-ash sm:block">first scan</span>;
  const Icon = value > 0 ? ArrowUpRight : value < 0 ? ArrowDownRight : ArrowRight;
  return (
    <span
      className={cn(
        "hidden items-center justify-end gap-1 text-[13px] tabular-nums sm:flex",
        value > 0 ? "text-secure" : value < 0 ? "text-risk" : "text-ash",
      )}
      aria-label={`${value > 0 ? "up" : value < 0 ? "down" : "unchanged"} ${Math.abs(value)} since previous scan`}
    >
      <Icon size={14} aria-hidden />
      {value > 0 ? `+${value}` : value}
    </span>
  );
}
