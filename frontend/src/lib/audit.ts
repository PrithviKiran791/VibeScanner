import { RULES } from "./catalog";
import type { Counts, Finding, Scan, Severity } from "./types";
import { TERMINAL } from "./types";

export interface RepoPosture {
  target: string;
  latest: Scan;
  /** Change in Hardening Index since the previous completed scan of this repo. */
  delta: number | null;
  scans: number;
}

export interface AuditSummary {
  totals: { scans: number; completed: number; failed: number; running: number; repos: number };
  /** Mean of each repo's latest score; null until something has completed. */
  averageScore: number | null;
  open: Counts;
  repos: RepoPosture[];
}

const ZERO: Counts = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };

/** Scans arrive newest first (GET /scans). */
export function summarize(scans: Scan[]): AuditSummary {
  const byRepo = new Map<string, Scan[]>();
  for (const s of scans) {
    const list = byRepo.get(s.target) ?? [];
    list.push(s);
    byRepo.set(s.target, list);
  }

  const repos: RepoPosture[] = [];
  for (const [target, list] of byRepo) {
    const completed = list.filter((s) => s.status === "COMPLETED" && s.hardening_score !== null);
    const latest = completed[0];
    if (!latest) continue;
    const previous = completed[1];
    repos.push({
      target,
      latest,
      delta: previous ? latest.hardening_score! - previous.hardening_score! : null,
      scans: list.length,
    });
  }
  // Worst first: that's where to look
  repos.sort((a, b) => a.latest.hardening_score! - b.latest.hardening_score!);

  const open = repos.reduce<Counts>(
    (acc, r) => ({
      critical: acc.critical + r.latest.counts.critical,
      high: acc.high + r.latest.counts.high,
      medium: acc.medium + r.latest.counts.medium,
      low: acc.low + r.latest.counts.low,
      total: acc.total + r.latest.counts.total,
    }),
    { ...ZERO },
  );

  return {
    totals: {
      scans: scans.length,
      completed: scans.filter((s) => s.status === "COMPLETED").length,
      failed: scans.filter((s) => s.status === "FAILED").length,
      running: scans.filter((s) => !TERMINAL.has(s.status)).length,
      repos: byRepo.size,
    },
    averageScore: repos.length
      ? Math.round(repos.reduce((n, r) => n + r.latest.hardening_score!, 0) / repos.length)
      : null,
    open,
    repos,
  };
}

export interface RecurringIssue {
  ruleId: string;
  title: string;
  severity: Severity;
  occurrences: number;
  repos: number;
}

/** Open findings from each repo's latest scan, grouped by rule, most widespread first. */
export function recurringIssues(findingsByRepo: Map<string, Finding[]>): RecurringIssue[] {
  const tally = new Map<string, { f: Finding; occurrences: number; repos: Set<string> }>();
  for (const [repo, findings] of findingsByRepo) {
    for (const f of findings) {
      if (f.status !== "OPEN") continue;
      const entry = tally.get(f.rule_id) ?? { f, occurrences: 0, repos: new Set<string>() };
      entry.occurrences += 1;
      entry.repos.add(repo);
      tally.set(f.rule_id, entry);
    }
  }
  const catalogTitle = new Map(RULES.map((r) => [r.id, r.title]));
  return [...tally.entries()]
    .map(([ruleId, { f, occurrences, repos }]) => ({
      ruleId,
      // LLM findings have free-form titles; group them under their category instead
      title: catalogTitle.get(ruleId) ?? (ruleId.startsWith("llm-") ? f.category : f.title),
      severity: f.severity,
      occurrences,
      repos: repos.size,
    }))
    .sort((a, b) => b.repos - a.repos || b.occurrences - a.occurrences);
}
