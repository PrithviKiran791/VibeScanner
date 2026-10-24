import type { Finding, Severity } from "./types";

export const CHART_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const satisfies readonly Severity[];

/** Red / grey / green only (design.md): severity reads as a red-to-grey ramp. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "#EF4444",
  HIGH: "#B91C1C",
  MEDIUM: "#A1A1AA",
  LOW: "#52525B",
  INFO: "#3F3F46",
};

export type ChartFilter =
  | { kind: "severity"; value: Severity }
  | { kind: "category"; value: string }
  | null;

export interface SeverityCount {
  severity: Severity;
  count: number;
}

export interface CategoryCount {
  category: string;
  count: number;
  worst: Severity;
}

const RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

/** The chart counts what still costs points: OPEN findings only. */
export function isOpen(f: Finding): boolean {
  return f.status === "OPEN";
}

export function countBySeverity(findings: Finding[]): SeverityCount[] {
  return CHART_SEVERITIES.map((severity) => ({
    severity,
    count: findings.filter((f) => isOpen(f) && f.severity === severity).length,
  }));
}

export function countByCategory(findings: Finding[]): CategoryCount[] {
  const map = new Map<string, CategoryCount>();
  for (const f of findings) {
    if (!isOpen(f)) continue;
    const entry = map.get(f.category) ?? { category: f.category, count: 0, worst: f.severity };
    entry.count += 1;
    if (RANK[f.severity] > RANK[entry.worst]) entry.worst = f.severity;
    map.set(f.category, entry);
  }
  return [...map.values()].sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
}

export function matchesFilter(f: Finding, filter: ChartFilter): boolean {
  if (!filter) return true;
  return filter.kind === "severity" ? f.severity === filter.value : f.category === filter.value;
}

export interface Arc {
  /** Distance along the circle where the segment starts. */
  start: number;
  /** Visible length of the segment (gap already removed). */
  length: number;
}

/**
 * Lay segments around a circle of the given circumference, proportional to `counts`, leaving
 * `gap` between neighbours. Zero counts get no arc. A lone segment closes the ring with no gap.
 */
export function ringArcs(counts: number[], circumference: number, gap: number): Arc[] {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return counts.map(() => ({ start: 0, length: 0 }));
  const visible = counts.filter((c) => c > 0).length;
  const g = visible > 1 ? gap : 0;
  let cursor = 0;
  return counts.map((count) => {
    const span = (count / total) * circumference;
    const arc = { start: cursor, length: count === 0 ? 0 : Math.max(0, span - g) };
    cursor += span;
    return arc;
  });
}
