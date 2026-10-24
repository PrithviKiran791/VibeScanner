import type { Finding, FindingDomain, QualityBreakdown, QualityGrade } from "./types";

/** The five sub-scores, in display order. `category` matches the findings' category field. */
export const QUALITY_METRICS = [
  { key: "modularity", label: "Modularity" },
  { key: "type_safety", label: "Type Safety" },
  { key: "error_hygiene", label: "Error Hygiene" },
  { key: "cleanliness", label: "Cleanliness" },
  { key: "architecture", label: "Architecture" },
] as const satisfies readonly { key: keyof QualityBreakdown; label: string }[];

export type DomainTab = "ALL" | FindingDomain;

/** A/B read as healthy, C as debt, D/F as a problem (same red/grey/green palette as security). */
export function gradeTone(grade: QualityGrade | null): "secure" | "neutral" | "risk" {
  if (grade === "A" || grade === "B") return "secure";
  if (grade === "D" || grade === "F") return "risk";
  return "neutral";
}

/** Sub-score band: 80+ healthy, under 60 a problem. */
export function metricTone(score: number): "secure" | "neutral" | "risk" {
  return score >= 80 ? "secure" : score < 60 ? "risk" : "neutral";
}

export function domainCounts(findings: Finding[]): Record<DomainTab, number> {
  const quality = findings.filter((f) => f.domain === "QUALITY").length;
  return { ALL: findings.length, SECURITY: findings.length - quality, QUALITY: quality };
}

export function inDomain(f: Finding, tab: DomainTab): boolean {
  return tab === "ALL" || f.domain === tab;
}
