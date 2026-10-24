import { describe, expect, it } from "vitest";

import { countByCategory, countBySeverity, matchesFilter, ringArcs } from "./chart";
import type { Finding } from "./types";

function f(severity: Finding["severity"], category: string, status: Finding["status"] = "OPEN"): Finding {
  return {
    id: Math.random().toString(36),
    scan_id: "s",
    rule_id: "r",
    severity,
    category,
    title: "t",
    cwe_id: null,
    file_path: "a.ts",
    line_start: 1,
    line_end: 1,
    snippet_original: "",
    snippet_fixed: null,
    unified_diff: null,
    explanation: "",
    source: "STATIC",
    domain: "SECURITY",
    status,
    remediation: null,
    pull_request: null,
  };
}

const FINDINGS = [
  f("CRITICAL", "Injection"),
  f("CRITICAL", "Secret Exposure"),
  f("HIGH", "Injection"),
  f("LOW", "Supply Chain"),
  f("CRITICAL", "Injection", "DISMISSED_FALSE_POSITIVE"),
];

describe("counts", () => {
  it("counts open findings by severity, zeros included, in severity order", () => {
    expect(countBySeverity(FINDINGS).map((c) => [c.severity, c.count])).toEqual([
      ["CRITICAL", 2],
      ["HIGH", 1],
      ["MEDIUM", 0],
      ["LOW", 1],
    ]);
  });

  it("groups open findings by category with the worst severity, biggest first", () => {
    expect(countByCategory(FINDINGS)).toEqual([
      { category: "Injection", count: 2, worst: "CRITICAL" },
      { category: "Secret Exposure", count: 1, worst: "CRITICAL" },
      { category: "Supply Chain", count: 1, worst: "LOW" },
    ]);
  });
});

describe("matchesFilter", () => {
  it("matches by severity or category, and everything when unfiltered", () => {
    expect(matchesFilter(FINDINGS[0]!, null)).toBe(true);
    expect(matchesFilter(FINDINGS[0]!, { kind: "severity", value: "CRITICAL" })).toBe(true);
    expect(matchesFilter(FINDINGS[2]!, { kind: "severity", value: "CRITICAL" })).toBe(false);
    expect(matchesFilter(FINDINGS[2]!, { kind: "category", value: "Injection" })).toBe(true);
  });
});

describe("ringArcs", () => {
  it("splits the circumference proportionally and leaves gaps", () => {
    const arcs = ringArcs([2, 1, 0, 1], 100, 2);
    expect(arcs.map((a) => Math.round(a.start))).toEqual([0, 50, 75, 75]);
    expect(arcs.map((a) => Math.round(a.length))).toEqual([48, 23, 0, 23]);
  });

  it("closes a single segment into a full ring with no gap", () => {
    expect(ringArcs([0, 4, 0], 100, 2)[1]).toEqual({ start: 0, length: 100 });
  });

  it("draws nothing when there are no findings", () => {
    expect(ringArcs([0, 0], 100, 2)).toEqual([
      { start: 0, length: 0 },
      { start: 0, length: 0 },
    ]);
  });
});
