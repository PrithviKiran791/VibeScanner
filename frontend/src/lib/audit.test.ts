import { describe, expect, it } from "vitest";

import { recurringIssues, summarize } from "./audit";
import type { Finding, Scan } from "./types";

let n = 0;
function scan(target: string, score: number | null, over: Partial<Scan> = {}): Scan {
  n += 1;
  return {
    id: `s${n}`,
    status: "COMPLETED",
    source_type: "GITHUB",
    target,
    repository: target,
    commit_hash: null,
    hardening_score: score,
    counts: { critical: 1, high: 2, medium: 0, low: 0, total: 3 },
    files_scanned: 10,
    llm_used: false,
    warnings: [],
    duration_ms: 1000,
    error_message: null,
    progress: null,
    created_by: null,
    created_at: "2026-10-22T10:00:00Z",
    completed_at: "2026-10-22T10:00:05Z",
    ...over,
  };
}

function finding(rule_id: string, status: Finding["status"] = "OPEN", over: Partial<Finding> = {}): Finding {
  return {
    id: rule_id + Math.random(),
    scan_id: "s",
    rule_id,
    severity: "HIGH",
    category: "Injection",
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
    status,
    remediation: null,
    pull_request: null,
    ...over,
  };
}

describe("summarize", () => {
  it("uses each repo's latest completed scan and the change since the previous one", () => {
    const a = "https://github.com/acme/a";
    const b = "https://github.com/acme/b";
    const s = summarize([
      scan(a, 76), // newest first
      scan(a, 40),
      scan(b, null, { status: "ANALYZING_STATIC" }),
      scan(b, 100),
      scan(b, null, { status: "FAILED" }),
    ]);
    expect(s.totals).toEqual({ scans: 5, completed: 3, failed: 1, running: 1, repos: 2 });
    expect(s.repos.map((r) => [r.target, r.latest.hardening_score, r.delta])).toEqual([
      [a, 76, 36], // worst first
      [b, 100, null],
    ]);
    expect(s.averageScore).toBe(88);
    expect(s.open).toEqual({ critical: 2, high: 4, medium: 0, low: 0, total: 6 });
  });

  it("handles no completed scans", () => {
    const s = summarize([scan("x", null, { status: "QUEUED" })]);
    expect(s.averageScore).toBeNull();
    expect(s.repos).toEqual([]);
  });
});

describe("recurringIssues", () => {
  it("counts open findings by rule, ranks by how many repos they hit", () => {
    const issues = recurringIssues(
      new Map([
        ["a", [finding("sql-string-interpolation"), finding("sql-string-interpolation"), finding("hallucinated-dependency")]],
        ["b", [finding("hallucinated-dependency"), finding("dom-inner-html", "DISMISSED_FALSE_POSITIVE")]],
        ["c", [finding("llm-broken-access-control", "OPEN", { category: "Broken Access Control", title: "IDOR On X" })]],
      ]),
    );
    expect(issues.map((i) => [i.ruleId, i.repos, i.occurrences])).toEqual([
      ["hallucinated-dependency", 2, 2],
      ["sql-string-interpolation", 1, 2],
      ["llm-broken-access-control", 1, 1],
    ]);
    expect(issues[0]!.title).toBe("Hallucinated Package");
    expect(issues[2]!.title).toBe("Broken Access Control");
  });
});
