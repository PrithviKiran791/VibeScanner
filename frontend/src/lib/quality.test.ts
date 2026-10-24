import { describe, expect, it } from "vitest";

import { domainCounts, gradeTone, inDomain, metricTone } from "./quality";
import type { Finding } from "./types";

const f = (domain: Finding["domain"]) => ({ domain }) as Finding;

describe("quality helpers", () => {
  it("colours grades: A/B healthy, C debt, D/F a problem", () => {
    expect(["A", "B", "C", "D", "F"].map((g) => gradeTone(g as never))).toEqual([
      "secure",
      "secure",
      "neutral",
      "risk",
      "risk",
    ]);
    expect(gradeTone(null)).toBe("neutral");
  });

  it("bands sub-scores", () => {
    expect([100, 80, 79, 60, 59].map(metricTone)).toEqual(["secure", "secure", "neutral", "neutral", "risk"]);
  });

  it("counts and filters findings by domain", () => {
    const list = [f("SECURITY"), f("QUALITY"), f("QUALITY")];
    expect(domainCounts(list)).toEqual({ ALL: 3, SECURITY: 1, QUALITY: 2 });
    expect(list.filter((x) => inDomain(x, "QUALITY"))).toHaveLength(2);
    expect(list.filter((x) => inDomain(x, "ALL"))).toHaveLength(3);
  });
});
