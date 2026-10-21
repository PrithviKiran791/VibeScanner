import { describe, expect, it } from "vitest";

import { errorMessage } from "./api";
import { relativeTime, scoreBand, shortTarget } from "./format";

describe("format", () => {
  it("bands scores per design.md", () => {
    const scores = [100, 80, 79, 60, 59, null] as const;
    expect(scores.map(scoreBand)).toEqual([
      "secure",
      "secure",
      "neutral",
      "neutral",
      "risk",
      "neutral",
    ]);
  });

  it("shortens targets", () => {
    expect(shortTarget("https://github.com/acme/vibe-app")).toBe("acme/vibe-app");
    expect(shortTarget("C:\\Users\\me\\code\\demo_app")).toBe("code/demo_app");
  });

  it("formats relative time", () => {
    const now = Date.parse("2026-10-22T12:00:00Z");
    expect(relativeTime("2026-10-22T11:59:30Z", now)).toBe("30s ago");
    expect(relativeTime("2026-10-22T09:00:00Z", now)).toBe("3h ago");
  });

  it("turns API error details into readable messages", () => {
    expect(errorMessage("Scan not found", 404)).toBe("Scan not found");
    expect(
      errorMessage([{ msg: "Value error, Provide exactly one of repo_url or local_path" }], 422),
    ).toBe("Provide exactly one of repo_url or local_path");
    expect(errorMessage({ message: "A scan is already running" }, 409)).toMatch(/already/);
    expect(errorMessage(null, 503)).toBe("The VibeGuard API is unavailable.");
  });
});
