import { describe, expect, it } from "vitest";

import { normalizeTarget } from "./target";

describe("normalizeTarget", () => {
  it.each([
    ["acme/vibe-app", "https://github.com/acme/vibe-app"],
    ["github.com/acme/vibe-app", "https://github.com/acme/vibe-app"],
    ["https://github.com/acme/vibe.app.git", "https://github.com/acme/vibe.app"],
    ["  https://www.github.com/acme/vibe-app/  ", "https://github.com/acme/vibe-app"],
  ])("%s -> GitHub URL", (input, url) => {
    expect(normalizeTarget(input)).toEqual({ repo_url: url });
  });

  it("passes absolute local paths through", () => {
    expect(normalizeTarget("C:\\code\\demo_app")).toEqual({ local_path: "C:\\code\\demo_app" });
    expect(normalizeTarget("/srv/demo")).toEqual({ local_path: "/srv/demo" });
  });

  it.each(["", "acme", "https://gitlab.com/acme/app", "acme/app/tree/main"])("rejects %j", (input) => {
    expect(normalizeTarget(input)).toBeNull();
  });
});
