import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";
import { safeNext, setAuthFailureHandler, setTokenProvider } from "./session";

function respond(status: number, body: unknown = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

afterEach(() => {
  vi.unstubAllGlobals();
  setTokenProvider(null);
  setAuthFailureHandler(null);
});

describe("API client auth", () => {
  it("sends the ID token as a bearer header", async () => {
    const fetchMock = vi.fn().mockResolvedValue(respond(200, []));
    vi.stubGlobal("fetch", fetchMock);
    setTokenProvider(async () => "id-token-1");

    await api.listScans();
    const headers = fetchMock.mock.calls[0]![1].headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer id-token-1");
  });

  it("sends no Authorization header when nobody is signed in (dev mode)", async () => {
    const fetchMock = vi.fn().mockResolvedValue(respond(200, []));
    vi.stubGlobal("fetch", fetchMock);

    await api.listScans();
    expect(fetchMock.mock.calls[0]![1].headers).not.toHaveProperty("Authorization");
  });

  it("retries a 401 once with a force-refreshed token", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(respond(401)).mockResolvedValueOnce(respond(200, []));
    vi.stubGlobal("fetch", fetchMock);
    const provider = vi.fn(async (force?: boolean) => (force ? "fresh" : "stale"));
    setTokenProvider(provider);
    const failure = vi.fn();
    setAuthFailureHandler(failure);

    await expect(api.listScans()).resolves.toEqual([]);
    expect(provider.mock.calls.map((c) => c[0])).toEqual([false, true]);
    expect((fetchMock.mock.calls[1]![1].headers as Record<string, string>).Authorization).toBe("Bearer fresh");
    expect(failure).not.toHaveBeenCalled();
  });

  it("signals an auth failure when even a fresh token is rejected", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(respond(401, { detail: "Sign in required" })));
    setTokenProvider(async () => "t");
    const failure = vi.fn();
    setAuthFailureHandler(failure);

    await expect(api.listScans()).rejects.toMatchObject({ status: 401, message: "Sign in required" });
    expect(failure).toHaveBeenCalledOnce();
  });

  it("does not treat 403 (not allowlisted) as a session failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(respond(403, { detail: "x is not allowed" })));
    setTokenProvider(async () => "t");
    const failure = vi.fn();
    setAuthFailureHandler(failure);

    await expect(api.me()).rejects.toMatchObject({ status: 403 });
    expect(failure).not.toHaveBeenCalled();
  });
});

describe("safeNext", () => {
  it.each([
    ["/scans/abc", "/scans/abc"],
    ["/audit?x=1", "/audit?x=1"],
    [null, "/"],
    ["", "/"],
    ["https://evil.example", "/"],
    ["//evil.example/path", "/"],
    ["/\\evil.example", "/"],
    ["javascript:alert(1)", "/"],
  ])("%s -> %s", (input, expected) => {
    expect(safeNext(input)).toBe(expected);
  });
});
