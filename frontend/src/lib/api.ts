import { currentToken, notifyAuthFailure } from "./session";
import type {
  Finding,
  Me,
  FindingStatus,
  FindingUpdateResult,
  OpenPullRequestResult,
  Scan,
  ScanOptions,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly detail: unknown,
  ) {
    super(message);
  }

  /** On 409 the API returns the scan already running for that repo. */
  get conflictingScanId(): string | null {
    const d = this.detail as { scan_id?: unknown } | null;
    return this.status === 409 && typeof d?.scan_id === "string" ? d.scan_id : null;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let resp = await send(path, init, false);
  if (resp.status === 401) {
    // The cached ID token may have just expired: retry once with a fresh one
    resp = await send(path, init, true);
    if (resp.status === 401) notifyAuthFailure();
  }
  const body: unknown = await resp.json().catch(() => null);
  if (!resp.ok) {
    const detail = (body as { detail?: unknown } | null)?.detail;
    throw new ApiError(errorMessage(detail, resp.status), resp.status, detail);
  }
  return body as T;
}

async function send(path: string, init: RequestInit | undefined, refresh: boolean): Promise<Response> {
  const token = await currentToken(refresh);
  try {
    return await fetch(`/api/v1${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init?.headers,
      },
      cache: "no-store",
    });
  } catch {
    throw new ApiError("Can't reach the VibeGuard API. Is the backend running?", 0, null);
  }
}

export function errorMessage(detail: unknown, status: number): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    // FastAPI validation errors: [{loc, msg}, ...]
    const msgs = detail
      .map((d) => (d as { msg?: unknown } | null)?.msg)
      .filter((m): m is string => typeof m === "string")
      .map((m) => m.replace(/^Value error, /, ""));
    if (msgs.length) return msgs.join("; ");
  }
  const message = (detail as { message?: unknown } | null)?.message;
  if (typeof message === "string") return message;
  if (status === 0 || status >= 500) return "The VibeGuard API is unavailable.";
  return `Request failed (${status})`;
}

export const api = {
  createScan: (target: { repo_url: string } | { local_path: string }, options: ScanOptions) =>
    request<Scan>("/scans", { method: "POST", body: JSON.stringify({ ...target, options }) }),
  me: () => request<Me>("/me"),
  listScans: (limit = 20) => request<Scan[]>(`/scans?limit=${limit}`),
  getScan: (id: string) => request<Scan>(`/scans/${encodeURIComponent(id)}`),
  deleteScan: (id: string) =>
    request<null>(`/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),
  listFindings: (id: string) => request<Finding[]>(`/scans/${encodeURIComponent(id)}/findings`),
  updateFinding: (id: string, status: FindingStatus) =>
    request<FindingUpdateResult>(`/findings/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  openPullRequest: (id: string) =>
    request<OpenPullRequestResult>(`/findings/${encodeURIComponent(id)}/pull-request`, {
      method: "POST",
    }),
};
