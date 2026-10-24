// A repo someone asked to scan before signing in. Kept in sessionStorage so it survives the
// sign-in popup and the redirect to /scan, and dies with the tab. Storage can be unavailable
// (private windows, blocked site data): then there's simply nothing pending.

const KEY = "pending_scan_repo";

export function savePendingScan(repoUrl: string): void {
  try {
    sessionStorage.setItem(KEY, repoUrl);
  } catch {
    /* storage unavailable */
  }
}

/** Read and clear in one step, so a pending scan is started at most once. */
export function takePendingScan(): string | null {
  try {
    const value = sessionStorage.getItem(KEY);
    sessionStorage.removeItem(KEY);
    return value;
  } catch {
    return null;
  }
}
