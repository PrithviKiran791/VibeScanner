// The API client asks this module for a bearer token instead of importing Firebase, so
// lib/api.ts stays framework-free and testable. AuthProvider registers the real provider.

export type TokenProvider = (forceRefresh?: boolean) => Promise<string | null>;
export type AuthFailureHandler = () => void;

let provider: TokenProvider | null = null;
let onAuthFailure: AuthFailureHandler | null = null;

export function setTokenProvider(p: TokenProvider | null): void {
  provider = p;
}

export function setAuthFailureHandler(h: AuthFailureHandler | null): void {
  onAuthFailure = h;
}

export async function currentToken(forceRefresh = false): Promise<string | null> {
  return provider ? provider(forceRefresh) : null;
}

export function notifyAuthFailure(): void {
  onAuthFailure?.();
}

/** Only same-site paths are valid post-login destinations (no open redirects). */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  return next;
}
