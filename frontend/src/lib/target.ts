/** Accepts `owner/repo`, `github.com/owner/repo`, full URLs, or (dev only) an absolute local path. */
export function normalizeTarget(raw: string): { repo_url: string } | { local_path: string } | null {
  const v = raw.trim().replace(/\/+$/, "");
  if (!v) return null;
  if (/^([a-zA-Z]:[\\/]|\/)/.test(v)) return { local_path: v };
  const m = /^(?:https?:\/\/)?(?:www\.)?(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?$/.exec(v);
  return m ? { repo_url: `https://github.com/${m[1]}/${m[2]}` } : null;
}
