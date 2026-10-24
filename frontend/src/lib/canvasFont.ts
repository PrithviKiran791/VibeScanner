/**
 * <canvas> can't resolve CSS variables, so `font: "800 24px var(--font-heading)"` is silently
 * ignored. Read the variable's real value (next/font defines it as a font-family list) instead.
 */
export function resolveFontFamily(variable: string, fallback = "sans-serif"): string {
  if (typeof document === "undefined") return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(variable).trim();
  return value ? `${value}, ${fallback}` : fallback;
}
