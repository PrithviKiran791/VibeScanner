import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

import type { ScanStatus, Severity } from "./types";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

export function isSevere(s: Severity): boolean {
  return s === "CRITICAL" || s === "HIGH";
}

export type ScoreBand = "secure" | "neutral" | "risk";

/** design.md §3.4 */
export function scoreBand(score: number | null): ScoreBand {
  if (score === null) return "neutral";
  if (score >= 80) return "secure";
  if (score < 60) return "risk";
  return "neutral";
}

export const STATUS_LABEL: Record<ScanStatus, string> = {
  QUEUED: "Queued",
  CLONING: "Cloning",
  ANALYZING_STATIC: "Static analysis",
  ANALYZING_LLM: "Semantic review",
  COMPLETED: "Completed",
  FAILED: "Failed",
};

export function location(path: string, line: number): string {
  return `${path}:${line}`;
}

export function relativeTime(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/** "Oct 24, 2026 • 2.9s" for a history row (duration omitted while it's unknown). */
export function scanWhen(iso: string, durationMs: number | null, timeZone?: string): string {
  const date = new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone,
  }).format(new Date(iso));
  return durationMs == null ? date : `${date} • ${(durationMs / 1000).toFixed(1)}s`;
}

/** "https://github.com/acme/app" -> "acme/app"; local paths keep their last two segments. */
export function shortTarget(target: string): string {
  const gh = /^https:\/\/github\.com\/(.+)$/.exec(target);
  if (gh?.[1]) return gh[1];
  return target.split(/[\\/]/).filter(Boolean).slice(-2).join("/");
}
