"use client";

import { Eye, Plus, RotateCw, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { Spinner } from "@/components/ui/spinner";
import { ApiError, api } from "@/lib/api";
import { cn, scanWhen, scoreBand, shortTarget, STATUS_LABEL } from "@/lib/format";
import type { Scan } from "@/lib/types";
import { TERMINAL } from "@/lib/types";
import { useScanList } from "@/lib/useScanList";

const SCORE_BADGE = {
  secure: "border-secure bg-grad-secure text-secure",
  neutral: "border-hairline text-bone",
  risk: "border-risk bg-grad-risk text-risk",
} as const;

/** The signed-in user's audits (the API only ever returns their own), newest first. */
export function ScanHistoryView() {
  const { scans, error, remove } = useScanList(50);

  return (
    <section aria-labelledby="history-title">
      <div className="mb-6 flex items-end justify-between gap-4 border-l-[6px] border-secure pl-5">
        <div>
          <h1 id="history-title" className="stamp text-[30px] font-extrabold leading-none sm:text-[38px]">
            Scan History
          </h1>
          <p className="mt-2 text-[14px] text-ash">Your audits only. Nobody else can see or open them.</p>
        </div>
        <div className="flex items-center gap-4">
          {scans && scans.length > 0 && (
            <span className="stamp hidden text-[13px] text-ash sm:inline">
              {scans.length} {scans.length === 1 ? "audit" : "audits"}
            </span>
          )}
          <Link href="/scan" className="btn btn-primary">
            <Plus size={15} strokeWidth={2.5} aria-hidden /> New scan
          </Link>
        </div>
      </div>

      {error && <p className="border-[1.5px] border-risk px-5 py-4 text-[14px] text-risk">{error}</p>}
      {!error && scans === null && (
        <div className="flex items-center gap-3 border-[1.5px] border-hairline px-5 py-6 text-[14px] text-ash">
          <Spinner className="size-4 text-secure" />
          <span>Loading your audits…</span>
        </div>
      )}
      {scans?.length === 0 && (
        <div className="border-[1.5px] border-hairline bg-obsidian px-5 py-12 text-center">
          <p className="stamp text-[14px] leading-relaxed text-ash">
            No audits recorded yet. Submit a repo to generate your first report.
          </p>
          <Link href="/scan" className="btn btn-primary mt-6">
            New scan
          </Link>
        </div>
      )}

      {scans && scans.length > 0 && (
        <ul className="grid gap-3">
          {scans.map((s) => (
            <HistoryRow key={s.id} scan={s} onDeleted={() => remove(s.id)} />
          ))}
        </ul>
      )}
    </section>
  );
}

function HistoryRow({ scan, onDeleted }: { scan: Scan; onDeleted: () => void }) {
  const router = useRouter();
  const [busy, setBusy] = useState<"rescan" | "delete" | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const done = TERMINAL.has(scan.status);

  async function rescan() {
    setBusy("rescan");
    setError(null);
    const target = scan.source_type === "GITHUB" ? { repo_url: scan.target } : { local_path: scan.target };
    try {
      const next = await api.createScan(target, { llm: true, registry: true });
      router.push(`/scans/${next.id}`);
    } catch (err) {
      if (err instanceof ApiError && err.conflictingScanId) {
        router.push(`/scans/${err.conflictingScanId}`);
        return;
      }
      setError(err instanceof Error ? err.message : "Could not start the scan");
      setBusy(null);
    }
  }

  async function del() {
    setBusy("delete");
    setError(null);
    try {
      await api.deleteScan(scan.id);
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete the scan");
      setBusy(null);
      setConfirming(false);
    }
  }

  return (
    <li className="border-[1.5px] border-hairline bg-obsidian">
      <div className="grid items-center gap-4 px-4 py-4 sm:px-5 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,1.3fr)_88px_auto]">
        {/* 1. Repo + commit */}
        <div className="min-w-0">
          <p className="truncate text-[14px] font-semibold text-bone" title={scan.target}>
            {scan.source_type === "GITHUB" ? `github.com/${shortTarget(scan.target)}` : shortTarget(scan.target)}
          </p>
          <p className="mt-1 font-mono text-[12px] text-ash">
            {scan.commit_hash ? scan.commit_hash.slice(0, 7) : "-------"}
          </p>
        </div>

        {/* 2. When + how long */}
        <p className="text-[13px] text-ash">{scanWhen(scan.created_at, scan.duration_ms)}</p>

        {/* 3. What it found */}
        <div className="flex flex-wrap gap-1.5">
          {!done ? (
            <span className="stamp text-[11px] text-bone">
              {STATUS_LABEL[scan.status]}
              {scan.progress && ` ${scan.progress.percentage}%`}
            </span>
          ) : scan.status === "FAILED" ? (
            <span className="stamp text-[11px] text-risk">Failed</span>
          ) : (
            <Summary scan={scan} />
          )}
        </div>

        {/* 4. Hardening Index */}
        <div
          className={cn(
            "flex h-10 w-[88px] items-center justify-center border-2 font-heading text-[17px] font-extrabold tabular-nums",
            SCORE_BADGE[scoreBand(scan.hardening_score)],
          )}
          aria-label={scan.hardening_score === null ? "No score" : `Hardening score ${scan.hardening_score} of 100`}
        >
          {scan.hardening_score ?? "--"}
          <span className="ml-0.5 text-[11px] text-ash">/100</span>
        </div>

        {/* 5. Actions */}
        <div className="flex flex-wrap gap-2 lg:justify-end">
          <Link href={`/scans/${scan.id}`} className="btn btn-neutral h-9 px-3 text-[12px]">
            <Eye size={14} aria-hidden /> View audit
          </Link>
          <button
            type="button"
            className="btn btn-neutral h-9 px-3 text-[12px]"
            disabled={busy !== null || !done}
            onClick={rescan}
          >
            {busy === "rescan" ? <Spinner className="size-3.5 text-secure" /> : <RotateCw size={14} aria-hidden />}
            Re-scan
          </button>
          {confirming ? (
            <button
              type="button"
              className="btn btn-risk h-9 px-3 text-[12px]"
              disabled={busy !== null}
              onClick={del}
              onBlur={() => busy === null && setConfirming(false)}
              autoFocus
            >
              {busy === "delete" ? <Spinner className="size-3.5" /> : <Trash2 size={14} aria-hidden />}
              Confirm delete
            </button>
          ) : (
            <button
              type="button"
              className="btn btn-neutral h-9 px-3 text-[12px] hover:text-risk"
              disabled={busy !== null || !done}
              title={done ? undefined : "Wait for the scan to finish"}
              onClick={() => setConfirming(true)}
            >
              <Trash2 size={14} aria-hidden /> Delete
            </button>
          )}
        </div>
      </div>
      {error && (
        <p role="alert" className="border-t-[1.5px] border-hairline px-4 py-2 text-[13px] text-risk sm:px-5">
          {error}
        </p>
      )}
    </li>
  );
}

function Summary({ scan }: { scan: Scan }) {
  const { critical, high, medium, low, patched } = scan.counts;
  const pills = [
    critical > 0 && { label: `${critical} critical`, cls: "border-risk bg-risk text-obsidian" },
    high > 0 && { label: `${high} high`, cls: "border-risk text-risk" },
    medium > 0 && { label: `${medium} medium`, cls: "border-ash text-ash" },
    low > 0 && { label: `${low} low`, cls: "border-hairline text-ash" },
    patched > 0 && { label: `${patched} patched`, cls: "border-secure text-secure" },
  ].filter((p): p is { label: string; cls: string } => Boolean(p));

  if (pills.length === 0) return <span className="stamp text-[11px] text-secure">No open findings</span>;
  return (
    <>
      {pills.map((p) => (
        <span
          key={p.label}
          className={cn(
            "inline-flex h-[22px] items-center border-2 px-2 font-heading text-[11px] font-extrabold uppercase tracking-[0.1em]",
            p.cls,
          )}
        >
          {p.label}
        </span>
      ))}
    </>
  );
}
