"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { cn, relativeTime, scoreBand, shortTarget, STATUS_LABEL } from "@/lib/format";
import type { Scan } from "@/lib/types";
import { TERMINAL } from "@/lib/types";
import { Spinner } from "@/components/ui/spinner";

const SCORE_TEXT = { secure: "text-secure", neutral: "text-bone", risk: "text-risk" } as const;

export function ScanTable({ limit, title }: { limit: number; title: string }) {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = async () => {
      try {
        const data = await api.listScans(limit);
        if (!alive) return;
        setScans(data);
        setError(null);
        // Keep in-flight rows fresh without hammering the API once everything settles
        if (data.some((s) => !TERMINAL.has(s.status))) timer = setTimeout(load, 2000);
      } catch (err) {
        if (alive) setError(err instanceof Error ? err.message : "Could not load scans");
      }
    };
    void load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [limit]);

  return (
    <section className="border-2 border-hairline bg-carbon" aria-labelledby="scans-title">
      <div className="flex items-center justify-between border-b-2 border-hairline px-5 py-4 sm:px-6">
        <h2 id="scans-title" className="stamp text-[18px]">
          {title}
        </h2>
        {scans && <span className="text-[13px] text-ash">{scans.length}</span>}
      </div>

      {error && <p className="px-5 py-6 text-[14px] text-risk sm:px-6">{error}</p>}
      {!error && scans === null && (
        <div className="flex items-center gap-3 px-5 py-6 text-[14px] text-ash sm:px-6">
          <Spinner className="size-4 text-secure" />
          <span>Loading scans…</span>
        </div>
      )}
      {scans?.length === 0 && (
        <p className="px-5 py-6 text-[14px] text-ash sm:px-6">No scans yet. Start one above.</p>
      )}

      {scans && scans.length > 0 && (
        <ul className="divide-y-2 divide-hairline">
          {scans.map((s) => {
            const band = scoreBand(s.hardening_score);
            return (
              <li key={s.id}>
                <Link
                  href={`/scans/${s.id}`}
                  className="grid grid-cols-[1fr_auto] items-center gap-x-4 gap-y-1 px-5 py-4 transition-colors hover:bg-graphite sm:grid-cols-[1fr_140px_80px] sm:px-6"
                >
                  <span className="min-w-0">
                    <span className="block truncate text-[14px] font-semibold">
                      {shortTarget(s.target)}
                    </span>
                    <span className="block text-[12px] text-ash">
                      {s.source_type} · {relativeTime(s.created_at)}
                    </span>
                  </span>
                  <span
                    className={cn(
                      "stamp hidden text-[11px] sm:block",
                      s.status === "FAILED" ? "text-risk" : TERMINAL.has(s.status) ? "text-ash" : "text-bone",
                    )}
                  >
                    {STATUS_LABEL[s.status]}
                    {!TERMINAL.has(s.status) && s.progress && ` ${s.progress.percentage}%`}
                  </span>
                  <span
                    className={cn(
                      "text-right font-heading text-[22px] font-extrabold tabular-nums",
                      SCORE_TEXT[band],
                    )}
                  >
                    {s.hardening_score ?? "--"}
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
