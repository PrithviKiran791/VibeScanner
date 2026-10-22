"use client";

import { RotateCw, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useMemo, useRef, useState } from "react";

import { Inspector } from "@/components/inspector/Inspector";
import { ScorePill } from "@/components/nav/ScorePill";
import { TopNav } from "@/components/nav/TopNav";
import { ScanProgress } from "@/components/scan/ScanProgress";
import { FindingList } from "@/components/triage/FindingList";
import { ApiError, api } from "@/lib/api";
import { shortTarget } from "@/lib/format";
import type { Scan } from "@/lib/types";
import { TERMINAL } from "@/lib/types";
import { useScan } from "@/lib/useScan";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

export function ScanWorkspace({ scanId }: { scanId: string }) {
  const { scan, findings, error, applyUpdate } = useScan(scanId);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const inspectorRef = useRef<HTMLDivElement>(null);

  // Until the user picks one, show the most severe open finding (findings arrive pre-sorted)
  const selected = useMemo(
    () =>
      findings?.find((f) => f.id === selectedId) ??
      findings?.find((f) => f.status === "OPEN") ??
      findings?.[0] ??
      null,
    [findings, selectedId],
  );

  function select(id: string) {
    setSelectedId(id);
    // Stacked layout on small screens: bring the inspector into view
    if (window.matchMedia("(max-width: 1023px)").matches) {
      inspectorRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  const nav = (
    <TopNav
      repo={scan ? shortTarget(scan.target) : undefined}
      right={
        scan && (
          <>
            <ScorePill score={scan.hardening_score} />
            <RescanButton scan={scan} />
          </>
        )
      }
    />
  );

  if (!scan) {
    return (
      <>
        {nav}
        <main className="px-4 pt-[calc(64px+48px)] text-center sm:px-6">
          {error ? (
            <p className="text-[14px] text-risk">{error}</p>
          ) : (
            <div className="flex items-center justify-center gap-3 text-[14px] text-ash">
              <Spinner className="size-5 text-secure" />
              <span>Loading scan…</span>
            </div>
          )}
        </main>
      </>
    );
  }

  if (!TERMINAL.has(scan.status)) {
    return (
      <>
        {nav}
        <main className="pt-nav">
          <ScanProgress scan={scan} />
        </main>
      </>
    );
  }

  if (scan.status === "FAILED") {
    return (
      <>
        {nav}
        <main className="mx-auto max-w-[720px] px-4 pt-[calc(64px+48px)] sm:px-6">
          <div className="border-2 border-risk bg-grad-risk p-6">
            <p className="stamp text-[12px] text-risk">Scan Failed</p>
            <h1 className="stamp mt-1 text-[24px]">{shortTarget(scan.target)}</h1>
            <p className="mt-4 text-[15px] text-bone/90">{scan.error_message ?? "Unknown error"}</p>
          </div>
        </main>
      </>
    );
  }

  return (
    <>
      {nav}
      <main className="pt-nav lg:grid lg:h-dvh lg:grid-cols-[38%_62%] lg:grid-rows-1">
        <aside
          aria-label="Findings"
          className="border-b-2 border-hairline lg:overflow-y-auto lg:border-b-0 lg:border-r-2"
        >
          {findings === null ? (
            <p className="px-5 py-6 text-[14px] text-ash">Loading findings…</p>
          ) : (
            <>
              <FindingList findings={findings} selectedId={selected?.id ?? null} onSelect={select} />
              <ScanNotes scan={scan} />
            </>
          )}
        </aside>
        <div ref={inspectorRef} className="scroll-mt-nav lg:overflow-y-auto">
          {selected ? (
            // Keyed so per-finding UI state (errors, "Copied") resets on selection change
            <Inspector key={selected.id} finding={selected} sourceType={scan.source_type} onUpdate={applyUpdate} />
          ) : (
            findings !== null && <AllClear score={scan.hardening_score} />
          )}
        </div>
      </main>
    </>
  );
}

function RescanButton({ scan }: { scan: Scan }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const disabled = busy || !TERMINAL.has(scan.status);

  async function rescan() {
    setBusy(true);
    const target =
      scan.source_type === "GITHUB" ? { repo_url: scan.target } : { local_path: scan.target };
    try {
      const next = await api.createScan(target, { llm: true, registry: true });
      router.push(`/scans/${next.id}`);
    } catch (err) {
      if (err instanceof ApiError && err.conflictingScanId) router.push(`/scans/${err.conflictingScanId}`);
      setBusy(false);
    }
  }

  return (
    <Button type="button" variant="neutral" className="px-3 sm:px-4" disabled={disabled} onClick={rescan}>
      {busy ? (
        <Spinner className="size-3.5 text-secure" />
      ) : (
        <RotateCw size={15} strokeWidth={2.5} aria-hidden />
      )}
      <span className="hidden sm:inline">Re-scan</span>
    </Button>
  );
}

function ScanNotes({ scan }: { scan: Scan }) {
  const facts = [
    scan.files_scanned != null && `${scan.files_scanned} files`,
    scan.duration_ms != null && `${(scan.duration_ms / 1000).toFixed(1)}s`,
    scan.llm_used ? "semantic review on" : "semantic review off",
    scan.commit_hash && scan.commit_hash.slice(0, 7),
  ].filter(Boolean);
  return (
    <footer className="space-y-1 px-4 py-5 text-[12px] text-ash sm:px-5">
      <p>{facts.join(" · ")}</p>
      {scan.warnings.map((w) => (
        <p key={w}>{w}</p>
      ))}
    </footer>
  );
}

function AllClear({ score }: { score: number | null }) {
  return (
    <div className="grid h-full place-items-center p-8">
      <div className="border-2 border-secure bg-grad-secure p-8 text-center">
        <ShieldCheck size={32} className="mx-auto text-secure" aria-hidden />
        <p className="stamp mt-4 text-[20px]">No Open Findings</p>
        <p className="mt-2 text-[14px] text-ash">Hardening Index {score ?? 100}/100</p>
      </div>
    </div>
  );
}
