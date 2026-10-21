"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "./api";
import { SEVERITY_RANK } from "./format";
import type { Finding, FindingUpdateResult, Scan } from "./types";
import { TERMINAL } from "./types";

const POLL_MS = 1000;

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.file_path.localeCompare(b.file_path) ||
      a.line_start - b.line_start,
  );
}

/**
 * Polls the scan until it settles (progress lives in Redis behind GET /scans/{id}), then loads
 * findings. Callers key the component by scanId so a new scan starts from fresh state.
 */
export function useScan(scanId: string) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      try {
        const s = await api.getScan(scanId);
        if (!alive) return;
        setScan(s);
        setError(null);
        if (!TERMINAL.has(s.status)) {
          timer = setTimeout(tick, POLL_MS);
        } else if (s.status === "COMPLETED") {
          const f = await api.listFindings(scanId);
          if (alive) setFindings(sortFindings(f));
        }
      } catch (err) {
        if (!alive) return;
        setError(err instanceof Error ? err.message : "Could not load the scan");
        timer = setTimeout(tick, POLL_MS * 3); // keep trying: the API may be restarting
      }
    };

    void tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [scanId]);

  /** Apply a PATCH / PR result: swap in the finding and the recalculated score. */
  const applyUpdate = useCallback((result: FindingUpdateResult) => {
    setFindings((prev) => prev?.map((f) => (f.id === result.finding.id ? result.finding : f)) ?? prev);
    setScan((prev) =>
      prev && {
        ...prev,
        hardening_score: result.scan.hardening_score,
        counts: result.scan.counts,
      },
    );
  }, []);

  return { scan, findings, error, applyUpdate };
}
