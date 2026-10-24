"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { TERMINAL } from "@/lib/types";

/** The signed-in user's latest scans; polls while any of them is still running. */
export function useScanList(limit: number) {
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

  /** Drop a row locally after it was deleted on the server. */
  function remove(id: string) {
    setScans((list) => list?.filter((s) => s.id !== id) ?? null);
  }

  return { scans, error, remove };
}
