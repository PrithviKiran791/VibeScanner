import type { Metadata } from "next";

import { RequireAuth } from "@/components/auth/RequireAuth";
import { ScanHistoryView } from "@/components/history/ScanHistoryView";
import { TopNav } from "@/components/nav/TopNav";

export const metadata: Metadata = { title: "Scan History · VibeGuard" };

export default function HistoryPage() {
  return (
    <RequireAuth>
      <TopNav />
      <main className="mx-auto max-w-[1180px] px-4 pb-16 pt-[calc(64px+40px)] sm:px-6">
        <ScanHistoryView />
      </main>
    </RequireAuth>
  );
}
