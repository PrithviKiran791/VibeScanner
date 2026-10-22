import type { Metadata } from "next";

import { RequireAuth } from "@/components/auth/RequireAuth";
import { TopNav } from "@/components/nav/TopNav";
import { ScanTable } from "@/components/scan/ScanTable";

export const metadata: Metadata = { title: "Scan History · VibeGuard" };

export default function HistoryPage() {
  return (
    <RequireAuth>
      <TopNav />
      <main className="mx-auto max-w-[1080px] px-4 pb-16 pt-[calc(64px+40px)] sm:px-6">
        <ScanTable limit={50} title="Scan History" />
      </main>
    </RequireAuth>
  );
}
