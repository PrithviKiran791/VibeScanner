import type { Metadata } from "next";

import { RequireAuth } from "@/components/auth/RequireAuth";
import { ScanWorkspace } from "@/components/scan/ScanWorkspace";

export const metadata: Metadata = { title: "Scan · VibeGuard" };

export default async function ScanPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <RequireAuth>
      <ScanWorkspace key={id} scanId={id} />
    </RequireAuth>
  );
}
