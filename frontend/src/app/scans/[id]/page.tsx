import type { Metadata } from "next";

import { ScanWorkspace } from "@/components/scan/ScanWorkspace";

export const metadata: Metadata = { title: "Scan · VibeGuard" };

export default async function ScanPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <ScanWorkspace key={id} scanId={id} />;
}
