import type { Metadata } from "next";

import { AuditOverview } from "@/components/audit/AuditOverview";
import { RequireAuth } from "@/components/auth/RequireAuth";
import { Page, PageHeader } from "@/components/page/Page";

export const metadata: Metadata = { title: "Audit · VibeGuard" };

export default function AuditPage() {
  return (
    <RequireAuth>
      <Page wide>
        <PageHeader eyebrow="Security posture" title="Audit">
          Where every repository stands right now: the latest Hardening Index, how it moved since
          the previous scan, and the issues that keep coming back.
        </PageHeader>
        <AuditOverview />
      </Page>
    </RequireAuth>
  );
}
