import type { Metadata } from "next";

import { C, OnThisPage, Page, PageHeader, Panel, Section } from "@/components/page/Page";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { PASSES, PENALTIES, RULES, rulesFor, SEMANTIC_CATEGORIES, type Rule } from "@/lib/catalog";
import { cn } from "@/lib/format";

export const metadata: Metadata = { title: "Rules · VibeGuard" };

const fixable = RULES.filter((r) => r.fix).length;

export default function RulesPage() {
  return (
    <Page wide>
      <PageHeader eyebrow="Detection" title="Rules" accent="risk">
        Every check VibeGuard runs, what it catches, and what the generated fix does. Static rules
        run on every scan at zero cost. The semantic pass reviews only your server entry points.
      </PageHeader>

      <div className="mb-12 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat value={RULES.length} label="Static rules" />
        <Stat value={fixable} label="With auto-fix" tone="secure" />
        <Stat value={SEMANTIC_CATEGORIES.length} label="LLM categories" />
        <Stat value={PASSES.length} label="Analysis passes" />
      </div>

      <OnThisPage
        items={[
          ...PASSES.map((p) => ({ id: p.id, label: p.title })),
          { id: "scoring", label: "Hardening Index" },
        ]}
      />

      {PASSES.filter((p) => p.id !== "semantic").map((pass) => (
        <Section
          key={pass.id}
          id={pass.id}
          title={pass.title}
          lead={
            <>
              <p>{pass.summary}</p>
              <p className="code mt-2 text-ash">Engine: {pass.engine}</p>
            </>
          }
        >
          <RuleTable rules={rulesFor(pass.id)} />
        </Section>
      ))}

      <Section
        id="semantic"
        title="Semantic Review (LLM)"
        lead={
          <>
            <p>
              Tree-sitter pulls out App Router handlers, Pages API routes, server actions, Express
              routes and middleware, ranks them by risk (database access, mutations, user input, no
              auth check), and sends only those to the model. The model must quote the vulnerable
              lines verbatim. If they aren&apos;t really on those lines, the finding is thrown away.
            </p>
            <p className="code mt-2 text-ash">
              Engine: {PASSES.find((p) => p.id === "semantic")?.engine}
            </p>
          </>
        }
      >
        <div className="grid gap-3 md:grid-cols-2">
          {SEMANTIC_CATEGORIES.map((c) => (
            <Panel key={c.name} className="p-4">
              <p className="stamp text-[13px]">{c.name}</p>
              <p className="mt-1.5 text-[14px] leading-relaxed text-ash">{c.example}</p>
            </Panel>
          ))}
        </div>
        <p className="mt-4 text-[13px] text-ash">
          Hardcoded secrets, made-up packages, <C>eval</C>, shell calls, SQL interpolation and{" "}
          <C>dangerouslySetInnerHTML</C> are left to the static rules above, so the model&apos;s
          budget goes to logic bugs only.
        </p>
      </Section>

      <Section
        id="scoring"
        title="Hardening Index"
        lead={
          <p>
            A deterministic 0 to 100 score. The LLM never sets it. Each open finding subtracts
            points, the floor is 0, and dismissed or patched findings stop counting.
          </p>
        }
      >
        <Panel className="mb-4 px-5 py-4">
          <p className="code text-[15px] text-bone">
            score = max(0, 100 − 25·critical − 12·high − 5·medium − 1·low)
          </p>
        </Panel>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {PENALTIES.map((p) => (
            <Panel key={p.severity} className="p-4">
              <div className="flex items-center justify-between">
                <SeverityBadge severity={p.severity} />
                <span className="font-heading text-[22px] font-extrabold tabular-nums">
                  −{p.points}
                </span>
              </div>
              <p className="mt-3 text-[13px] leading-relaxed text-ash">{p.examples}</p>
            </Panel>
          ))}
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <Band range="80–100" label="Hardened" className="border-secure bg-grad-secure text-secure" />
          <Band range="60–79" label="Needs work" className="border-hairline text-bone" />
          <Band range="0–59" label="At risk" className="border-risk bg-grad-risk text-risk" />
        </div>
      </Section>
    </Page>
  );
}

function RuleTable({ rules }: { rules: Rule[] }) {
  return (
    <ul className="divide-y-2 divide-hairline border-2 border-hairline bg-carbon">
      {rules.map((r) => (
        <li key={r.id} id={`rule-${r.id}`} className="scroll-mt-[88px] p-4 sm:p-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={r.severity} />
            <span className="stamp inline-flex h-[22px] items-center border-2 border-hairline px-2 text-[11px] text-ash">
              {r.cwe}
            </span>
            <span
              className={cn(
                "stamp inline-flex h-[22px] items-center border-2 px-2 text-[11px]",
                r.fix ? "border-secure/60 text-secure" : "border-hairline text-ash",
              )}
            >
              {r.fix ? "Auto-fix" : "Manual fix"}
            </span>
          </div>
          <h3 className="stamp mt-3 text-[15px]">{r.title}</h3>
          <p className="code mt-1 text-ash">{r.id}</p>
          <p className="mt-2 max-w-[80ch] text-[14px] leading-relaxed text-bone/85">{r.detects}</p>
          {r.fix && (
            <p className="mt-2 max-w-[80ch] text-[13px] leading-relaxed text-ash">
              <span className="stamp mr-2 text-[11px] text-secure">Fix</span>
              {r.fix}
            </p>
          )}
        </li>
      ))}
    </ul>
  );
}

function Stat({ value, label, tone }: { value: number; label: string; tone?: "secure" }) {
  return (
    <Panel className={cn("p-4", tone === "secure" && "border-secure/60 bg-grad-secure")}>
      <p
        className={cn(
          "font-heading text-[32px] font-extrabold leading-none tabular-nums",
          tone === "secure" && "text-secure",
        )}
      >
        {value}
      </p>
      <p className="stamp mt-2 text-[11px] text-ash">{label}</p>
    </Panel>
  );
}

function Band({ range, label, className }: { range: string; label: string; className: string }) {
  return (
    <div className={cn("flex items-center justify-between border-2 px-4 py-3", className)}>
      <span className="stamp text-[12px]">{label}</span>
      <span className="font-heading text-[18px] font-extrabold tabular-nums">{range}</span>
    </div>
  );
}
