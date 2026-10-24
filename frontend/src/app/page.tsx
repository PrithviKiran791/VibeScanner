import type { Metadata } from "next";
import Link from "next/link";

import { HeroScan } from "@/components/landing/HeroScan";
import { LandingNav } from "@/components/landing/LandingNav";
import ShapeWaves from "@/components/ShapeWaves";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn } from "@/lib/format";

export const metadata: Metadata = {
  title: "VibeGuard · Harden what you vibe-coded",
  description:
    "AST analysis and semantic review for AI-generated web apps. Find leaked secrets, hallucinated packages and missing auth, and get the fix as a pull request.",
};

const REPO = "https://github.com/PrithviKiran791/VibeScanner";

const BEFORE: string[] = [
  "export async function GET(",
  "  req: Request,",
  "  { params }: { params: { id: string } },",
  ") {",
  "  const user = await db.user.findUnique({",
  "    where: { id: params.id },",
  "  });",
  "  return Response.json(user);",
  "}",
];

type Row = { kind: "ctx" | "add" | "del"; text: string };
const AFTER: Row[] = [
  { kind: "ctx", text: "export async function GET(" },
  { kind: "ctx", text: "  req: Request," },
  { kind: "ctx", text: "  { params }: { params: { id: string } }," },
  { kind: "ctx", text: ") {" },
  { kind: "add", text: "  const session = await auth();" },
  { kind: "add", text: "  if (!session) return new Response(null, { status: 401 });" },
  { kind: "add", text: "  if (session.user.id !== params.id)" },
  { kind: "add", text: "    return new Response(null, { status: 403 });" },
  { kind: "ctx", text: "  const user = await db.user.findUnique({" },
  { kind: "ctx", text: "    where: { id: params.id }," },
  { kind: "ctx", text: "  });" },
  { kind: "ctx", text: "  return Response.json(user);" },
  { kind: "ctx", text: "}" },
];

const PATTERNS = [
  {
    n: "01",
    title: "Slopsquatting & Hallucinated Packages",
    body: "LLMs invent package names. Attackers register them with malware. VibeGuard checks every npm and PyPI dependency against the live registry and flags the ones that don't exist.",
    tag: "SUPPLY CHAIN · CWE-1357",
    tone: "risk",
  },
  {
    n: "02",
    title: "Client-Side Secret Leaks",
    body: "Stripe keys, Supabase service-role tokens and AWS credentials baked into source, committed .env files, or hiding behind a NEXT_PUBLIC_ prefix that ships them to every browser.",
    tag: "SECRETS · CWE-798 · CWE-200",
    tone: "risk",
  },
  {
    n: "03",
    title: "Broken Authorization (BOLA / IDOR)",
    body: "Pattern matchers can't see a missing permission check. A targeted LLM review reads each route handler and server action and catches the ones that trust the URL instead of the session.",
    tag: "SEMANTIC · CWE-639",
    tone: "secure",
  },
] as const;

const STEPS = [
  ["01", "Clone", "Shallow clone into a throwaway sandbox. Deleted when the scan ends."],
  ["02", "Static pass", "Secrets, hallucinated packages and injection sinks, found by parsing, not grepping."],
  ["03", "Semantic pass", "Only your route handlers and server actions go to the model, which must quote the vulnerable lines."],
  ["04", "Fix", "Every patch is re-parsed, then opened as a pull request on your live branch."],
] as const;

const METRICS = [
  { value: "0", unit: "files", label: "Components, libs and .env files sent to the LLM. Only route code is reviewed.", tone: "secure" },
  { value: "100%", unit: "", label: "Generated patches re-parsed with Tree-sitter before you see them.", tone: "secure" },
  { value: "0–100", unit: "", label: "Deterministic Hardening Index. The model never sets the score.", tone: "neutral" },
] as const;

export default function Landing() {
  return (
    <>
      <LandingNav />
      <main className="pt-nav">
        {/* HERO */}
        <section className="relative overflow-hidden border-b-2 border-hairline">
          <div aria-hidden className="pointer-events-none absolute inset-0 z-0 opacity-60">
            <ShapeWaves
              text="</>"
              fontFamily="var(--font-heading), sans-serif"
              fontWeight={800}
              textSize={0.6}
              shapes="mixed"
              cellSize={11}
              dotSize={0.75}
              color="#27272a"
              hoverColor="#10b981"
              backgroundColor="#09090b"
              speed={0.8}
              brightness={0.4}
              flow={0.15}
              direction={45}
              fade={0.35}
              interactive
              splashRadius={45}
              splashStrength={0.45}
              glow={0.35}
              intro
              introDuration={1.6}
            />
          </div>
          <div className="relative z-10 mx-auto flex max-w-[1180px] flex-col items-start gap-8 px-4 pb-20 pt-16 sm:px-6 sm:pb-28 sm:pt-24">
            <p className="stamp inline-flex items-center gap-2 border-2 border-hairline bg-obsidian px-3 py-1.5 text-[11px] text-ash">
              <span aria-hidden className="blink text-secure">
                ●
              </span>
              The vibe-coding era needs hardening
            </p>
            <h1 className="stamp max-w-[18ch] text-[40px] font-extrabold leading-[1.02] sm:max-w-none sm:text-[64px] lg:text-[80px]">
              Vibe-coded apps ship in hours.
              <br />
              <span className="text-risk">Hackers exploit them in seconds.</span>
            </h1>
            <p className="max-w-[64ch] text-[16px] leading-relaxed text-bone/80 sm:text-[17px]">
              Cursor and Claude write code that works, but often miss basic auth, leak client-side
              secrets, and import hallucinated packages. VibeGuard runs AST analysis and semantic
              verification to find your vulnerabilities and auto-generate the fix.
            </p>
            <HeroScan />
          </div>
        </section>

        {/* PROOF */}
        <section id="proof" className="scroll-mt-nav border-b-2 border-hairline">
          <div className="mx-auto max-w-[1180px] px-4 py-16 sm:px-6 sm:py-20">
            <SectionHead eyebrow="The proof" title="From exploitable to merge-ready" />
            <div className="grid border-2 border-hairline lg:grid-cols-2">
              <Panel
                tone="risk"
                title="Before: what the LLM generated"
                meta="CWE-639 · Broken Object Authorization"
                badge={<SeverityBadge severity="CRITICAL" />}
                note="CVSS 8.6"
              >
                <CodeBlock>
                  {BEFORE.map((line, i) => (
                    <Line key={i} no={i + 1} callout={i === 5}>
                      {line}
                    </Line>
                  ))}
                </CodeBlock>
                <p className="mt-4 text-[13px] leading-relaxed text-ash">
                  <span className="text-risk">Line 6:</span> the record id comes straight from the URL.
                  Any visitor can read any user by changing it.
                </p>
              </Panel>
              <Panel
                tone="secure"
                title="After: what VibeGuard fixes"
                meta="Unified diff · app/api/user/[id]/route.ts"
                badge={
                  <span className="stamp inline-flex h-[22px] items-center border-2 border-secure px-2 text-[11px] text-secure">
                    Syntax verified
                  </span>
                }
                note="Ready to merge PR"
                divider
              >
                <CodeBlock>
                  {AFTER.map((row, i) => (
                    <DiffLine key={i} row={row} />
                  ))}
                </CodeBlock>
                <p className="mt-4 text-[13px] leading-relaxed text-ash">
                  The patch is re-parsed before you see it, then opened as a pull request against your
                  live branch.
                </p>
              </Panel>
            </div>
          </div>
        </section>

        {/* HOW IT WORKS */}
        <section id="how" className="scroll-mt-nav border-b-2 border-hairline">
          <div className="mx-auto max-w-[1180px] px-4 py-16 sm:px-6 sm:py-20">
            <SectionHead eyebrow="How it works" title="Four passes. Zero hand-waving." />
            <ol className="grid border-2 border-hairline sm:grid-cols-2 lg:grid-cols-4">
              {STEPS.map(([n, title, body], i) => (
                <li
                  key={n}
                  className={cn("p-6", i > 0 && "border-t-2 border-hairline sm:border-t-0", i % 2 === 1 && "sm:border-l-2", i > 1 && "sm:border-t-2 lg:border-t-0", i > 0 && "lg:border-l-2")}
                >
                  <span className="font-heading text-[13px] font-extrabold text-secure">{n}</span>
                  <h3 className="stamp mt-2 text-[16px]">{title}</h3>
                  <p className="mt-2 text-[14px] leading-relaxed text-ash">{body}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* DETECTION SUITE */}
        <section id="detection" className="scroll-mt-nav border-b-2 border-hairline">
          <div className="mx-auto max-w-[1180px] px-4 py-16 sm:px-6 sm:py-20">
            <SectionHead eyebrow="Detection suite" title="What traditional SAST misses" />
            <div className="grid border-2 border-hairline md:grid-cols-3">
              {PATTERNS.map((p, i) => (
                <article
                  key={p.n}
                  className={cn(
                    "group bg-carbon p-6 transition-[box-shadow,transform] duration-[60ms] ease-linear sm:p-8",
                    i > 0 && "border-t-2 border-hairline md:border-l-2 md:border-t-0",
                    p.tone === "risk" ? "hover:shadow-hard-risk" : "hover:shadow-hard-secure",
                    "hover:relative hover:z-10 hover:-translate-x-0.5 hover:-translate-y-0.5",
                  )}
                >
                  <span className={cn("font-heading text-[40px] font-extrabold leading-none", p.tone === "risk" ? "text-risk" : "text-secure")}>
                    {p.n}
                  </span>
                  <h3 className="stamp mt-5 text-[17px] leading-snug">{p.title}</h3>
                  <p className="mt-3 text-[14px] leading-relaxed text-ash">{p.body}</p>
                  <p className="stamp mt-6 border-t-2 border-hairline pt-3 text-[10.5px] text-ash">{p.tag}</p>
                </article>
              ))}
            </div>
            <p className="mt-4 text-[13px] text-ash">
              Plus SQL and shell injection, XSS sinks and dynamic <code className="code">eval</code>.{" "}
              <Link href="/rules" className="text-secure underline-offset-4 hover:underline">
                See all 18 rules →
              </Link>
            </p>
          </div>
        </section>

        {/* METRICS */}
        <section aria-label="By the numbers" className="border-b-2 border-hairline">
          <div className="mx-auto max-w-[1180px] px-4 py-16 sm:px-6 sm:py-20">
            <div className="grid border-2 border-hairline md:grid-cols-3">
              {METRICS.map((m, i) => (
                <div key={m.value} className={cn("bg-carbon p-6 sm:p-8", i > 0 && "border-t-2 border-hairline md:border-l-2 md:border-t-0", m.tone === "secure" && "bg-grad-secure")}>
                  <p className={cn("font-heading text-[56px] font-extrabold leading-none tabular-nums sm:text-[64px]", m.tone === "secure" ? "text-secure" : "text-bone")}>
                    {m.value}
                    {m.unit && <span className="ml-2 text-[20px] text-ash">{m.unit}</span>}
                  </p>
                  <p className="mt-4 max-w-[34ch] text-[14px] leading-relaxed text-ash">{m.label}</p>
                </div>
              ))}
            </div>
            <div className="mt-10 flex flex-wrap items-center gap-4">
              <Link href="/scan" className="btn btn-primary h-12 px-6 text-[14px]">
                Run your first audit <span aria-hidden>→</span>
              </Link>
              <Link href="/docs" className="btn btn-neutral h-12 px-6 text-[14px]">
                Read the docs
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* FOOTER */}
      <footer>
        <div className="mx-auto max-w-[1180px] px-4 py-12 sm:px-6">
          <p className="stamp text-[18px] sm:text-[22px]">Built for builders who ship fast but harden first.</p>
          <ul className="mt-6 flex flex-wrap gap-x-8 gap-y-2 text-[13px]">
            {[
              ["GitHub repo", REPO],
              ["Architecture spec", `${REPO}/blob/main/markdown/app_flow.md`],
              ["PRD", `${REPO}/blob/main/markdown/PRD.md`],
            ].map(([label, href]) => (
              <li key={label}>
                <a href={href} target="_blank" rel="noopener noreferrer" className="stamp text-ash hover:text-bone">
                  {label} ↗
                </a>
              </li>
            ))}
          </ul>
        </div>
        <div className="border-t-2 border-hairline">
          <p className="mx-auto max-w-[1180px] px-4 py-5 text-[12px] text-ash sm:px-6">
            © {new Date().getFullYear()} VibeGuard
          </p>
        </div>
      </footer>
    </>
  );
}

function SectionHead({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <header className="mb-10">
      <p className="stamp text-[12px] text-secure">{eyebrow}</p>
      <h2 className="stamp mt-2 text-[28px] font-extrabold leading-tight sm:text-[40px]">{title}</h2>
    </header>
  );
}

function Panel(props: {
  tone: "risk" | "secure";
  title: string;
  meta: string;
  badge: React.ReactNode;
  note: string;
  divider?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "min-w-0 p-5 sm:p-6",
        props.tone === "risk" ? "bg-grad-risk" : "bg-grad-secure",
        props.divider && "border-t-2 border-hairline lg:border-l-2 lg:border-t-0",
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        {props.badge}
        <span className={cn("stamp text-[11px]", props.tone === "risk" ? "text-risk" : "text-secure")}>{props.note}</span>
      </div>
      <h3 className="stamp mt-3 text-[15px]">{props.title}</h3>
      <p className="code mt-1 text-ash">{props.meta}</p>
      <div className="mt-4">{props.children}</div>
    </div>
  );
}

function CodeBlock({ children }: { children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto border-2 border-hairline bg-obsidian">
      <div className="code min-w-max py-2">{children}</div>
    </div>
  );
}

function Line({ no, callout, children }: { no: number; callout?: boolean; children: React.ReactNode }) {
  return (
    <div className={cn("flex border-l-2", callout ? "border-l-risk bg-grad-risk" : "border-l-transparent")}>
      <span className="w-9 shrink-0 select-none pr-2 text-right text-ash/50">{no}</span>
      <span className="whitespace-pre pr-6">{children}</span>
    </div>
  );
}

function DiffLine({ row }: { row: Row }) {
  return (
    <div
      className={cn(
        "flex border-l-2",
        row.kind === "add" ? "border-l-secure bg-grad-secure" : row.kind === "del" ? "border-l-risk bg-grad-risk" : "border-l-transparent",
      )}
    >
      <span
        aria-hidden
        className={cn("w-9 shrink-0 select-none pr-2 text-right", row.kind === "add" ? "text-secure" : "text-ash/50")}
      >
        {row.kind === "add" ? "+" : " "}
      </span>
      <span className="whitespace-pre pr-6">
        <span className="sr-only">{row.kind === "add" ? "added: " : ""}</span>
        {row.text}
      </span>
    </div>
  );
}
