"use client";

import {
  BookOpen,
  Braces,
  Code2,
  FileCode2,
  GitPullRequest,
  History,
  KeyRound,
  LayoutDashboard,
  Package,
  ScanSearch,
  ShieldAlert,
  Sparkles,
  Gauge,
  Terminal,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

import { AccountControl } from "@/components/nav/AccountControl";
import { FeatureItem, Menu, MenuItem, MenuLink } from "@/components/ui/navbar-menu";
import { RULES, rulesFor } from "@/lib/catalog";

type Section = "audit" | "rules" | "docs" | null;

/** Which menu a route belongs to, so the nav always shows where you are. */
function sectionFor(path: string): Section {
  if (path.startsWith("/scan") || path.startsWith("/audit") || path.startsWith("/history") || path.startsWith("/scans")) {
    return "audit";
  }
  if (path.startsWith("/rules")) return "rules";
  if (path.startsWith("/docs")) return "docs";
  return null;
}

const ICON = "size-4";

/** The only navigation surface (design.md §5): 64px, no sidebars, no breadcrumbs. */
export function TopNav({ repo, right }: { repo?: string; right?: React.ReactNode }) {
  const [active, setActive] = useState<string | null>(null);
  const section = sectionFor(usePathname());

  return (
    <header className="fixed inset-x-0 top-0 z-30 flex h-nav items-stretch border-b-2 border-hairline bg-obsidian">
      <Link
        href="/"
        aria-label="VibeGuard home"
        className="flex items-center gap-2 border-r-2 border-hairline px-4 font-heading text-[17px] font-extrabold uppercase tracking-[0.08em] sm:px-6"
      >
        <span aria-hidden className="block h-3 w-3 bg-secure" />
        <span className="hidden min-[420px]:inline">VibeGuard</span>
      </Link>

      {repo && (
        <div className="hidden min-w-0 max-w-[320px] items-center border-r-2 border-hairline px-5 lg:flex">
          <span className="truncate text-[13px] font-medium text-ash" title={repo}>
            {repo}
          </span>
        </div>
      )}

      <div className="flex flex-1 items-stretch justify-center">
        <Menu active={active} setActive={setActive} aria-label="Primary">
          <MenuItem
            item="audit"
            label="Audit"
            icon={<Code2 className="size-3.5 text-secure" aria-hidden />}
            current={section === "audit"}
            active={active}
            setActive={setActive}
            panelClassName="sm:w-[540px]"
          >
            <div className="grid gap-1 sm:grid-cols-2">
              <FeatureItem
                href="/audit"
                title="Security Overview"
                description="Every repo's latest score and the issues that keep recurring."
                icon={<LayoutDashboard className={ICON} />}
              />
              <FeatureItem
                href="/scan"
                title="New Code Scan"
                description="Scan a GitHub repo for secrets, injection and missing auth."
                icon={<ScanSearch className={ICON} />}
              />
              <FeatureItem
                href="/history"
                title="Scan History"
                description="Every past scan, newest first, with live progress."
                icon={<History className={ICON} />}
              />
              <FeatureItem
                href="/docs#demo-app"
                title="Demo App"
                description="An intentionally vulnerable app to try it on."
                icon={<FileCode2 className={ICON} />}
              />
            </div>
          </MenuItem>

          <MenuItem
            item="rules"
            label="Rules"
            icon={<ShieldAlert className="size-3.5 text-risk" aria-hidden />}
            current={section === "rules"}
            active={active}
            setActive={setActive}
            panelClassName="sm:w-[540px]"
          >
            <div className="grid gap-1 sm:grid-cols-2">
              <FeatureItem
                href="/rules#secrets"
                title="Secrets"
                meta={`${rulesFor("secrets").length} rules`}
                description="Provider keys, Supabase service roles, public-prefixed secrets."
                icon={<KeyRound className={ICON} />}
              />
              <FeatureItem
                href="/rules#sinks"
                title="AST Sinks"
                meta={`${rulesFor("sinks").length} rules`}
                description="SQL, XSS, eval and shell injection found by parsing, not grepping."
                icon={<Braces className={ICON} />}
              />
              <FeatureItem
                href="/rules#supply-chain"
                title="Supply Chain"
                meta={`${rulesFor("supply-chain").length} rule`}
                description="Packages that don't exist on npm or PyPI (slopsquatting)."
                icon={<Package className={ICON} />}
              />
              <FeatureItem
                href="/rules#semantic"
                title="Semantic Review"
                meta="LLM"
                description="Gemma checks routes and server actions for missing auth and IDOR."
                icon={<Sparkles className={ICON} />}
              />
            </div>
            <MenuLink href="/rules" className="mt-2">
              <span>All {RULES.length} rules and fixes</span>
              <span aria-hidden>→</span>
            </MenuLink>
          </MenuItem>

          <MenuItem
            item="docs"
            label="Docs"
            icon={<BookOpen className="size-3.5 text-ash" aria-hidden />}
            current={section === "docs"}
            active={active}
            setActive={setActive}
            panelClassName="sm:w-[340px]"
          >
            <div className="grid gap-1">
              <FeatureItem
                href="/docs"
                title="Documentation"
                description="Pipeline, API, CLI, configuration and security model."
                icon={<BookOpen className={ICON} />}
              />
              <FeatureItem
                href="/docs#pull-requests"
                title="Fix Pull Requests"
                description="How Apply Fix rebuilds a patch on your live branch."
                icon={<GitPullRequest className={ICON} />}
              />
              <FeatureItem
                href="/docs#hardening-index"
                title="Hardening Index"
                description="How the 0 to 100 score is calculated."
                icon={<Gauge className={ICON} />}
              />
              <FeatureItem
                href="http://localhost:8000/docs"
                title="API Reference"
                description="Interactive OpenAPI docs."
                icon={<Terminal className={ICON} />}
                external
              />
            </div>
          </MenuItem>
        </Menu>
      </div>

      {right && (
        <div className="flex items-center gap-3 border-l-2 border-hairline px-3 sm:px-5">{right}</div>
      )}

      {/* Sign In / account + sign out at the right edge */}
      <AccountControl />
    </header>
  );
}
