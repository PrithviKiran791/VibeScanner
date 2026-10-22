"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { ShieldAlert, BookOpen, Code2 } from "lucide-react";

import { AccountControl } from "@/components/nav/AccountControl";
import {
  Menubar,
  MenubarContent,
  MenubarItem,
  MenubarMenu,
  MenubarSeparator,
  MenubarShortcut,
  MenubarTrigger,
} from "@/components/ui/menubar";

/** The only navigation surface (design.md §5): 64px, no sidebars, no breadcrumbs. */
export function TopNav({ repo, right }: { repo?: string; right?: React.ReactNode }) {
  const router = useRouter();

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

      {/* Primary Center Neobrutalism Menubar */}
      <nav className="flex flex-1 items-center justify-center px-2" aria-label="Primary">
        <Menubar className="border-0 bg-transparent h-9">
          <MenubarMenu>
            <MenubarTrigger className="text-[12px] uppercase tracking-wider font-heading">
              <Code2 className="mr-1.5 size-3.5 text-secure" />
              Audit
            </MenubarTrigger>
            <MenubarContent>
              <MenubarItem onClick={() => router.push("/audit")}>Security Overview</MenubarItem>
              <MenubarSeparator />
              <MenubarItem onClick={() => router.push("/")}>
                New Code Scan <MenubarShortcut>⌘N</MenubarShortcut>
              </MenubarItem>
              <MenubarItem onClick={() => router.push("/history")}>
                Scan History <MenubarShortcut>⌘H</MenubarShortcut>
              </MenubarItem>
              <MenubarSeparator />
              <MenubarItem onClick={() => router.push("/docs#demo-app")}>
                Demo App Workspace
              </MenubarItem>
            </MenubarContent>
          </MenubarMenu>

          <MenubarMenu>
            <MenubarTrigger className="text-[12px] uppercase tracking-wider font-heading">
              <ShieldAlert className="mr-1.5 size-3.5 text-risk" />
              Rules
            </MenubarTrigger>
            <MenubarContent>
              <MenubarItem disabled className="font-semibold text-ash text-[11px] uppercase tracking-wider">
                Active Scanners
              </MenubarItem>
              <MenubarItem onClick={() => router.push("/rules#secrets")}>Secrets & Token Leaks</MenubarItem>
              <MenubarItem onClick={() => router.push("/rules#sinks")}>Tree-sitter AST Sinks</MenubarItem>
              <MenubarItem onClick={() => router.push("/rules#supply-chain")}>
                Supply Chain Typosquatting
              </MenubarItem>
              <MenubarSeparator />
              <MenubarItem onClick={() => router.push("/rules#semantic")}>
                LLM Semantic Review (Gemma)
              </MenubarItem>
              <MenubarSeparator />
              <MenubarItem onClick={() => router.push("/rules")}>All Rules</MenubarItem>
            </MenubarContent>
          </MenubarMenu>

          <MenubarMenu>
            <MenubarTrigger className="text-[12px] uppercase tracking-wider font-heading">
              <BookOpen className="mr-1.5 size-3.5 text-ash" />
              Docs
            </MenubarTrigger>
            <MenubarContent>
              <MenubarItem onClick={() => router.push("/docs")}>Documentation</MenubarItem>
              <MenubarItem onClick={() => router.push("/docs#pull-requests")}>GitHub PR Fixes</MenubarItem>
              <MenubarItem onClick={() => router.push("/docs#hardening-index")}>
                Hardening Index (0–100)
              </MenubarItem>
              <MenubarSeparator />
              <MenubarItem onClick={() => window.open("http://localhost:8000/docs", "_blank", "noopener")}>
                API Interactive Docs <MenubarShortcut>↗</MenubarShortcut>
              </MenubarItem>
            </MenubarContent>
          </MenubarMenu>
        </Menubar>
      </nav>

      {right && (
        <div className="flex items-center gap-3 border-l-2 border-hairline px-3 sm:px-5">{right}</div>
      )}

      {/* Sign In / account + sign out at the right edge */}
      <AccountControl />
    </header>
  );
}
