"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/format";

/** The only navigation surface (design.md §5): 64px, no sidebars, no breadcrumbs. */
export function TopNav({ repo, right }: { repo?: string; right?: React.ReactNode }) {
  const path = usePathname();
  const onHistory = path.startsWith("/history");

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

      <nav className="flex flex-1 items-stretch justify-center" aria-label="Primary">
        {[
          { href: "/", label: "Code Audit", short: "Audit", active: !onHistory },
          { href: "/history", label: "Scan History", short: "History", active: onHistory },
        ].map((tab) => (
          <Link
            key={tab.href}
            href={tab.href}
            aria-current={tab.active ? "page" : undefined}
            className={cn(
              "stamp -mb-[2px] flex items-center whitespace-nowrap border-b-2 px-3 text-[12px] sm:px-5",
              tab.active ? "border-bone text-bone" : "border-transparent text-ash hover:text-bone",
            )}
          >
            <span className="hidden sm:inline">{tab.label}</span>
            <span className="sm:hidden">{tab.short}</span>
          </Link>
        ))}
      </nav>

      {right && (
        <div className="flex items-center gap-3 border-l-2 border-hairline px-3 sm:px-5">{right}</div>
      )}
    </header>
  );
}
