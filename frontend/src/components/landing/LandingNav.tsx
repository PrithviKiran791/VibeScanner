import Link from "next/link";

const LINKS = [
  { href: "#how", label: "How it works" },
  { href: "#detection", label: "Detection suite" },
  { href: "/docs", label: "GitHub docs" },
];

/** Landing nav: wordmark, raw anchors, one hard-shadow CTA. 64px, no menus. */
export function LandingNav() {
  return (
    <header className="fixed inset-x-0 top-0 z-30 flex h-nav items-stretch border-b-2 border-hairline bg-obsidian">
      <Link
        href="/"
        aria-label="VibeGuard home"
        className="flex items-center gap-2 border-r-2 border-hairline px-4 font-heading text-[17px] font-extrabold uppercase tracking-[0.08em] sm:px-6"
      >
        <span aria-hidden className="block h-3 w-3 bg-secure" />
        VibeGuard
      </Link>

      <nav aria-label="Primary" className="hidden flex-1 items-stretch justify-center md:flex">
        {LINKS.map((l) => (
          <Link
            key={l.href}
            href={l.href}
            className="stamp flex items-center px-5 text-[12px] text-ash hover:text-bone"
          >
            [{l.label}]
          </Link>
        ))}
      </nav>
      <div className="flex-1 md:hidden" />

      <div className="flex items-center border-l-2 border-hairline px-3 sm:px-5">
        <Link
          href="/scan"
          className="btn btn-neutral h-9 !px-3 text-[12px] shadow-[3px_3px_0_#10B981] active:!shadow-none sm:!px-4"
        >
          Run audit <span aria-hidden>→</span>
        </Link>
      </div>
    </header>
  );
}
