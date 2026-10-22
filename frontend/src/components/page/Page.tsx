import { TopNav } from "@/components/nav/TopNav";
import { cn } from "@/lib/format";

/** Shell for content pages (Audit, Rules, Docs): top nav only, centered column, no sidebars. */
export function Page({ children, wide }: { children: React.ReactNode; wide?: boolean }) {
  return (
    <>
      <TopNav />
      <main
        className={cn(
          "mx-auto px-4 pb-24 pt-[calc(64px+40px)] sm:px-6",
          wide ? "max-w-[1180px]" : "max-w-[960px]",
        )}
      >
        {children}
      </main>
    </>
  );
}

export function PageHeader(props: {
  eyebrow: string;
  title: string;
  children?: React.ReactNode;
  accent?: "secure" | "risk" | "bone";
}) {
  const bar = { secure: "border-secure", risk: "border-risk", bone: "border-bone" }[
    props.accent ?? "secure"
  ];
  return (
    <header className={cn("mb-10 border-l-[6px] pl-5", bar)}>
      <p className="stamp text-[12px] text-ash">{props.eyebrow}</p>
      <h1 className="stamp mt-1 text-[32px] font-extrabold leading-none sm:text-[42px]">
        {props.title}
      </h1>
      {props.children && (
        <div className="mt-4 max-w-[68ch] text-[15px] leading-relaxed text-ash">{props.children}</div>
      )}
    </header>
  );
}

/** Horizontal "on this page" index. A strip of anchors, not a sidebar (design.md §5). */
export function OnThisPage({ items }: { items: { id: string; label: string }[] }) {
  return (
    <nav aria-label="On this page" className="mb-12 flex flex-wrap gap-2">
      {items.map((item) => (
        <a
          key={item.id}
          href={`#${item.id}`}
          className="stamp border-2 border-hairline bg-carbon px-3 py-1.5 text-[11px] text-ash transition-[transform,box-shadow,color] duration-[60ms] ease-linear hover:text-bone hover:shadow-hard active:translate-x-[2px] active:translate-y-[2px] active:shadow-none"
        >
          {item.label}
        </a>
      ))}
    </nav>
  );
}

export function Section(props: {
  id: string;
  title: string;
  lead?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section id={props.id} aria-labelledby={`${props.id}-title`} className="mb-16 scroll-mt-[88px]">
      <h2
        id={`${props.id}-title`}
        className="stamp border-b-2 border-hairline pb-3 text-[20px] sm:text-[22px]"
      >
        {props.title}
      </h2>
      {props.lead && (
        <div className="mt-4 max-w-[72ch] text-[15px] leading-relaxed text-bone/85">{props.lead}</div>
      )}
      <div className="mt-6">{props.children}</div>
    </section>
  );
}

export function Panel({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("border-2 border-hairline bg-carbon", className)}>{children}</div>;
}

/** Inline code in prose. */
export function C({ children }: { children: React.ReactNode }) {
  return (
    <code className="code break-words border border-hairline bg-graphite px-1 text-bone">
      {children}
    </code>
  );
}

/** A block of commands or JSON. Scrolls horizontally inside its own frame. */
export function CodeBlock({ children, label }: { children: string; label?: string }) {
  return (
    // min-w-0: inside a grid, long lines must scroll in the frame, not widen the page
    <figure className="min-w-0 border-2 border-hairline bg-obsidian">
      {label && (
        <figcaption className="stamp border-b-2 border-hairline px-3 py-2 text-[11px] text-ash">
          {label}
        </figcaption>
      )}
      <pre className="code overflow-x-auto px-4 py-3 text-bone/90">{children}</pre>
    </figure>
  );
}
