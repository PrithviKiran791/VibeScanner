import { cn } from "@/lib/format";
import type { DomainTab } from "@/lib/quality";

const TABS: { value: DomainTab; label: string }[] = [
  { value: "ALL", label: "All" },
  { value: "SECURITY", label: "Security" },
  { value: "QUALITY", label: "Code quality" },
];

/** Three-way switch at the top of the findings column. */
export function DomainTabs(props: {
  value: DomainTab;
  counts: Record<DomainTab, number>;
  onChange: (tab: DomainTab) => void;
}) {
  return (
    <div className="border-b-2 border-hairline px-4 py-4 sm:px-5">
      <div role="tablist" aria-label="Finding type" className="grid grid-cols-3 border-2 border-hairline">
        {TABS.map((t) => {
          const on = props.value === t.value;
          return (
            <button
              key={t.value}
              type="button"
              role="tab"
              aria-selected={on}
              onClick={() => props.onChange(t.value)}
              className={cn(
                "stamp px-2 py-2 text-[11px] transition-colors [&:not(:last-child)]:border-r-2 [&:not(:last-child)]:border-hairline",
                on ? "bg-bone text-obsidian" : "text-ash hover:bg-carbon hover:text-bone",
              )}
            >
              {t.label} <span className={on ? "text-obsidian/70" : "text-bone"}>({props.counts[t.value]})</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
