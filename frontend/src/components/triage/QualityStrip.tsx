"use client";

import { ChevronDown } from "lucide-react";
import { useState } from "react";

import type { ChartFilter } from "@/lib/chart";
import { cn } from "@/lib/format";
import { metricTone, QUALITY_METRICS } from "@/lib/quality";
import type { QualityBreakdown, QualityGrade } from "@/lib/types";

const CELL_TONE = { secure: "text-secure", neutral: "text-bone", risk: "text-risk" } as const;

/**
 * Five-cell telemetry bar above the inspector. Clicking a cell lists the smells behind that
 * score (left column switches to Code Quality, filtered to the metric); clicking again clears.
 */
export function QualityStrip(props: {
  score: number;
  grade: QualityGrade;
  breakdown: QualityBreakdown;
  filter: ChartFilter;
  onPick: (category: string | null) => void;
}) {
  const { score, grade, breakdown, filter, onPick } = props;
  const [open, setOpen] = useState(true);
  const active = filter?.kind === "category" ? filter.value : null;

  return (
    <section aria-label="Code quality" className="border-b-[1.5px] border-hairline bg-obsidian">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left sm:px-6"
      >
        <span className="stamp text-[12px] text-ash">
          Code quality <span className="text-bone">{score}/100</span> · grade{" "}
          <span className="text-bone">{grade}</span>
        </span>
        <span className="flex items-center gap-3 text-[12px] text-ash">
          <span className="hidden sm:inline">
            {breakdown.code_smells_count} smells · {breakdown.total_loc.toLocaleString()} lines
          </span>
          <ChevronDown size={16} className={cn("transition-transform", open && "rotate-180")} aria-hidden />
        </span>
      </button>

      {open && (
        <ul className="grid grid-cols-2 border-t-[1.5px] border-hairline sm:grid-cols-5">
          {QUALITY_METRICS.map((m) => {
            const value = breakdown[m.key];
            const on = active === m.label;
            return (
              <li key={m.key} className="border-hairline [&:not(:last-child)]:border-r-[1.5px] max-sm:border-b-[1.5px]">
                <button
                  type="button"
                  aria-pressed={on}
                  onClick={() => onPick(on ? null : m.label)}
                  title={`Show the smells behind ${m.label}`}
                  className={cn(
                    "flex w-full flex-col gap-1 px-4 py-3 text-left transition-colors hover:bg-carbon sm:px-5",
                    on && "bg-carbon shadow-[inset_0_-3px_0_0_currentColor]",
                    CELL_TONE[metricTone(value)],
                  )}
                >
                  <span className="stamp text-[10.5px] text-ash">{m.label}</span>
                  <span className="font-heading text-[22px] font-extrabold tabular-nums leading-none">{value}</span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
