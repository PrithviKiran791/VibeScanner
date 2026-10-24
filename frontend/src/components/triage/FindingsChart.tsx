"use client";

import { motion, useReducedMotion } from "motion/react";
import { useMemo, useState } from "react";

import {
  type ChartFilter,
  CHART_SEVERITIES,
  countByCategory,
  countBySeverity,
  ringArcs,
  SEVERITY_COLOR,
} from "@/lib/chart";
import { cn } from "@/lib/format";
import type { Finding, Severity } from "@/lib/types";

type View = "severity" | "category";

const R = 44;
const CIRC = 2 * Math.PI * R;
const GAP = 3;

/**
 * Overview of what's still open. Two views of the same data: a severity ring and category bars.
 * Hover highlights, click filters the findings list below (click again to clear).
 */
export function FindingsChart(props: {
  findings: Finding[];
  filter: ChartFilter;
  onFilter: (filter: ChartFilter) => void;
}) {
  const { findings, filter, onFilter } = props;
  const [view, setView] = useState<View>("severity");
  const [hover, setHover] = useState<string | null>(null);

  const severities = useMemo(() => countBySeverity(findings), [findings]);
  const categories = useMemo(() => countByCategory(findings), [findings]);
  const total = severities.reduce((n, s) => n + s.count, 0);

  function toggle(next: NonNullable<ChartFilter>) {
    const same = filter && filter.kind === next.kind && filter.value === next.value;
    onFilter(same ? null : next);
  }

  return (
    <section aria-label="Findings overview" className="border-b-2 border-hairline px-4 py-5 sm:px-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="stamp text-[13px] text-ash">Overview</h2>
        <div role="group" aria-label="Chart view" className="flex border-2 border-hairline">
          {(["severity", "category"] as const).map((v) => (
            <button
              key={v}
              type="button"
              aria-pressed={view === v}
              onClick={() => {
                setView(v);
                setHover(null);
              }}
              className={cn(
                "stamp px-2.5 py-1 text-[10.5px] transition-colors",
                view === v ? "bg-bone text-obsidian" : "text-ash hover:text-bone",
              )}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {total === 0 ? (
        <AllClear />
      ) : view === "severity" ? (
        <SeverityRing
          severities={severities}
          total={total}
          filter={filter}
          hover={hover}
          setHover={setHover}
          toggle={toggle}
        />
      ) : (
        <CategoryBars
          categories={categories}
          filter={filter}
          hover={hover}
          setHover={setHover}
          toggle={toggle}
        />
      )}

      {filter && (
        <button
          type="button"
          onClick={() => onFilter(null)}
          className="stamp mt-4 inline-flex items-center gap-2 border-2 border-bone px-2.5 py-1 text-[11px] text-bone hover:bg-bone hover:text-obsidian"
        >
          Showing {filter.value} <span aria-hidden>✕</span>
          <span className="sr-only">Clear filter</span>
        </button>
      )}
    </section>
  );
}

function SeverityRing(props: {
  severities: { severity: Severity; count: number }[];
  total: number;
  filter: ChartFilter;
  hover: string | null;
  setHover: (key: string | null) => void;
  toggle: (f: NonNullable<ChartFilter>) => void;
}) {
  const { severities, total, filter, hover, setHover, toggle } = props;
  const reduce = useReducedMotion();
  const arcs = ringArcs(
    severities.map((s) => s.count),
    CIRC,
    GAP,
  );
  const active = hover ?? (filter?.kind === "severity" ? filter.value : null);
  const focused = severities.find((s) => s.severity === active);

  return (
    <div className="flex flex-col items-center gap-5 sm:flex-row sm:items-center">
      <svg
        viewBox="0 0 120 120"
        className="size-[150px] shrink-0 -rotate-90"
        role="img"
        aria-label={`${total} open findings: ${severities.map((s) => `${s.count} ${s.severity.toLowerCase()}`).join(", ")}`}
      >
        <circle cx="60" cy="60" r={R} fill="none" stroke="#27272A" strokeWidth="1" />
        {severities.map((s, i) => {
          const arc = arcs[i]!;
          if (arc.length <= 0) return null;
          const dim = active !== null && active !== s.severity;
          return (
            <motion.circle
              key={s.severity}
              cx="60"
              cy="60"
              r={R}
              fill="none"
              stroke={SEVERITY_COLOR[s.severity]}
              strokeDashoffset={-arc.start}
              initial={{ strokeDasharray: `0 ${CIRC}`, strokeWidth: 16 }}
              animate={{
                strokeDasharray: `${arc.length} ${CIRC - arc.length}`,
                strokeWidth: active === s.severity ? 22 : 16,
                opacity: dim ? 0.3 : 1,
              }}
              transition={reduce ? { duration: 0 } : { duration: 0.6, ease: "easeOut", delay: i * 0.08 }}
              className="cursor-pointer"
              onMouseEnter={() => setHover(s.severity)}
              onMouseLeave={() => setHover(null)}
              onClick={() => toggle({ kind: "severity", value: s.severity })}
            />
          );
        })}
        {/* Counter-rotate so the centre label reads upright */}
        <g transform="rotate(90 60 60)" className="pointer-events-none">
          <text x="60" y="58" textAnchor="middle" className="fill-bone font-heading text-[22px] font-extrabold">
            {focused ? focused.count : total}
          </text>
          <text x="60" y="73" textAnchor="middle" className="fill-ash font-heading text-[7px] font-bold uppercase tracking-[0.12em]">
            {focused ? focused.severity : "open"}
          </text>
        </g>
      </svg>

      <ul className="grid w-full gap-1.5">
        {CHART_SEVERITIES.map((sev) => {
          const count = severities.find((s) => s.severity === sev)?.count ?? 0;
          const on = filter?.kind === "severity" && filter.value === sev;
          return (
            <li key={sev}>
              <button
                type="button"
                disabled={count === 0}
                aria-pressed={on}
                onMouseEnter={() => setHover(sev)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(sev)}
                onBlur={() => setHover(null)}
                onClick={() => toggle({ kind: "severity", value: sev })}
                className={cn(
                  "flex w-full items-center gap-3 border-2 px-3 py-1.5 text-left transition-[transform,box-shadow] duration-[60ms] ease-linear",
                  "disabled:cursor-default disabled:opacity-40",
                  on ? "border-bone" : "border-hairline",
                  count > 0 && "hover:shadow-hard active:translate-x-[2px] active:translate-y-[2px] active:shadow-none",
                )}
              >
                <span aria-hidden className="h-3 w-3 shrink-0" style={{ background: SEVERITY_COLOR[sev] }} />
                <span className="stamp flex-1 text-[12px]">{sev}</span>
                <span className="font-heading text-[16px] font-extrabold tabular-nums">{count}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function CategoryBars(props: {
  categories: { category: string; count: number; worst: Severity }[];
  filter: ChartFilter;
  hover: string | null;
  setHover: (key: string | null) => void;
  toggle: (f: NonNullable<ChartFilter>) => void;
}) {
  const { categories, filter, hover, setHover, toggle } = props;
  const reduce = useReducedMotion();
  const max = Math.max(...categories.map((c) => c.count));

  return (
    <ul className="grid gap-2">
      {categories.map((c, i) => {
        const on = filter?.kind === "category" && filter.value === c.category;
        const dim = (hover !== null && hover !== c.category) || (filter?.kind === "category" && !on);
        return (
          <li key={c.category}>
            <button
              type="button"
              aria-pressed={on}
              onMouseEnter={() => setHover(c.category)}
              onMouseLeave={() => setHover(null)}
              onFocus={() => setHover(c.category)}
              onBlur={() => setHover(null)}
              onClick={() => toggle({ kind: "category", value: c.category })}
              className={cn(
                "block w-full border-2 px-3 py-2 text-left transition-[transform,box-shadow,opacity] duration-[60ms] ease-linear",
                "hover:shadow-hard active:translate-x-[2px] active:translate-y-[2px] active:shadow-none",
                on ? "border-bone" : "border-hairline",
                dim && "opacity-40",
              )}
            >
              <span className="flex items-baseline justify-between gap-3">
                <span className="stamp truncate text-[12px]">{c.category}</span>
                <span className="font-heading text-[16px] font-extrabold tabular-nums">{c.count}</span>
              </span>
              <span className="mt-2 block h-2.5 bg-obsidian">
                <motion.span
                  className="block h-full"
                  style={{ background: SEVERITY_COLOR[c.worst] }}
                  initial={{ width: 0 }}
                  animate={{ width: `${(c.count / max) * 100}%` }}
                  transition={reduce ? { duration: 0 } : { duration: 0.5, ease: "easeOut", delay: i * 0.06 }}
                />
              </span>
            </button>
          </li>
        );
      })}
      <li className="text-[11px] text-ash">Bar colour = worst severity in the category.</li>
    </ul>
  );
}

function AllClear() {
  return (
    <div className="flex items-center gap-4 border-2 border-secure bg-grad-secure p-4">
      <svg viewBox="0 0 120 120" className="size-[72px] shrink-0 -rotate-90" aria-hidden>
        <circle cx="60" cy="60" r={R} fill="none" stroke="#10B981" strokeWidth="16" />
      </svg>
      <div>
        <p className="stamp text-[15px] text-secure">All clear</p>
        <p className="mt-1 text-[13px] text-ash">No open findings. Nothing left costs points.</p>
      </div>
    </div>
  );
}
