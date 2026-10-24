"use client";

import { useRef } from "react";

import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn, isSevere, location } from "@/lib/format";
import type { Finding } from "@/lib/types";

/** Left column. Cards carry exactly three data points: severity, title, file:line (design.md §6). */
export function FindingList(props: {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const open = props.findings.filter((f) => f.status === "OPEN");
  const triaged = props.findings.filter((f) => f.status !== "OPEN");
  const ordered = [...open, ...triaged];
  const listRef = useRef<HTMLDivElement>(null);

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const i = ordered.findIndex((f) => f.id === props.selectedId);
    const next = ordered[Math.min(ordered.length - 1, Math.max(0, i + (e.key === "ArrowDown" ? 1 : -1)))];
    if (next) {
      props.onSelect(next.id);
      listRef.current?.querySelector<HTMLButtonElement>(`[data-id="${next.id}"]`)?.focus();
    }
  }

  return (
    <div ref={listRef} onKeyDown={onKeyDown}>
      <Group title="Issues" count={open.length}>
        {open.map((f) => (
          <Card key={f.id} finding={f} selected={f.id === props.selectedId} onSelect={props.onSelect} />
        ))}
        {open.length === 0 && (
          <li className="border-2 border-secure bg-grad-secure p-4 text-[14px] text-secure">
            No open findings.
          </li>
        )}
      </Group>
      {triaged.length > 0 && (
        <Group title="Triaged" count={triaged.length}>
          {triaged.map((f) => (
            <Card key={f.id} finding={f} selected={f.id === props.selectedId} onSelect={props.onSelect} />
          ))}
        </Group>
      )}
    </div>
  );
}

function Group({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  return (
    <section className="border-b-2 border-hairline px-4 py-5 sm:px-5">
      <h2 className="stamp mb-4 flex items-center justify-between text-[13px] text-ash">
        {title}
        <span className="text-bone">{count}</span>
      </h2>
      <ul className="space-y-3">{children}</ul>
    </section>
  );
}

function Card({
  finding: f,
  selected,
  onSelect,
}: {
  finding: Finding;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  const severe = isSevere(f.severity);
  const patched = f.status === "PATCH_APPLIED" || f.status === "RESOLVED";
  const dismissed = f.status === "DISMISSED_FALSE_POSITIVE";

  return (
    <li>
      <button
        type="button"
        data-id={f.id}
        onClick={() => onSelect(f.id)}
        aria-current={selected ? "true" : undefined}
        className={cn(
          "block w-full border-2 bg-carbon p-4 text-left",
          "transition-[transform,box-shadow] duration-[60ms] ease-linear active:translate-x-[2px] active:translate-y-[2px] active:shadow-none",
          patched
            ? "border-secure/70 hover:shadow-hard-secure"
            : severe
              ? "border-hairline hover:shadow-hard-risk"
              : "border-hairline hover:shadow-hard",
          dismissed && "opacity-50",
          selected &&
            (patched
              ? "border-secure bg-grad-secure"
              : severe
                ? "border-risk bg-grad-risk"
                : "border-bone"),
          selected && "translate-x-[2px] translate-y-[2px] !shadow-none",
        )}
      >
        <SeverityBadge severity={f.severity} suffix={f.domain === "QUALITY" ? "SMELL" : "SEC"} />
        <span className="stamp mt-3 block text-[14px] leading-snug">{f.title}</span>
        <span className="code mt-1.5 block truncate text-ash" title={location(f.file_path, f.line_start)}>
          {location(f.file_path, f.line_start)}
        </span>
      </button>
    </li>
  );
}
