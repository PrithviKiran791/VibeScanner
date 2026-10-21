import { cn } from "@/lib/format";
import type { Severity } from "@/lib/types";

const STYLE: Record<Severity, string> = {
  CRITICAL: "border-risk bg-risk text-obsidian",
  HIGH: "border-risk text-risk",
  MEDIUM: "border-ash text-ash",
  LOW: "border-hairline text-ash",
  INFO: "border-hairline text-ash/70",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-[22px] items-center border-2 px-2 font-heading text-[11px] font-extrabold uppercase tracking-[0.1em]",
        STYLE[severity],
        className,
      )}
    >
      {severity}
    </span>
  );
}
