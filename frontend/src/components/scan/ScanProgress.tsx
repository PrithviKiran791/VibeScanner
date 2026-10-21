import { Check } from "lucide-react";

import { cn, shortTarget } from "@/lib/format";
import type { Scan, ScanStatus } from "@/lib/types";

const STAGES: { status: ScanStatus; label: string; detail: string }[] = [
  { status: "QUEUED", label: "Queued", detail: "Waiting for a worker" },
  { status: "CLONING", label: "Clone", detail: "Shallow clone into an ephemeral sandbox" },
  { status: "ANALYZING_STATIC", label: "Static Pass", detail: "Secrets, packages, injection sinks" },
  { status: "ANALYZING_LLM", label: "Semantic Pass", detail: "Auth and logic review of extracted routes" },
];

export function ScanProgress({ scan }: { scan: Scan }) {
  const stages = STAGES.filter((s) => s.status !== "CLONING" || scan.source_type === "GITHUB");
  const current = Math.max(0, stages.findIndex((s) => s.status === scan.status));
  const pct = scan.progress?.percentage ?? 0;

  return (
    <div className="mx-auto max-w-[720px] px-4 py-12 sm:px-6">
      <div className="border-2 border-hairline bg-carbon">
        <div className="border-b-2 border-hairline px-5 py-5 sm:px-6">
          <p className="stamp text-[12px] text-ash">Scanning</p>
          <h1 className="stamp mt-1 truncate text-[24px]">{shortTarget(scan.target)}</h1>
        </div>

        <div className="px-5 py-6 sm:px-6">
          <div
            className="h-4 border-2 border-hairline"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={pct}
            aria-label="Scan progress"
          >
            <div className="h-full bg-bone transition-[width] duration-300 ease-linear" style={{ width: `${pct}%` }} />
          </div>
          <p className="code mt-2 flex justify-between text-ash">
            <span>{scan.progress?.step.replaceAll("_", " ").toLowerCase() ?? "starting"}</span>
            <span>{pct}%</span>
          </p>

          <ol className="mt-6 space-y-3">
            {stages.map((stage, i) => {
              const done = i < current;
              const active = i === current;
              return (
                <li
                  key={stage.status}
                  className={cn(
                    "flex items-center gap-4 border-2 p-3",
                    active ? "border-bone" : done ? "border-secure/50" : "border-hairline opacity-50",
                  )}
                  aria-current={active ? "step" : undefined}
                >
                  <span
                    className={cn(
                      "grid h-7 w-7 shrink-0 place-items-center border-2 font-heading text-[12px] font-extrabold",
                      done ? "border-secure bg-secure text-obsidian" : active ? "border-bone" : "border-hairline",
                    )}
                  >
                    {done ? <Check size={14} strokeWidth={3} aria-hidden /> : i + 1}
                  </span>
                  <span>
                    <span className="stamp block text-[13px]">{stage.label}</span>
                    <span className="block text-[13px] text-ash">{stage.detail}</span>
                  </span>
                  {active && <span aria-hidden className="ml-auto h-2.5 w-2.5 animate-pulse bg-bone" />}
                </li>
              );
            })}
          </ol>
        </div>
      </div>
    </div>
  );
}
