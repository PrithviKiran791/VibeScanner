import { Check } from "lucide-react";

import { AppIcon, type AppIconName } from "@/components/ui/AppIcon";
import { Spinner } from "@/components/ui/spinner";
import { Progress } from "@/components/ui/progress";
import { cn, shortTarget } from "@/lib/format";
import type { Scan, ScanStatus } from "@/lib/types";

const STAGES: { status: ScanStatus; label: string; detail: string; icon: AppIconName }[] = [
  { status: "QUEUED", label: "Queued", detail: "Waiting for a worker", icon: "scanner" },
  { status: "CLONING", label: "Clone", detail: "Shallow clone into an ephemeral sandbox", icon: "clone" },
  { status: "ANALYZING_STATIC", label: "Static Pass", detail: "Secrets, packages, injection sinks", icon: "staticPass" },
  { status: "ANALYZING_LLM", label: "Semantic Pass", detail: "Auth and logic review of extracted routes", icon: "semanticPass" },
];

export function ScanProgress({ scan }: { scan: Scan }) {
  const stages = STAGES.filter((s) => s.status !== "CLONING" || scan.source_type === "GITHUB");
  const current = Math.max(0, stages.findIndex((s) => s.status === scan.status));
  const pct = scan.progress?.percentage ?? 0;

  return (
    <div className="mx-auto max-w-[720px] px-4 py-12 sm:px-6">
      <div className="border-2 border-hairline bg-carbon">
        <div className="flex items-center justify-between border-b-2 border-hairline px-5 py-5 sm:px-6">
          <div>
            <p className="stamp text-[12px] text-ash">Scanning</p>
            <h1 className="stamp mt-1 truncate text-[24px]">{shortTarget(scan.target)}</h1>
          </div>
          <AppIcon name="scanner" size={32} alt="Scanner" />
        </div>

        <div className="px-5 py-6 sm:px-6">
          <Progress value={pct} className="w-full" />
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
                      "grid h-8 w-8 shrink-0 place-items-center border-2 font-heading text-[12px] font-extrabold",
                      done ? "border-secure bg-secure text-obsidian" : active ? "border-bone bg-carbon" : "border-hairline",
                    )}
                  >
                    {done ? (
                      <AppIcon name="success" size={16} alt="Completed" />
                    ) : (
                      <AppIcon name={stage.icon} size={16} alt={stage.label} />
                    )}
                  </span>
                  <div className="flex-1 min-w-0">
                    <span className="stamp block text-[13px]">{stage.label}</span>
                    <span className="block truncate text-[13px] text-ash">{stage.detail}</span>
                  </div>
                  {active && <Spinner className="ml-auto size-4 text-secure" />}
                </li>
              );
            })}
          </ol>
        </div>
      </div>
    </div>
  );
}
