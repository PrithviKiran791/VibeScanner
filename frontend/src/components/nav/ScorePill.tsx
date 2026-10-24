import { cn, scoreBand } from "@/lib/format";

const BAND = {
  secure: "border-secure bg-grad-secure text-secure",
  neutral: "border-hairline text-bone",
  risk: "border-risk bg-grad-risk text-risk",
} as const;

export function ScorePill({ score }: { score: number | null }) {
  return (
    <div
      className={cn("flex h-10 items-center gap-3 border-2 px-3", BAND[scoreBand(score)])}
      aria-label={score === null ? "Security score pending" : `Security hardening score ${score} of 100`}
    >
      <span className="stamp hidden text-[11px] text-ash md:inline">Security</span>
      <span className="font-heading text-[20px] font-extrabold tabular-nums leading-none">
        {score ?? "--"}
      </span>
    </div>
  );
}
