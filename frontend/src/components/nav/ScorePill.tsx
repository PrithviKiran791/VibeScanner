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
      aria-label={score === null ? "Hardening score pending" : `Hardening score ${score} of 100`}
    >
      <span className="stamp text-[11px] text-ash">Score</span>
      <span className="font-heading text-[20px] font-extrabold tabular-nums leading-none">
        {score ?? "--"}
      </span>
    </div>
  );
}
