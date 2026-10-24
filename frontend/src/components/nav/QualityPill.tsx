import { cn } from "@/lib/format";
import { gradeTone } from "@/lib/quality";
import type { QualityGrade } from "@/lib/types";

const TONE = {
  secure: "border-secure bg-grad-secure text-secure",
  neutral: "border-hairline text-bone",
  risk: "border-risk bg-grad-risk text-risk",
} as const;

/** Code Quality Score + letter grade, the sibling of the security ScorePill. */
export function QualityPill({ score, grade }: { score: number | null; grade: QualityGrade | null }) {
  return (
    <div
      className={cn("flex h-10 items-center gap-2.5 border-2 px-3", TONE[gradeTone(grade)])}
      aria-label={score === null ? "Code quality not measured" : `Code quality ${score} of 100, grade ${grade}`}
    >
      <span className="stamp hidden text-[11px] text-ash md:inline">Quality</span>
      <span className="font-heading text-[20px] font-extrabold tabular-nums leading-none">
        {score ?? "--"}
      </span>
      {grade && (
        <span className="grid h-6 min-w-6 place-items-center border-2 border-current px-1 font-heading text-[12px] font-extrabold leading-none">
          {grade}
        </span>
      )}
    </div>
  );
}
