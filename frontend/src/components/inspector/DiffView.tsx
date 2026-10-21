import { useMemo } from "react";

import { type DiffRow, diffStats, parseUnifiedDiff } from "@/lib/diff";
import { cn } from "@/lib/format";

const ROW: Record<DiffRow["kind"], string> = {
  add: "bg-grad-secure border-l-secure",
  del: "bg-grad-risk border-l-risk",
  ctx: "border-l-transparent",
  hunk: "bg-graphite border-l-transparent text-ash",
};
const SIGN: Record<DiffRow["kind"], string> = { add: "+", del: "-", ctx: " ", hunk: "" };

/** Unified diff with red (-) / green (+) industrial gradient rows. Scrolls horizontally inside its own frame. */
export function DiffView({ diff, path }: { diff: string; path: string }) {
  const rows = useMemo(() => parseUnifiedDiff(diff), [diff]);
  const { added, removed } = diffStats(rows);

  return (
    <figure className="border-2 border-hairline bg-obsidian">
      <figcaption className="flex items-center justify-between gap-3 border-b-2 border-hairline px-3 py-2">
        <span className="code truncate text-ash" title={path}>
          {path}
        </span>
        <span className="code shrink-0">
          <span className="text-secure">+{added}</span> <span className="text-risk">-{removed}</span>
        </span>
      </figcaption>
      <div className="overflow-x-auto">
        <table className="code w-full min-w-max border-collapse" aria-label={`Patch for ${path}`}>
          <tbody>
            {rows.map((row, i) =>
              row.kind === "hunk" ? (
                <tr key={i} className={ROW.hunk}>
                  <td colSpan={4} className="px-3 py-1 text-[12px]">
                    {row.text}
                  </td>
                </tr>
              ) : (
                <tr key={i} className={cn("border-l-2", ROW[row.kind])}>
                  <LineNo n={row.oldNo} />
                  <LineNo n={row.newNo} />
                  <td
                    aria-hidden
                    className={cn(
                      "w-5 select-none text-center",
                      row.kind === "add" && "text-secure",
                      row.kind === "del" && "text-risk",
                    )}
                  >
                    {SIGN[row.kind]}
                  </td>
                  <td className="whitespace-pre pr-6">
                    <span className="sr-only">
                      {row.kind === "add" ? "added: " : row.kind === "del" ? "removed: " : ""}
                    </span>
                    {row.text || " "}
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </table>
      </div>
    </figure>
  );
}

function LineNo({ n }: { n: number | null }) {
  return (
    <td className="w-[1%] select-none whitespace-nowrap px-2 text-right text-ash/50">{n ?? ""}</td>
  );
}

/** Plain code block for findings without a patch (the ±3-line snippet). */
export function SnippetView({ code, path, firstLine }: { code: string; path: string; firstLine: number }) {
  const lines = code.split("\n");
  return (
    <figure className="border-2 border-hairline bg-obsidian">
      <figcaption className="border-b-2 border-hairline px-3 py-2">
        <span className="code text-ash">{path}</span>
      </figcaption>
      <div className="overflow-x-auto">
        <table className="code w-full min-w-max border-collapse">
          <tbody>
            {lines.map((line, i) => (
              <tr key={i}>
                <LineNo n={firstLine + i} />
                <td className="whitespace-pre px-3 pr-6">{line || " "}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </figure>
  );
}
