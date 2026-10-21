import { describe, expect, it } from "vitest";

import { diffStats, parseUnifiedDiff } from "./diff";

const DIFF = [
  "--- a/app/api/search/route.ts",
  "+++ b/app/api/search/route.ts",
  "@@ -4,3 +4,3 @@",
  " export async function GET(request: Request) {",
  "-  const { rows } = await db.query(`SELECT ${q}`);",
  '+  const { rows } = await db.query("SELECT $1", [q]);',
  "   return NextResponse.json(rows);",
  "",
].join("\n");

describe("parseUnifiedDiff", () => {
  it("numbers lines from the hunk header and drops file headers", () => {
    const rows = parseUnifiedDiff(DIFF);
    expect(rows.map((r) => r.kind)).toEqual(["hunk", "ctx", "del", "add", "ctx"]);
    expect(rows[1]).toMatchObject({ oldNo: 4, newNo: 4 });
    expect(rows[2]).toMatchObject({ oldNo: 5, newNo: null });
    expect(rows[3]).toMatchObject({ oldNo: null, newNo: 5 });
    expect(rows[4]).toMatchObject({ oldNo: 6, newNo: 6, text: "  return NextResponse.json(rows);" });
  });

  it("handles CRLF diffs and multiple hunks", () => {
    const crlf = "@@ -1 +1 @@\r\n-a\r\n+b\r\n@@ -9,1 +9,2 @@\r\n x\r\n+y\r\n";
    const rows = parseUnifiedDiff(crlf);
    expect(rows.filter((r) => r.kind === "hunk")).toHaveLength(2);
    expect(rows.at(-1)).toMatchObject({ kind: "add", text: "y", newNo: 10 });
    expect(diffStats(rows)).toEqual({ added: 2, removed: 1 });
  });

  it("returns nothing for an empty diff", () => {
    expect(parseUnifiedDiff("")).toEqual([]);
  });
});
