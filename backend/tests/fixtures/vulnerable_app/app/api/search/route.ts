import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET(request: Request) {
  const q = new URL(request.url).searchParams.get("q") ?? "";
  const { rows } = await db.query(`SELECT id, title FROM posts WHERE title LIKE '%${q}%' LIMIT 20`);
  return NextResponse.json(rows);
}
