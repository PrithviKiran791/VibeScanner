import { exec } from "child_process";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const { file } = await request.json();
  exec(`convert uploads/${file} -resize 50% uploads/thumb-${file}`);
  return NextResponse.json({ ok: true });
}
