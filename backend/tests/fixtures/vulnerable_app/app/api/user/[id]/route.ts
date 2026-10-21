import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const user = await prisma.user.findUnique({ where: { id: params.id } });
  return NextResponse.json(user);
}
