"use server";

import { prisma } from "@/lib/db";

export async function deleteProject(projectId: string) {
  await prisma.project.delete({ where: { id: projectId } });
}
