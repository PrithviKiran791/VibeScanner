import { Pool } from "pg";
import { PrismaClient } from "@prisma/client";

export const db = new Pool({ connectionString: process.env.DATABASE_URL });
export const prisma = new PrismaClient();
