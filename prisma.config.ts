import dotenv from "dotenv";
import { defineConfig, env } from "prisma/config";

// Load .env before evaluating prisma config so env(...) resolves during module load
dotenv.config({ path: ".env" });

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  engine: "classic",
  datasource: {
    url: env("DATABASE_URL"),
  },
});
