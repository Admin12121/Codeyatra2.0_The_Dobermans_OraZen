import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "@/db/schema";

// PostgreSQL connection via postgres driver
// Connection is shared with Rust API - DO NOT run migrations from here
const connectionString = process.env.DATABASE_URL!;

// For query purposes (used by Drizzle ORM)
const queryClient = postgres(connectionString, {
  max: 10,
  idle_timeout: 20,
  connect_timeout: 10,
});

// Drizzle instance with schema
export const db = drizzle(queryClient, { schema });

// Export types for use in other files
export type Database = typeof db;
