import { pgTable, text, serial, timestamp, integer, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const scansTable = pgTable("scans", {
  id: serial("id").primaryKey(),
  status: text("status").notNull().default("em_andamento"), // em_andamento | pausado | concluido | erro
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  technologies: text("technologies").array().notNull().default([]),
  totalFound: integer("total_found").notNull().default(0),
  // Progress tracking
  progress: integer("progress").notNull().default(0),       // index of current tech
  totalTechs: integer("total_techs").notNull().default(0),  // total techs to scan
  currentTech: text("current_tech"),                        // name of tech being scanned
  paused: boolean("paused").notNull().default(false),
});

export const insertScanSchema = createInsertSchema(scansTable).omit({ id: true, startedAt: true });
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;
