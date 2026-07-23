import { Router, type IRouter } from "express";
import { eq, desc } from "drizzle-orm";
import { db, scansTable, vulnerabilitiesTable } from "@workspace/db";
import { GetScanParams, CreateScanBody } from "@workspace/api-zod";
import {
  searchCisaKev,
  searchOsvDev,
  searchCircl,
  searchNvd,
  searchRedHat,
  searchMicrosoftPatchTuesday,
} from "../lib/scanner";
import { logger } from "../lib/logger";

const router: IRouter = Router();

// ─── GET /scans ───────────────────────────────────────────────────────────────
router.get("/scans", async (_req, res): Promise<void> => {
  const scans = await db.select().from(scansTable).orderBy(desc(scansTable.startedAt));
  res.json(scans.map(serializeScan));
});

// ─── POST /scans ──────────────────────────────────────────────────────────────
router.post("/scans", async (req, res): Promise<void> => {
  const body = CreateScanBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const [scan] = await db
    .insert(scansTable)
    .values({
      status: "em_andamento",
      technologies: body.data.technologies,
      totalFound: 0,
      progress: 0,
      totalTechs: body.data.technologies.length,
      paused: false,
    })
    .returning();

  runScan(scan.id, body.data.technologies).catch((err) => {
    logger.error({ err, scanId: scan.id }, "Scan failed unexpectedly");
  });

  res.status(201).json(serializeScan(scan));
});

// ─── GET /scans/:id ───────────────────────────────────────────────────────────
router.get("/scans/:id", async (req, res): Promise<void> => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, params.data.id));
  if (!scan) {
    res.status(404).json({ error: "Varredura não encontrada" });
    return;
  }
  res.json(serializeScan(scan));
});

// ─── PATCH /scans/:id/pause ───────────────────────────────────────────────────
router.patch("/scans/:id/pause", async (req, res): Promise<void> => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, params.data.id));
  if (!scan) {
    res.status(404).json({ error: "Varredura não encontrada" });
    return;
  }
  if (scan.status !== "em_andamento") {
    res.status(400).json({ error: "Apenas varreduras em andamento podem ser pausadas" });
    return;
  }
  const [updated] = await db
    .update(scansTable)
    .set({ paused: true, status: "pausado" })
    .where(eq(scansTable.id, params.data.id))
    .returning();
  res.json(serializeScan(updated));
});

// ─── PATCH /scans/:id/resume ──────────────────────────────────────────────────
router.patch("/scans/:id/resume", async (req, res): Promise<void> => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, params.data.id));
  if (!scan) {
    res.status(404).json({ error: "Varredura não encontrada" });
    return;
  }
  if (scan.status !== "pausado") {
    res.status(400).json({ error: "Apenas varreduras pausadas podem ser retomadas" });
    return;
  }
  const [updated] = await db
    .update(scansTable)
    .set({ paused: false, status: "em_andamento" })
    .where(eq(scansTable.id, params.data.id))
    .returning();

  // Resume the scan from the last progress point
  resumeScan(scan.id, scan.technologies ?? [], scan.progress ?? 0).catch((err) => {
    logger.error({ err, scanId: scan.id }, "Scan resume failed unexpectedly");
  });

  res.json(serializeScan(updated));
});

// ─── Scan engine ─────────────────────────────────────────────────────────────
async function runScan(scanId: number, technologies: string[], startIndex = 0): Promise<void> {
  try {
    logger.info({ scanId, count: technologies.length, startIndex }, "Starting scan");

    const existing = await db
      .select({ cveId: vulnerabilitiesTable.cveId })
      .from(vulnerabilitiesTable);
    const processedIds = new Set(existing.map((e) => e.cveId));
    const seen = new Set<string>();
    let totalFound = 0;

    // Count already-found for this scan
    const alreadyFound = await db
      .select({ id: vulnerabilitiesTable.id })
      .from(vulnerabilitiesTable)
      .where(eq(vulnerabilitiesTable.scanId, scanId));
    totalFound = alreadyFound.length;

    for (let i = startIndex; i < technologies.length; i++) {
      const tech = technologies[i];

      // Check if paused before each tech
      const [current] = await db.select({ paused: scansTable.paused }).from(scansTable).where(eq(scansTable.id, scanId));
      if (current?.paused) {
        logger.info({ scanId, tech }, "Scan paused");
        return; // Stop here; resume will restart from this index
      }

      // Update progress
      await db
        .update(scansTable)
        .set({ progress: i, currentTech: tech })
        .where(eq(scansTable.id, scanId));

      const results = [
        ...(await searchCisaKev(tech)),
        ...(await searchOsvDev(tech)),
        ...(await searchCircl(tech)),
        ...(await searchNvd(tech)),
        ...(await searchRedHat(tech)),
        ...(await searchMicrosoftPatchTuesday(tech)),
      ];

      for (const cve of results) {
        if (!cve.id || processedIds.has(cve.id) || seen.has(cve.id)) continue;
        seen.add(cve.id);
        await db.insert(vulnerabilitiesTable).values({
          cveId: cve.id,
          tech: cve.tech,
          description: cve.desc,
          solution: cve.solution,
          cvss: cve.cvss,
          source: cve.source,
          status: "pendente",
          scanId,
        });
        totalFound++;
        await db.update(scansTable).set({ totalFound }).where(eq(scansTable.id, scanId));
      }
    }

    await db
      .update(scansTable)
      .set({ status: "concluido", completedAt: new Date(), totalFound, progress: technologies.length, currentTech: null })
      .where(eq(scansTable.id, scanId));

    logger.info({ scanId, totalFound }, "Scan completed");
  } catch (err) {
    logger.error({ err, scanId }, "Scan error");
    await db
      .update(scansTable)
      .set({ status: "erro", completedAt: new Date() })
      .where(eq(scansTable.id, scanId));
  }
}

async function resumeScan(scanId: number, technologies: string[], fromIndex: number): Promise<void> {
  await runScan(scanId, technologies, fromIndex);
}

// ─── Serializer ───────────────────────────────────────────────────────────────
function serializeScan(s: typeof scansTable.$inferSelect) {
  return {
    id: s.id,
    status: s.status,
    startedAt: s.startedAt instanceof Date ? s.startedAt.toISOString() : String(s.startedAt),
    completedAt: s.completedAt instanceof Date ? s.completedAt.toISOString() : (s.completedAt ? String(s.completedAt) : null),
    technologies: s.technologies ?? [],
    totalFound: s.totalFound,
    progress: s.progress ?? 0,
    totalTechs: s.totalTechs ?? (s.technologies?.length ?? 0),
    currentTech: s.currentTech ?? null,
    paused: s.paused ?? false,
  };
}

export default router;
