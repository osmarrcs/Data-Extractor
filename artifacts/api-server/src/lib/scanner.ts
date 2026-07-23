import { logger } from "./logger";

export interface CveResult {
  id: string;
  tech: string;
  desc: string;
  solution: string;
  cvss: string;
  source: string;
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 14000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ─── CISA KEV ────────────────────────────────────────────────────────────────
export async function searchCisaKev(tech: string): Promise<CveResult[]> {
  const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  const results: CveResult[] = [];
  try {
    const resp = await fetchWithTimeout(url);
    if (!resp.ok) return results;
    const data = await resp.json() as { vulnerabilities?: Record<string, string>[] };
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    for (const vuln of data.vulnerabilities ?? []) {
      const dateAdded = new Date(vuln["dateAdded"] ?? "");
      if (isNaN(dateAdded.getTime()) || dateAdded < thirtyDaysAgo) continue;
      const vendor = (vuln["vendorProject"] ?? "").toLowerCase();
      const product = (vuln["product"] ?? "").toLowerCase();
      if (!vendor.includes(tech.toLowerCase()) && !product.includes(tech.toLowerCase())) continue;
      results.push({
        id: vuln["cveID"] ?? `CISA-${Date.now()}`,
        tech,
        desc: vuln["shortDescription"] ?? "Sem descrição disponível.",
        solution: vuln["requiredAction"] ?? "Aplicar correção conforme orientação do fabricante.",
        cvss: "N/D (Exploração Ativa)",
        source: "CISA KEV",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "CISA KEV fetch failed");
  }
  return results;
}

// ─── OSV.dev ─────────────────────────────────────────────────────────────────
export async function searchOsvDev(tech: string): Promise<CveResult[]> {
  const url = "https://api.osv.dev/v1/query";
  const results: CveResult[] = [];
  try {
    const resp = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: { name: tech.toLowerCase() } }),
    });
    if (!resp.ok) return results;
    const data = await resp.json() as { vulns?: Record<string, string>[] };
    for (const vuln of (data.vulns ?? []).slice(0, 2)) {
      results.push({
        id: vuln["id"] ?? "OSV-VULN",
        tech,
        desc: vuln["details"] ?? vuln["summary"] ?? "Detalhes técnicos fornecidos na base OSV.",
        solution: "Atualizar biblioteca/pacote afetado no repositório.",
        cvss: "N/D",
        source: "OSV.dev (Open Source)",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "OSV.dev fetch failed");
  }
  return results;
}

// ─── CIRCL ───────────────────────────────────────────────────────────────────
export async function searchCircl(tech: string): Promise<CveResult[]> {
  const url = `https://cve.circl.lu/api/search/${encodeURIComponent(tech.toLowerCase())}`;
  const results: CveResult[] = [];
  try {
    const resp = await fetchWithTimeout(url);
    if (!resp.ok) return results;
    const data = await resp.json() as { data?: Record<string, unknown>[] };
    for (const vuln of (data.data ?? []).slice(0, 2)) {
      results.push({
        id: String(vuln["id"] ?? ""),
        tech,
        desc: String(vuln["summary"] ?? "Sem descrição disponível."),
        solution: "Verificar boletins do fabricante.",
        cvss: String(vuln["cvss"] ?? "N/D"),
        source: "CIRCL CVE Search",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "CIRCL fetch failed");
  }
  return results;
}

// ─── NVD / NIST ──────────────────────────────────────────────────────────────
export async function searchNvd(tech: string): Promise<CveResult[]> {
  const results: CveResult[] = [];
  try {
    const hoje = new Date();
    const inicio = new Date();
    inicio.setDate(inicio.getDate() - 7);
    const params = new URLSearchParams({
      pubStartDate: inicio.toISOString().replace(/\.\d{3}Z$/, ".000Z"),
      pubEndDate: hoje.toISOString().replace(/\.\d{3}Z$/, ".000Z"),
      keywordSearch: tech,
      resultsPerPage: "2",
    });
    await new Promise((r) => setTimeout(r, 6000)); // NVD rate-limit sem token
    const resp = await fetchWithTimeout(`https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`, {}, 20000);
    if (!resp.ok) return results;
    const data = await resp.json() as { vulnerabilities?: { cve: Record<string, unknown> }[] };
    for (const item of data.vulnerabilities ?? []) {
      const cve = item.cve;
      const metrics = cve["metrics"] as Record<string, unknown> | undefined;
      let cvss = "N/D";
      if (metrics?.["cvssMetricV31"]) {
        const m = (metrics["cvssMetricV31"] as { cvssData?: { baseScore?: number } }[])[0];
        if (m?.cvssData?.baseScore != null) cvss = String(m.cvssData.baseScore);
      } else if (metrics?.["cvssMetricV30"]) {
        const m = (metrics["cvssMetricV30"] as { cvssData?: { baseScore?: number } }[])[0];
        if (m?.cvssData?.baseScore != null) cvss = String(m.cvssData.baseScore);
      }
      const descriptions = cve["descriptions"] as { lang: string; value: string }[] | undefined;
      const desc = descriptions?.find((d) => d.lang === "en")?.value ?? "Sem descrição disponível.";
      results.push({
        id: String(cve["id"] ?? ""),
        tech,
        desc,
        solution: "Aplicar atualizações de segurança fornecidas pelo fabricante ou rotacionar credenciais afetadas.",
        cvss,
        source: "NVD / NIST",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "NVD fetch failed");
  }
  return results;
}

// ─── Red Hat Security Advisory ───────────────────────────────────────────────
export async function searchRedHat(tech: string): Promise<CveResult[]> {
  const results: CveResult[] = [];
  try {
    const after = new Date();
    after.setDate(after.getDate() - 30);
    const params = new URLSearchParams({
      after: after.toISOString().split("T")[0],
      severity: "Critical,Important",
      per_page: "5",
      keyword: tech,
    });
    const resp = await fetchWithTimeout(
      `https://access.redhat.com/hydra/rest/securitydata/cve.json?${params}`
    );
    if (!resp.ok) return results;
    const data = await resp.json() as {
      CVE?: string;
      severity?: string;
      public_date?: string;
      bugzilla_description?: string;
      cvss3_score?: string;
      affected_release?: { product_name?: string }[];
      package_state?: { product_name?: string }[];
    }[];

    const techLower = tech.toLowerCase();
    for (const vuln of (Array.isArray(data) ? data : []).slice(0, 3)) {
      // Filter by relevance to technology
      const desc = vuln.bugzilla_description ?? "";
      const affected = [
        ...(vuln.affected_release ?? []).map((r) => r.product_name ?? ""),
        ...(vuln.package_state ?? []).map((r) => r.product_name ?? ""),
      ].join(" ").toLowerCase();

      if (!desc.toLowerCase().includes(techLower) && !affected.includes(techLower)) continue;

      const cvss = vuln.cvss3_score ?? "N/D";
      results.push({
        id: vuln.CVE ?? `RHSA-${Date.now()}`,
        tech,
        desc: desc || "Consultar boletim Red Hat para detalhes.",
        solution: "Aplicar errata de segurança disponível no Portal do Cliente Red Hat (access.redhat.com).",
        cvss,
        source: "Red Hat Security Advisory",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "Red Hat fetch failed");
  }
  return results;
}

// ─── Microsoft Patch Tuesday (MSRC) ─────────────────────────────────────────
export async function searchMicrosoftPatchTuesday(tech: string): Promise<CveResult[]> {
  const results: CveResult[] = [];
  try {
    // Get updates list to find the latest Patch Tuesday document
    const updatesResp = await fetchWithTimeout(
      "https://api.msrc.microsoft.com/cvrf/v2.0/updates",
      { headers: { Accept: "application/json" } }
    );
    if (!updatesResp.ok) return results;

    const updates = await updatesResp.json() as {
      value?: { ID?: string; DocumentTitle?: string; CurrentReleaseDate?: string }[];
    };

    // Get the most recent update (first in list)
    const latest = updates.value?.[0];
    if (!latest?.ID) return results;

    const cvrfResp = await fetchWithTimeout(
      `https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/${latest.ID}`,
      { headers: { Accept: "application/json" } }
    );
    if (!cvrfResp.ok) return results;

    const cvrf = await cvrfResp.json() as {
      Vulnerability?: {
        CVE?: string;
        Title?: { Value?: string };
        Notes?: { Value?: string; Title?: string }[];
        CVSSScoreSets?: { BaseScore?: number }[];
        ProductStatuses?: { ProductID?: string[] }[];
      }[];
    };

    const techLower = tech.toLowerCase();
    const vulns = cvrf.Vulnerability ?? [];

    for (const vuln of vulns) {
      const title = vuln.Title?.Value ?? "";
      const notes = vuln.Notes?.map((n) => n.Value ?? "").join(" ") ?? "";
      if (!title.toLowerCase().includes(techLower) && !notes.toLowerCase().includes(techLower)) continue;

      const cvss = String(vuln.CVSSScoreSets?.[0]?.BaseScore ?? "N/D");
      const desc = vuln.Notes?.find((n) => n.Title === "Description")?.Value
        ?? vuln.Notes?.find((n) => n.Title === "FAQ")?.Value
        ?? title
        ?? "Consultar boletim Microsoft para detalhes.";

      results.push({
        id: vuln.CVE ?? `MSRC-${Date.now()}`,
        tech,
        desc,
        solution: `Instalar atualização de segurança do Patch Tuesday de ${latest.DocumentTitle ?? latest.ID}. Acesse o Microsoft Update Catalog para obter o patch correspondente.`,
        cvss,
        source: `Microsoft Patch Tuesday (${latest.DocumentTitle ?? latest.ID})`,
      });

      if (results.length >= 3) break;
    }
  } catch (err) {
    logger.warn({ err, tech }, "Microsoft Patch Tuesday fetch failed");
  }
  return results;
}

// ─── Relatório HTML estilo Tenable (todo em português) ───────────────────────
export function generateTenableReport(vuln: {
  cveId: string;
  tech: string;
  source: string;
  description: string;
  solution: string;
  cvss: string;
}): string {
  const cvssFloat = parseFloat(vuln.cvss);
  let severidade = "Informativo";
  let corSeveridade = "#2196f3";
  let sugestao = "Monitorar e planejar atualização";

  if (vuln.cvss === "N/D (Exploração Ativa)" || cvssFloat >= 9.0) {
    severidade = "Crítico";
    corSeveridade = "#e53935";
    sugestao = "Ação emergencial recomendada — mitigar imediatamente";
  } else if (cvssFloat >= 7.0) {
    severidade = "Alto";
    corSeveridade = "#f4511e";
    sugestao = "Aplicar correção na próxima janela de manutenção";
  } else if (cvssFloat >= 4.0) {
    severidade = "Médio";
    corSeveridade = "#f9a825";
    sugestao = "Planejar atualização no próximo ciclo";
  }

  const dataAtual = new Date().toLocaleString("pt-BR", {
    day: "2-digit", month: "long", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });

  return `
<div style="font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#333;line-height:1.6;max-width:900px;margin:20px auto;border:1px solid #e0e0e0;padding:0;box-shadow:0 2px 8px rgba(0,0,0,0.08);background:#fff;border-radius:4px;overflow:hidden;">

  <!-- Cabeçalho -->
  <div style="background:#1a2228;padding:20px 30px;display:flex;align-items:center;justify-content:space-between;">
    <div>
      <div style="color:#00e5ff;font-family:monospace;font-size:11px;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:4px;">Boletim de Segurança — Tenable One</div>
      <div style="color:#fff;font-size:20px;font-weight:bold;">${vuln.cveId}</div>
      <div style="color:#90a4ae;font-size:13px;margin-top:4px;">${vuln.tech}</div>
    </div>
    <div style="background:${corSeveridade};color:#fff;font-family:monospace;font-size:13px;font-weight:bold;padding:6px 16px;border-radius:3px;text-transform:uppercase;letter-spacing:0.08em;">
      ${severidade}${!isNaN(cvssFloat) ? ` · ${vuln.cvss}` : ""}
    </div>
  </div>

  <!-- Alerta de exploração ativa -->
  ${vuln.cvss === "N/D (Exploração Ativa)" ? `
  <div style="background:#ffebee;border-left:4px solid #e53935;padding:12px 30px;font-size:13px;color:#b71c1c;">
    ⚠️ <strong>Exploração ativa confirmada pela CISA KEV.</strong> Esta vulnerabilidade está sendo ativamente explorada em ambiente real. Priorize a mitigação.
  </div>` : ""}

  <div style="padding:28px 30px;">

    <!-- Resumo executivo -->
    <div style="background:#f4f8fd;border-left:4px solid #007bc1;padding:14px 18px;margin-bottom:24px;border-radius:0 4px 4px 0;">
      <div style="font-size:11px;font-family:monospace;color:#607d8b;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;">Resumo Executivo</div>
      <p style="margin:0;font-size:14px;">${vuln.description}</p>
    </div>

    <!-- Metadados -->
    <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:24px;">
      <tr style="background:#f9f9f9;">
        <td style="padding:10px 14px;color:#555;font-weight:600;width:220px;border:1px solid #eee;">Identificador</td>
        <td style="padding:10px 14px;font-family:monospace;border:1px solid #eee;">${vuln.cveId}</td>
      </tr>
      <tr>
        <td style="padding:10px 14px;color:#555;font-weight:600;border:1px solid #eee;">Tecnologia Afetada</td>
        <td style="padding:10px 14px;border:1px solid #eee;">${vuln.tech}</td>
      </tr>
      <tr style="background:#f9f9f9;">
        <td style="padding:10px 14px;color:#555;font-weight:600;border:1px solid #eee;">Fonte de Inteligência</td>
        <td style="padding:10px 14px;border:1px solid #eee;">${vuln.source}</td>
      </tr>
      <tr>
        <td style="padding:10px 14px;color:#555;font-weight:600;border:1px solid #eee;">Pontuação CVSSv3</td>
        <td style="padding:10px 14px;border:1px solid #eee;">
          <span style="background:${corSeveridade};color:#fff;padding:3px 10px;border-radius:3px;font-weight:bold;font-size:13px;">
            ${vuln.cvss} — ${severidade}
          </span>
        </td>
      </tr>
      <tr style="background:#f9f9f9;">
        <td style="padding:10px 14px;color:#555;font-weight:600;border:1px solid #eee;">Ação Sugerida</td>
        <td style="padding:10px 14px;border:1px solid #eee;color:${corSeveridade};font-weight:600;">${sugestao}</td>
      </tr>
    </table>

    <!-- Mitigação -->
    <div style="margin-bottom:24px;">
      <div style="font-size:11px;font-family:monospace;color:#607d8b;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">Mitigação e Ações Recomendadas</div>
      <div style="background:#f4fff6;border-left:4px solid #00c853;padding:14px 18px;border-radius:0 4px 4px 0;font-size:14px;">
        ${vuln.solution}
      </div>
    </div>

  </div>

  <!-- Rodapé -->
  <div style="background:#f5f5f5;border-top:1px solid #eee;padding:14px 30px;font-size:11px;color:#888;display:flex;justify-content:space-between;align-items:center;">
    <span>Relatório gerado em ${dataAtual} — Deep Research de Vulnerabilidades (SecOps)</span>
    <span style="font-family:monospace;color:#b0bec5;">CVSSv3 Base Score · ${vuln.source}</span>
  </div>
</div>`.trim();
}
