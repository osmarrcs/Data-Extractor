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

// ─── Relatório HTML estilo Tenable One (segue template original do usuário) ──
export function generateTenableReport(vuln: {
  cveId: string;
  tech: string;
  source: string;
  description: string;
  solution: string;
  cvss: string;
}): string {
  const cvssFloat = parseFloat(vuln.cvss);
  let corCvss = "#e53935";
  let sugestao = "Monitorar e Planejar Atualização";

  if (!isNaN(cvssFloat)) {
    if (cvssFloat >= 9.0) { sugestao = "Ação Emergencial Recomendada"; corCvss = "#e53935"; }
    else if (cvssFloat >= 7.0) { sugestao = "Aplicar Correção na próxima janela"; corCvss = "#f4511e"; }
    else if (cvssFloat >= 4.0) { sugestao = "Planejar atualização no próximo ciclo"; corCvss = "#f9a825"; }
    else { corCvss = "#4caf50"; }
  }

  return `<div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #333; line-height: 1.5; max-width: 900px; margin: 20px auto; border: 1px solid #e0e0e0; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); background-color: #fff;">
    <h1 style="font-size: 24px; color: #1a1a1a; border-bottom: 1px solid #eaeaea; padding-bottom: 15px; margin-top: 0;">Modelos de Relatório &#128438;</h1>

    <p style="font-size: 14px;">O Tenable One Vulnerability Management fornece uma seleção de modelos de relatório e formatos de relatório personalizáveis. Você pode configurar um modelo de relatório fornecido pela Tenable ou criar um relatório totalmente personalizado a partir de um dos formatos disponíveis.</p>
    <p style="font-size: 14px;">Para um índice completo dos modelos de relatório fornecidos pela Tenable, consulte <a href="#" style="color: #007bc1; text-decoration: none;">Modelos de Relatório do Tenable One Vulnerability Management</a>.</p>

    <div style="background-color: #eaffea; border-left: 4px solid #00d282; padding: 12px 15px; margin: 20px 0; font-size: 13px;">
        <p style="margin: 0;"><strong>Dica:</strong> Para obter mais informações sobre os dados específicos incluídos em cada relatório individual, consulte <a href="#" style="color: #007bc1; text-decoration: none;">Exibir Detalhes do Relatório</a>.</p>
    </div>

    <div style="background-color: #f4f8fd; border-left: 4px solid #007bc1; padding: 15px; margin: 20px 0; font-size: 13px;">
        <p style="margin-top: 0;">Nota: O <strong>Relatório de Seguro Cibernético</strong> inclui as seguintes ressalvas:</p>
        <ul style="padding-left: 20px; margin-bottom: 10px;">
            <li style="margin-bottom: 6px;">O relatório não pode ser editado de forma alguma. Isso garante que os subscritores possam ter certeza de que suas métricas são 100% precisas.</li>
            <li style="margin-bottom: 6px;">Este relatório inclui apenas dados do Explore dos últimos 180 dias.</li>
            <li style="margin-bottom: 6px;">Este relatório está disponível apenas para clientes com relatórios do Explore habilitados em seu contêiner.</li>
            <li style="margin-bottom: 6px;">O nome do relatório não muda nas gerações subsequentes do relatório. Por exemplo, o carimbo de data/hora no nome do relatório não é atualizado na próxima vez que você executar o relatório, no entanto, os dados do relatório em si incluem a data em que o relatório foi executado mais recentemente.</li>
            <li>As severidades são relatadas usando apenas pontuações base CVSSv3.</li>
        </ul>
        <p style="margin-bottom: 0;">Para mais informações, consulte a postagem do blog <a href="#" style="color: #007bc1; text-decoration: none;">Relatório de Seguro Cibernético</a>.</p>
    </div>

    <div style="margin: 30px 0; padding: 20px; border: 1px solid #dcdcdc; border-radius: 4px; background-color: #fbfbfb;">
        <h2 style="font-size: 18px; margin-top: 0; color: #005a8c;">Detalhes da Ameaça: ${vuln.cveId} (${vuln.tech})</h2>
        <p style="font-size: 14px;"><strong>Fonte de Inteligência:</strong> ${vuln.source}</p>
        <p style="font-size: 14px;"><strong>Descrição:</strong> ${vuln.description}</p>
        <p style="font-size: 14px;"><strong>Mitigação Sugerida:</strong> ${vuln.solution}</p>
        <p style="font-size: 14px;"><strong>Base Score CVSSv3:</strong> <span style="background-color: ${corCvss}; color: #fff; padding: 2px 6px; border-radius: 3px; font-weight: bold;">${vuln.cvss}</span></p>
        <p style="font-size: 14px;"><strong>Ação Recomendada:</strong> <em>${sugestao}</em></p>
    </div>

    <hr style="border: 0; border-top: 1px solid #eaeaea; margin: 30px 0;">

    <p style="font-size: 14px;">Você pode compartilhar modelos de relatório com outros usuários dentro da organização.</p>
    <p style="font-size: 14px;">Para compartilhar modelos de relatório:</p>
    <ol style="font-size: 14px; padding-left: 20px;">
        <li style="margin-bottom: 10px;">Na navegação à esquerda, clique em <strong>&#128196; Relatórios</strong>.<br>A página Relatórios é exibida.</li>
        <li>Selecione os modelos de relatório que você deseja compartilhar:</li>
    </ol>

    <table style="width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px;">
        <thead>
            <tr style="background-color: #1a2228; color: #fff;">
                <th style="padding: 12px; text-align: left; border: 1px solid #1a2228; width: 25%;">Escopo</th>
                <th style="padding: 12px; text-align: left; border: 1px solid #1a2228; width: 75%;">Ação</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td style="padding: 15px; border: 1px solid #ddd; vertical-align: top; background-color: #fafafa;">Compartilhar um único relatório</td>
                <td style="padding: 15px; border: 1px solid #ddd; vertical-align: top;">
                    <p style="margin-top: 0;">Para compartilhar modelos de relatório a partir da página <strong>Relatórios</strong>:</p>
                    <ol type="a" style="padding-left: 20px;">
                        <li style="margin-bottom: 12px;">
                            Na guia <strong>Meus Modelos de Relatório</strong>, clique com o botão direito na linha do modelo de relatório que você deseja compartilhar.<br><br>
                            -ou-<br><br>
                            Na guia <strong>Meus Modelos de Relatório</strong>, na coluna <strong>Ações</strong>, clique no botão <strong>&#8942;</strong> na linha do modelo de relatório que deseja compartilhar.<br>
                            Os botões de ação aparecem na linha.<br><br>
                            -ou-<br><br>
                            Na guia <strong>Meus Modelos de Relatório</strong>, marque a caixa de seleção ao lado do modelo de relatório que você deseja compartilhar.<br>
                            Na barra de ações, o Tenable One Vulnerability Management habilita <strong>Mais > Compartilhar</strong>.
                        </li>
                        <li>Clique em <strong>&#10150; Compartilhar</strong>.</li>
                    </ol>
                    <p style="margin-bottom: 0;">O painel Compartilhar aparece.</p>
                    <div style="border: 1px solid #e0e0e0; padding: 15px; margin-top: 15px; border-radius: 4px; background-color: #fff; width: 250px;">
                        <strong style="display:block; margin-bottom: 10px;">Compartilhar</strong>
                        <p style="font-size: 11px; color: #666; margin-bottom: 15px; background-color: #e6f2f9; padding: 8px; border-left: 3px solid #007bc1;">
                            Cuidado: Você está compartilhando um modelo de relatório com um usuário que pode usá-lo para gerar relatórios. Quaisquer alterações feitas no modelo não refletirão no modelo compartilhado.
                        </p>
                        <span style="font-size: 10px; color: #888; text-transform: uppercase;">SELECIONAR USUÁRIOS OU GRUPOS</span><br>
                        <label style="font-size: 12px;"><input type="checkbox" checked> Todos os Usuários</label><br>
                        <input type="text" placeholder="Pesquisar por usuário ou nome do grupo" style="width: 100%; padding: 5px; margin-top: 5px; border: 1px solid #ccc; border-radius: 3px; font-size: 12px;">
                    </div>
                </td>
            </tr>
        </tbody>
    </table>

    <ol start="3" style="font-size: 14px; padding-left: 20px;">
        <li style="margin-bottom: 10px;">Na seção <strong>Selecionar Usuários ou Grupos</strong>, selecione <strong>Todos os Usuários</strong> ou pesquise usuários ou grupos específicos.</li>
        <li style="margin-bottom: 10px;">Clique em <strong>Compartilhar</strong>.</li>
    </ol>
    <p style="font-size: 14px; color: #555;">O Tenable One Vulnerability Management compartilha o modelo de relatório com os usuários que podem visualizá-los na guia <strong>Modelos de Relatório Compartilhados</strong>. Cada usuário recebe uma notificação por e-mail com detalhes do relatório compartilhado, o endereço de e-mail do remetente e um link para o relatório compartilhado.</p>
</div>`;
}
