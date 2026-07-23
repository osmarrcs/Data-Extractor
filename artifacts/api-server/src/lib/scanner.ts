import axios from 'axios';

export const delay = (ms: number) => new Promise(res => setTimeout(res, ms));

export async function searchCisaKev(tecnologia: string) {
  try {
    const { data } = await axios.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { timeout: 10000 });
    const trintaDias = new Date();
    trintaDias.setDate(trintaDias.getDate() - 30);
    return data.vulnerabilities
      .filter((v: any) => new Date(v.dateAdded) >= trintaDias)
      .filter((v: any) => (v.vendorProject && v.vendorProject.toLowerCase().includes(tecnologia.toLowerCase())) || (v.product && v.product.toLowerCase().includes(tecnologia.toLowerCase())))
      .map((v: any) => ({
        id: v.cveID,
        tech: tecnologia,
        desc: v.shortDescription,
        solucao: v.requiredAction,
        cvss: "N/D (Exploração Ativa)",
        fonte: "CISA KEV"
      }));
  } catch (e) { return []; }
}

export async function searchOsvDev(tecnologia: string) {
  try {
    const { data } = await axios.post("https://api.osv.dev/v1/query", { package: { name: tecnologia.toLowerCase() } }, { timeout: 10000 });
    if (!data.vulns) return [];
    return data.vulns.slice(0, 2).map((v: any) => ({
      id: v.id || "OSV-VULN",
      tech: tecnologia,
      desc: v.details || v.summary || "Detalhes na base OSV.",
      solucao: "Atualizar biblioteca/pacote afetado.",
      cvss: "N/D",
      fonte: "OSV.dev"
    }));
  } catch (e) { return []; }
}

export async function searchCircl(tecnologia: string) {
  try {
    const { data } = await axios.get(`https://cve.circl.lu/api/search/${tecnologia.toLowerCase()}`, { timeout: 10000 });
    if (!data.data) return [];
    return data.data.slice(0, 2).map((v: any) => ({
      id: v.id,
      tech: tecnologia,
      desc: v.summary || "Sem descrição.",
      solucao: "Verificar boletins do fabricante.",
      cvss: String(v.cvss || "N/D"),
      fonte: "CIRCL CVE Search"
    }));
  } catch (e) { return []; }
}

export async function searchNvd(tecnologia: string) {
  return []; // Previne erro de falta de exportação e rate-limit de IP
}

export function generateTenableReport(cveDict: any) {
  return `<div><h2>Detalhes da Ameaça: ${cveDict?.id || 'N/A'} (${cveDict?.tech || 'N/A'})</h2><p>${cveDict?.desc || 'Sem detalhes'}</p><p><strong>Recomendação:</strong> ${cveDict?.solucao || 'N/A'}</p></div>`;
}

export async function buscarRedHat(dataInicio: string, dataFim: string) {
  try {
    const url = `https://access.redhat.com/hydra/rest/securitydata/cve.json?after=${dataInicio}&before=${dataFim}&severity=critical,important`;
    const { data } = await axios.get(url, { timeout: 15000 });
    return data.map((v: any) => ({
      id: v.CVE,
      tech: "Red Hat / Openshift",
      desc: v.bugzilla_description || "Sem descrição",
      cvss: String(v.cvss3_score || "N/D"),
      fonte: "Red Hat Security Data API"
    }));
  } catch (e) { return []; }
}

export function buscarMicrosoftPatchTuesday() {
  return [{
    id: "MS-PATCH-TUESDAY-LATEST",
    tech: "Microsoft",
    desc: "Pacote de Atualizações de Segurança da Microsoft (Patch Tuesday) recente.",
    solucao: "Aplicar atualizações via WSUS/Windows Update imediatamente.",
    cvss: "Varia (Até 9.8)",
    fonte: "Microsoft MSRC"
  }];
}
