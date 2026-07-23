import axios from 'axios';

const delay = (ms: number) => new Promise(res => setTimeout(res, ms));

export async function buscarCisaKev(tecnologia: string) {
  try {
    const { data } = await axios.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { timeout: 10000 });
    const trintaDiasAtras = new Date();
    trintaDiasAtras.setDate(trintaDiasAtras.getDate() - 30);

    return data.vulnerabilities
      .filter((v: any) => new Date(v.dateAdded) >= trintaDiasAtras)
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

export async function buscarRedHat(dataInicio: string, dataFim: string) {
  try {
    const url = \`https://access.redhat.com/hydra/rest/securitydata/cve.json?after=\${dataInicio}&before=\${dataFim}&severity=critical,important\`;
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
    desc: "Pacote de Atualizações de Segurança da Microsoft (Patch Tuesday) recente. Requer validação de ambiente.",
    solucao: "Aplicar atualizações via WSUS/Windows Update imediatamente.",
    cvss: "Varia (Até 9.8)",
    fonte: "Microsoft MSRC"
  }];
}

export async function executarVarredura(alvos: string[]) {
  let resultados = [];
  resultados.push(...buscarMicrosoftPatchTuesday());

  const hoje = new Date().toISOString().split('T')[0];
  const trintaDias = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  
  for (const alvo of alvos) {
    if (alvo.toLowerCase().includes("red hat") || alvo.toLowerCase().includes("openshift")) {
      const rhData = await buscarRedHat(trintaDias, hoje);
      resultados.push(...rhData);
    } else {
      const cisa = await buscarCisaKev(alvo);
      resultados.push(...cisa);
    }
    await delay(1000); // Previne rate limit das APIs (mesma lógica do seu Python)
  }
  return resultados;
}
