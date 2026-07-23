import requests
import json
import time
from datetime import datetime, timedelta

DB_FILE = 'historico_cves_tenable.json'

def load_db():
    try:
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"processadas": [], "adiadas": []}

def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=2)

AMBIENTES = (
    'Fortigate', 'Fortinet Manager', 'Fortinet Analiser', 'Fortinet EMS',
    'Cisco Antispam', 'Senha Segura PAM', 'F5 Big IP WAF', 'AWS', 'Openshift', 'Microsoft', 'VMware',
    'Network Devices', 'Operating Systems', 'Cloud Platforms', 'Virtualization Software',
    'Git', 'Ansible', 'Kubernetes', 'CI/CD Tools', 'Containers', 'Orchestration Platforms',
    'Oracle', 'PostgreSQL', 'MySQL', 'SQL Server', 'MongoDB', 'Redis',
    'Google Chrome', 'Mozilla Firefox', 'Microsoft Edge', 'Safari', 'Brave', 'Opera',
    'WinZip', '7-Zip', 'OBS Studio', 'Docker', 'Visual Studio Code', 'JetBrains IDEs', 'npm', 'Python Packages',
    'Development Tools', 'Productivity Software', 'File Archivers', 'Streaming Software'
)

def buscar_redhat_cve(tecnologia):
    """Busca CVEs específicos da Red Hat"""
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?keyword={tecnologia}&per_page=5"
    resultados = []
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            for item in resp.json():
                cve_id = item.get("CVE")
                severity = item.get("severity", "Desconhecida")
                public_date = item.get("public_date", "")[:10]
                details = item.get("bugzilla_description", "Sem descrição disponível.")
                
                severidades = {
                    "Critical": "Crítico",
                    "Important": "Alto",
                    "Moderate": "Médio",
                    "Low": "Baixo"
                }
                severidade_pt = severidades.get(severity, severity)

                resultados.append({
                    "cve": cve_id,
                    "fonte": "Red Hat Security Data",
                    "severidade": severidade_pt,
                    "data_publicacao": public_date,
                    "descricao_pt": f"Impacto técnico (Red Hat): {details}",
                    "recomendacao": "Aplicar errata de segurança RHSA correspondente através do gerador de pacotes da distribuição (yum/dnf update)."
                })
    except Exception:
        pass
    return resultados

def buscar_microsoft_patch_tuesday():
    """Busca os boletins do Microsoft Patch Tuesday (MSRC API)"""
    resultados = []
    url = "https://api.msrc.microsoft.com/cvrf/v2.0/updates"
    try:
        resp = requests.get(url, headers={"Accept": "application/json"}, timeout=10)
        if resp.status_code == 200:
            updates = resp.json().get("value", [])
            for up in updates[:3]:
                id_doc = up.get("ID")
                titulo = up.get("Alias")
                data_release = up.get("InitialReleaseDate", "")[:10]
                
                resultados.append({
                    "cve": id_doc,
                    "fonte": "Microsoft Patch Tuesday",
                    "severidade": "Crítico / Alto",
                    "data_publicacao": data_release,
                    "descricao_pt": f"Pacote de Atualizações de Segurança da Microsoft (Patch Tuesday): {titulo}",
                    "recomendacao": "Aplicar atualizações via Windows Update / WSUS imediatamente."
                })
    except Exception:
        pass
    return resultados

class VarreduraController:
    def __init__(self, tecnologias):
        self.tecnologias = tecnologias
        self.pausado = False
        self.cancelado = False

    def alternar_pausa(self):
        self.pausado = not self.pausado
        estado = "Pausado" if self.pausado else "Em Andamento"
        print(f"\n[STATUS DA VARREDURA]: {estado}")

    def executar(self):
        total = len(self.tecnologias) + 1
        resultados_finais = []
        inicio_tempo = time.time()

        print(f"Iniciando varredura em {total} alvos...")

        m_results = buscar_microsoft_patch_tuesday()
        resultados_finais.extend(m_results)

        for index, tech in enumerate(self.tecnologias, start=1):
            if self.cancelado:
                print("\n[VARREDURA CANCELADA pelo usuário]")
                break

            while self.pausado:
                time.sleep(1)

            tempo_decorrido = time.time() - inicio_tempo
            tempo_medio = tempo_decorrido / index if index > 0 else 1
            estimativa_restante = int(tempo_medio * (total - index))
            
            porcentagem = int((index / total) * 100)
            barra = "█" * (porcentagem // 5) + "-" * (20 - (porcentagem // 5))

            print(f"\rProgresso: [{barra}] {porcentagem}% | Item {index}/{total}: {tech} | Est. Restante: {estimativa_restante}s", end="")

            rh_results = buscar_redhat_cve(tech)
            resultados_finais.extend(rh_results)

            time.sleep(0.3)

        print("\n\n=== Varredura Concluída com Sucesso! ===")
        return resultados_finais

def gerar_relatorio_portugues(vulnerabilidades):
    relatorio = []
    relatorio.append("=======================================================")
    relatorio.append("       BOLETIM TÉCNICO DE SEGURANÇA E VULNERABILIDADES")
    relatorio.append(f"       Data de Emissão: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    relatorio.append("=======================================================\n")

    if not vulnerabilidades:
        relatorio.append("Nenhuma vulnerabilidade crítica encontrada para os ativos mapeados.")
    else:
        for idx, item in enumerate(vulnerabilidades, 1):
            relatorio.append(f"[{idx}] IDENTIFICADOR: {item.get('cve')}")
            relatorio.append(f"    Origem / Fonte: {item.get('fonte')}")
            relatorio.append(f"    Classificação de Severidade: {item.get('severidade')}")
            relatorio.append(f"    Data de Publicação: {item.get('data_publicacao')}")
            relatorio.append(f"    Detalhes Técnicos: {item.get('descricao_pt')}")
            relatorio.append(f"    Ações de Mitigação: {item.get('recomendacao')}")
            relatorio.append("-" * 55)

    texto_final = "\n".join(relatorio)
    
    with open("relatorio_seguranca.txt", "w", encoding="utf-8") as f:
        f.write(texto_final)
        
    return texto_final

if __name__ == '__main__':
    controlador = VarreduraController(AMBIENTES)
    resultados = controlador.executar()
    gerar_relatorio_portugues(resultados)
