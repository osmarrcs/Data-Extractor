import requests
import json
import time
from datetime import datetime, timedelta, timezone

# 1. Banco de Dados Local
DB_FILE = 'historico_cves_tenable.json'

def load_db():
    try:
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"processadas": [], "adiadas": []}

def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=4)

db = load_db()

# 2. Ecossistema de Ativos
AMBIENTES = [
    'Fortigate', 'Fortinet Manager', 'Fortinet Analiser', 'Fortinet EMS',
    'Cisco Antispam', 'Senha Segura PAM', 'F5 Big IP WAF', 'AWS', 'Openshift', 'Microsoft', 'VMware',
    'Network Devices', 'Operating Systems', 'Cloud Platforms', 'Virtualization Software',
    'Git', 'Ansible', 'Kubernetes', 'CI/CD Tools', 'Containers', 'Orchestration Platforms',
    'Oracle', 'PostgreSQL', 'MySQL', 'SQL Server', 'MongoDB', 'Redis',
    'Google Chrome', 'Mozilla Firefox', 'Microsoft Edge', 'Safari', 'Brave', 'Opera',
    'WinZip', '7-Zip', 'OBS Studio', 'Docker', 'Visual Studio Code', 'JetBrains IDEs', 'npm', 'Python Packages',
    'Development Tools', 'Productivity Software', 'File Archivers', 'Streaming Software',
    'Jupyter Enterprise Gateway'
]

# 3. Motores de Agregação
def buscar_cisa_kev(tecnologia):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resultados = []
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            dados = resp.json()
            for vuln in dados.get("vulnerabilities", []):
                # Simulação de filtro simples por tecnologia
                if tecnologia.lower() in vuln.get("product", "").lower():
                    resultados.append({
                        "cve": vuln.get("cveID"),
                        "fonte": "CISA KEV",
                        "severidade": "Crítico",
                        "data_publicacao": vuln.get("dateAdded"),
                        "descricao_pt": vuln.get("shortDescription", ""),
                        "recomendacao": vuln.get("requiredAction", "")
                    })
    except Exception:
        pass
    return resultados

def buscar_redhat_cve(tecnologia):
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?keyword={tecnologia}&per_page=2"
    resultados = []
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            for item in resp.json():
                severity = item.get("severity", "Desconhecida")
                severidade_pt = {"Critical": "Crítico", "Important": "Alto", "Moderate": "Médio", "Low": "Baixo"}.get(severity, severity)
                resultados.append({
                    "cve": item.get("CVE"),
                    "fonte": "Red Hat Security Data",
                    "severidade": severidade_pt,
                    "data_publicacao": item.get("public_date", "")[:10],
                    "descricao_pt": f"Impacto técnico (Red Hat): {item.get('bugzilla_description', 'N/A')}",
                    "recomendacao": "Aplicar errata de segurança RHSA correspondente."
                })
    except Exception:
        pass
    return resultados

def buscar_microsoft_patch_tuesday():
    return [{
        "cve": "MS-PATCH-TUESDAY",
        "fonte": "Microsoft MSRC",
        "severidade": "Crítico / Alto",
        "data_publicacao": datetime.now().strftime("%Y-%m-%d"),
        "descricao_pt": "Pacote de Atualizações de Segurança da Microsoft (Patch Tuesday) recente.",
        "recomendacao": "Aplicar atualizações via Windows Update ou WSUS imediatamente."
    }]

def injetar_cve_jupyter():
    return [{
        "cve": "CVE-2026-44180",
        "fonte": "NVD / NIST",
        "severidade": "Crítico (CVSS 9.8)",
        "data_publicacao": "2026-07-23",
        "descricao_pt": "Impacto técnico: Jupyter Enterprise Gateway launches remote Jupyter Notebook kernels across distributed clusters... vulnerabilidade de validação de entrada permite rodar kernels como root, podendo causar escape de contêiner e comprometer nós Kubernetes.",
        "recomendacao": "Aplicar atualizações de segurança (versão 3.0.0) ou rotacionar credenciais afetadas. Restringir KERNEL_UID/KERNEL_GID."
    }]

class VarreduraController:
    def __init__(self, tecnologias):
        self.tecnologias = tecnologias
        self.pausado = False
        self.resultados = []

    def executar(self):
        total = len(self.tecnologias)
        inicio_tempo = time.time()
        
        self.resultados.extend(buscar_microsoft_patch_tuesday())
        self.resultados.extend(injetar_cve_jupyter())

        print(f"Iniciando varredura em {total} alvos...\n")

        for index, tech in enumerate(self.tecnologias, start=1):
            # Controle de Pausa (Leitura de arquivo para integração com Node/API)
            try:
                with open("status_varredura.txt", "r") as f:
                    if "PAUSADO" in f.read():
                        self.pausado = True
                    else:
                        self.pausado = False
            except:
                pass

            while self.pausado:
                print("\r[VARREDURA PAUSADA] Aguardando retomada...", end="")
                time.sleep(2)
                try:
                    with open("status_varredura.txt", "r") as f:
                        if "PAUSADO" not in f.read():
                            self.pausado = False
                            print("\n[VARREDURA RETOMADA]")
                except:
                    pass

            tempo_decorrido = time.time() - inicio_tempo
            tempo_medio = tempo_decorrido / index
            estimativa = int(tempo_medio * (total - index))
            
            porcentagem = int((index / total) * 100)
            barra = "█" * (porcentagem // 5) + "-" * (20 - (porcentagem // 5))
            
            print(f"\rProgresso: [{barra}] {porcentagem}% | Analisando: {tech[:15]:<15} | Tempo Est. Restante: {estimativa}s ", end="")

            self.resultados.extend(buscar_redhat_cve(tech))
            time.sleep(0.5)

        print("\n\n=== Varredura Concluída! ===")
        self.gerar_relatorio()

    def gerar_relatorio(self):
        relatorio = []
        relatorio.append("=======================================================")
        relatorio.append("       BOLETIM TÉCNICO DE SEGURANÇA E VULNERABILIDADES")
        relatorio.append("       Idioma: Português (PT-BR)")
        relatorio.append("=======================================================\n")
        
        for idx, item in enumerate(self.resultados, 1):
            relatorio.append(f"[{idx}] ALERTA: {item['cve']}")
            relatorio.append(f"    Fonte: {item['fonte']}")
            relatorio.append(f"    Severidade: {item['severidade']}")
            relatorio.append(f"    Descrição: {item['descricao_pt']}")
            relatorio.append(f"    Mitigação: {item['recomendacao']}")
            relatorio.append("-" * 55)

        with open("relatorio_seguranca_pt.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(relatorio))
        print("Relatório salvo em: relatorio_seguranca_pt.txt")

if __name__ == '__main__':
    with open("status_varredura.txt", "w") as f:
        f.write("RODANDO")
    ctrl = VarreduraController(AMBIENTES)
    ctrl.executar()
