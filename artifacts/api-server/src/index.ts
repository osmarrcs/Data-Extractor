import express from 'express';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Controle do Estado Global da Varredura
let varreduraAtual = {
  id: "scan-" + Date.now(),
  status: 'idle', // 'idle' | 'running' | 'paused' | 'completed'
  progresso: 0,
  tecnologiaAtual: '',
  totalTecnologias: 0,
  processadas: 0,
  resultados: [] as any[]
};

// Lista Completa de Tecnologias/Ativos
const TECNOLOGIAS_COMPLETAS = [
  { id: "fortigate", name: "Fortigate", category: "Infraestrutura" },
  { id: "fortinet-manager", name: "Fortinet Manager", category: "Infraestrutura" },
  { id: "fortinet-analyser", name: "Fortinet Analyser", category: "Infraestrutura" },
  { id: "fortinet-ems", name: "Fortinet EMS", category: "Infraestrutura" },
  { id: "forticlient-server", name: "FortiClient Server", category: "Infraestrutura" },
  { id: "forticlient-service", name: "FortiClient Service / Endpoint", category: "Infraestrutura" },
  { id: "cisco-antispam", name: "Cisco Antispam", category: "Infraestrutura" },
  { id: "senha-segura-pam", name: "Senha Segura PAM", category: "Infraestrutura" },
  { id: "f5-bigip-waf", name: "F5 Big IP WAF", category: "Infraestrutura" },
  { id: "aws", name: "AWS", category: "Infraestrutura" },
  { id: "openshift", name: "Openshift", category: "Infraestrutura" },
  { id: "microsoft", name: "Microsoft", category: "Infraestrutura" },
  { id: "vmware", name: "VMware", category: "Infraestrutura" },
  { id: "network-devices", name: "Network Devices", category: "Infraestrutura" },
  { id: "operating-systems", name: "Operating Systems", category: "Infraestrutura" },
  { id: "cloud-platforms", name: "Cloud Platforms", category: "Infraestrutura" },
  { id: "virtualization-software", name: "Virtualization Software", category: "Infraestrutura" },
  { id: "git", name: "Git", category: "Sistemas de Produção" },
  { id: "ansible", name: "Ansible", category: "Sistemas de Produção" },
  { id: "kubernetes", name: "Kubernetes", category: "Sistemas de Produção" },
  { id: "cicd-tools", name: "CI/CD Tools", category: "Sistemas de Produção" },
  { id: "containers", name: "Containers", category: "Sistemas de Produção" },
  { id: "orchestration-platforms", name: "Orchestration Platforms", category: "Sistemas de Produção" },
  { id: "oracle", name: "Oracle", category: "Banco de Dados" },
  { id: "postgresql", name: "PostgreSQL", category: "Banco de Dados" },
  { id: "mysql", name: "MySQL", category: "Banco de Dados" },
  { id: "sql-server", name: "SQL Server", category: "Banco de Dados" },
  { id: "mongodb", name: "MongoDB", category: "Banco de Dados" },
  { id: "redis", name: "Redis", category: "Banco de Dados" },
  { id: "google-chrome", name: "Google Chrome", category: "Navegadores" },
  { id: "mozilla-firefox", name: "Mozilla Firefox", category: "Navegadores" },
  { id: "microsoft-edge", name: "Microsoft Edge", category: "Navegadores" },
  { id: "safari", name: "Safari", category: "Navegadores" },
  { id: "brave", name: "Brave", category: "Navegadores" },
  { id: "opera", name: "Opera", category: "Navegadores" },
  { id: "winzip", name: "WinZip", category: "Aplicações / Desenvolvimento" },
  { id: "7zip", name: "7-Zip", category: "Aplicações / Desenvolvimento" },
  { id: "obs-studio", name: "OBS Studio", category: "Aplicações / Desenvolvimento" },
  { id: "docker", name: "Docker", category: "Aplicações / Desenvolvimento" },
  { id: "vscode", name: "Visual Studio Code", category: "Aplicações / Desenvolvimento" },
  { id: "jetbrains", name: "JetBrains IDEs", category: "Aplicações / Desenvolvimento" },
  { id: "npm", name: "npm", category: "Aplicações / Desenvolvimento" },
  { id: "python-packages", name: "Python Packages", category: "Aplicações / Desenvolvimento" },
  { id: "dev-tools", name: "Development Tools", category: "Aplicações / Desenvolvimento" },
  { id: "productivity-software", name: "Productivity Software", category: "Aplicações / Desenvolvimento" },
  { id: "file-archivers", name: "File Archivers", category: "Aplicações / Desenvolvimento" },
  { id: "streaming-software", name: "Streaming Software", category: "Aplicações / Desenvolvimento" }
];

// Health checks
app.get('/', (req, res) => res.json({ status: 'ok', service: 'secops-api' }));
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Lista Tecnologias
app.get('/api/technologies', (req, res) => res.json(TECNOLOGIAS_COMPLETAS));

// ROTA FALTANTE: POST /api/scans (Iniciar Varredura)
app.post('/api/scans', (req, res) => {
  const { technologies } = req.body || {};
  const alvos = Array.isArray(technologies) && technologies.length > 0 
    ? technologies 
    : TECNOLOGIAS_COMPLETAS.map(t => t.id);

  varreduraAtual = {
    id: "scan-" + Date.now(),
    status: 'running',
    progresso: 0,
    tecnologiaAtual: alvos[0] || 'Iniciando...',
    totalTecnologias: alvos.length,
    processadas: 0,
    resultados: []
  };

  res.status(201).json({
    message: "Varredura iniciada com sucesso",
    scan: varreduraAtual
  });
});

// GET /api/scans/current (Status da varredura atual)
app.get('/api/scans/current', (req, res) => {
  res.json(varreduraAtual);
});

// POST /api/scans/pause (Pausar/Retomar)
app.post('/api/scans/pause', (req, res) => {
  if (varreduraAtual.status === 'running') {
    varreduraAtual.status = 'paused';
  } else if (varreduraAtual.status === 'paused') {
    varreduraAtual.status = 'running';
  }
  res.json({ status: varreduraAtual.status, scan: varreduraAtual });
});

// ABAS SEPARADAS
app.get('/api/vulnerabilities/redhat', (req, res) => {
  res.json({ fonte: "Red Hat Security Data API", aba: "Red Hat CVEs", total: 0, itens: [] });
});

app.get('/api/vulnerabilities/patch-tuesday', (req, res) => {
  res.json({ fonte: "Microsoft MSRC API", aba: "Patch Tuesday", total: 0, itens: [] });
});

app.listen(Number(PORT), '0.0.0.0', () => {
  console.log(`SecOps API Server rodando em 0.0.0.0 na porta ${PORT}`);
});
