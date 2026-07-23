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

let estadoVarredura = {
  status: 'idle',
  progresso: 0,
  itemAtual: '',
  estimativaRestanteSegundos: 0,
  totalItens: 0,
  itensProcessados: 0
};

app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'secops-api' });
});

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/api/technologies', (req, res) => {
  const tecnologias = [
    { id: "fortigate", name: "Fortigate", category: "Infraestrutura" },
    { id: "fortinet-manager", name: "Fortinet Manager", category: "Infraestrutura" },
    { id: "cisco-antispam", name: "Cisco Antispam", category: "Infraestrutura" },
    { id: "senha-segura-pam", name: "Senha Segura PAM", category: "Infraestrutura" },
    { id: "f5-bigip-waf", name: "F5 Big IP WAF", category: "Infraestrutura" },
    { id: "aws", name: "AWS", category: "Infraestrutura" },
    { id: "openshift", name: "Openshift", category: "Infraestrutura" },
    { id: "microsoft", name: "Microsoft", category: "Infraestrutura" },
    { id: "vmware", name: "VMware", category: "Infraestrutura" },
    { id: "kubernetes", name: "Kubernetes", category: "Sistemas de Produção" },
    { id: "docker", name: "Docker", category: "Aplicações / Desenvolvimento" }
  ];
  res.json(tecnologias);
});

app.get('/api/scan/status', (req, res) => {
  res.json(estadoVarredura);
});

app.post('/api/scan/pause', (req, res) => {
  estadoVarredura.status = estadoVarredura.status === 'paused' ? 'running' : 'paused';
  res.json({ status: estadoVarredura.status, msg: `Varredura ${estadoVarredura.status === 'paused' ? 'pausada' : 'retomada'}` });
});

app.listen(Number(PORT), '0.0.0.0', () => {
  console.log(`SecOps API Server rodando na porta ${PORT}`);
});
