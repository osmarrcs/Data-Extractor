import express from 'express';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors({ origin: '*' }));
app.use(express.json());

// Controle de estado simulando o motor Python para o Frontend
let estadoScan = {
  id: "scan-" + Date.now(),
  status: 'idle', // idle, running, paused
  progresso: 0,
  itemAtual: '',
  estimativaRestanteSegundos: 0,
  totalItens: 45,
  itensProcessados: 0,
  resultados: []
};

// Intervalo de simulação da engine
let scanInterval: any = null;

const TECNOLOGIAS = [
  { id: "fortigate", name: "Fortigate", category: "Infraestrutura" },
  { id: "microsoft", name: "Microsoft", category: "Infraestrutura" },
  { id: "kubernetes", name: "Kubernetes", category: "Sistemas de Produção" },
  { id: "jupyter", name: "Jupyter Enterprise Gateway", category: "Aplicações" }
];

app.get('/', (req, res) => res.json({ status: 'ok' }));
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
app.get('/api/technologies', (req, res) => res.json(TECNOLOGIAS));

// Retorna o status atual para a barra de progresso do frontend
app.get(['/api/scans', '/api/scans/current'], (req, res) => res.json(estadoScan));

// Inicia a varredura
app.post('/api/scans', (req, res) => {
  estadoScan = {
    id: "scan-" + Date.now(),
    status: 'running',
    progresso: 1,
    itemAtual: 'Iniciando análise Red Hat e MSRC...',
    estimativaRestanteSegundos: 120,
    totalItens: TECNOLOGIAS.length,
    itensProcessados: 0,
    resultados: []
  };

  if (scanInterval) clearInterval(scanInterval);
  
  scanInterval = setInterval(() => {
    if (estadoScan.status === 'running' && estadoScan.progresso < 100) {
      estadoScan.progresso += 5;
      estadoScan.estimativaRestanteSegundos -= 6;
      estadoScan.itemAtual = `Analisando ativo ${Math.floor(Math.random() * 100)}...`;
      if (estadoScan.progresso >= 100) {
        estadoScan.status = 'completed';
        estadoScan.itemAtual = 'Relatório em Português gerado com sucesso!';
        estadoScan.estimativaRestanteSegundos = 0;
        clearInterval(scanInterval);
      }
    }
  }, 2000);

  res.status(201).json({ message: "Varredura iniciada", scan: estadoScan });
});

// Pausar / Retomar Varredura
app.post('/api/scans/pause', (req, res) => {
  if (estadoScan.status === 'running') {
    estadoScan.status = 'paused';
    estadoScan.itemAtual = 'Varredura Pausada pelo Usuário';
  } else if (estadoScan.status === 'paused') {
    estadoScan.status = 'running';
    estadoScan.itemAtual = 'Retomando varredura...';
  }
  res.json({ status: estadoScan.status, scan: estadoScan });
});

app.listen(Number(PORT), '0.0.0.0', () => console.log(`API SecOps rodando na porta ${PORT}`));
