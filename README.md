# SECOPS — Painel de Vulnerabilidades CVE

Plataforma de gestão e monitoramento de vulnerabilidades (CVE) com dashboard interativo, scanner de tecnologias, triagem de vulnerabilidades e geração de boletins. Interface em português, voltada para equipes de segurança defensiva.

## Acesse o app

O aplicativo está publicado em:

> **[https://secops.cve-dashboard.repl.co](https://secops.cve-dashboard.repl.co)**

_(Substitua pelo URL real de publicação quando disponível.)_

## Funcionalidades

- **Painel** — Visão geral com estatísticas de vulnerabilidades por severidade (crítico, alto, médio, baixo), por tecnologia e por fonte de dados.
- **Varredura** — Inicia uma nova varredura selecionando as tecnologias a inspecionar. Acompanha o progresso em tempo real.
- **Vulnerabilidades** — Lista filtrável por status (pendente, processado, adiado, descartado), tecnologia e fonte. Cada vulnerabilidade tem página de detalhe com descrição, solução recomendada, CVSS e triagem.
- **Histórico** — Registro de todas as varreduras realizadas, com status e total de vulnerabilidades encontradas.
- **Boletim** — Geração de relatórios individuais no estilo Tenable, com exportação de HTML para compartilhamento.

## Stack

| Camada | Tecnologia |
|--------|-----------|
| Frontend | React 19 + Vite 7 + TailwindCSS 4 + shadcn/ui |
| Roteamento | wouter |
| Estado/dados | TanStack Query |
| Backend | Express 5 + esbuild (bundle CJS) |
| Banco de dados | PostgreSQL + Drizzle ORM |
| Validação | Zod + drizzle-zod |
| API codegen | Orval (a partir de spec OpenAPI 3.1) |
| Logs | pino + pino-http |
| Runtime | Node.js 24, TypeScript 5.9, pnpm workspaces |

## Estrutura do projeto

```
project/
├── artifacts/
│   ├── api-server/          # Servidor Express (API REST)
│   ├── cve-dashboard/      # Frontend React (dashboard)
│   └── mockup-sandbox/      # Ambiente de prototipagem
├── lib/
│   ├── api-client-react/    # Hooks React gerados (Orval)
│   ├── api-spec/            # Spec OpenAPI + config Orval
│   ├── api-zod/             # Schemas Zod gerados
│   └── db/                  # Schema Drizzle + migrações
├── scripts/                # Scripts utilitários
└── pnpm-workspace.yaml      # Configuração do workspace
```

## Como rodar localmente

```bash
# Instalar dependências
pnpm install

# Rodar o servidor de API (porta 5000)
pnpm --filter @workspace/api-server run dev

# Rodar o frontend (porta 22015)
pnpm --filter @workspace/cve-dashboard run dev

# Typecheck completo
pnpm run typecheck

# Build de produção (typecheck + build de todos os pacotes)
pnpm run build

# Regenerar hooks e schemas a partir da spec OpenAPI
pnpm --filter @workspace/api-spec run codegen

# Push de schema para o banco (apenas dev)
pnpm --filter @workspace/db run push
```

### Variáveis de ambiente

| Variável | Descrição |
|----------|-----------|
| `DATABASE_URL` | String de conexão PostgreSQL (Drizzle ORM) |

## API REST

A API está disponível em `/api` com os seguintes endpoints principais:

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/api/healthz` | Health check |
| `GET` | `/api/technologies` | Lista tecnologias disponíveis |
| `GET` | `/api/vulnerabilities` | Lista vulnerabilidades (filtros: status, tech, source, scanId) |
| `GET` | `/api/vulnerabilities/:id` | Detalhe de uma vulnerabilidade |
| `PATCH` | `/api/vulnerabilities/:id/triage` | Define triagem (processado, adiado, descartado) |
| `GET` | `/api/vulnerabilities/:id/report` | Relatório HTML no estilo Tenable |
| `GET` | `/api/scans` | Lista varreduras |
| `POST` | `/api/scans` | Inicia nova varredura |
| `GET` | `/api/scans/:id` | Status e resultados de uma varredura |
| `GET` | `/api/stats` | Estatísticas do dashboard |
| `GET` | `/api/stats/by-tech` | Vulnerabilidades por tecnologia |
| `GET` | `/api/stats/by-source` | Vulnerabilidades por fonte |
| `GET` | `/api/stats/recent` | Vulnerabilidades mais recentes |

A especificação completa está em [`lib/api-spec/openapi.yaml`](lib/api-spec/openapi.yaml).

## Status de vulnerabilidades

| Status | Significado |
|--------|-------------|
| `pendente` | Recém-encontrada, aguardando triagem |
| `processado` | Triada e tratada |
| `adiado` | Remedição adiada intencionalmente |
| `descartado` | Avaliada e descartada (falso positivo ou não aplicável) |

## Licença

MIT
