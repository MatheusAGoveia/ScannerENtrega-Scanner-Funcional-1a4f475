# GovSec Scanner

Módulo funcional de scanner defensivo para redes previamente autorizadas. O frontend reutiliza a aparência original do GovSec Shield; somente as páginas de **Scanners** foram conectadas a dados reais.

## O que está implementado

- cadastro manual de IP ou CIDR com responsável e referência formal da autorização;
- importação com prévia para TXT, CSV, XLSX, PDF textual e ZIP;
- bloqueio de duplicidades, sobreposições, arquivos perigosos e faixas acima do limite;
- execução manual e agendada por cron;
- worker persistente, histórico de execuções e cancelamento solicitado pelo operador;
- descoberta TCP/UDP e identificação de serviços com Nmap;
- coleta limitada de banner HTTP e informações TLS com Python assíncrono;
- avaliação de vulnerabilidades com Nuclei, sem OAST, fuzzing, força bruta ou templates de DoS;
- inventário de ativos, portas, serviços e achados;
- reconciliação opcional com hosts já existentes no Zabbix, sem criação automática;
- autenticação entre frontend e API, auditoria e métricas Prometheus.

## Proteção de escopo

O alvo nunca é digitado no momento da execução. O operador escolhe uma faixa cadastrada e o worker a valida novamente antes de iniciar cada execução. Resultados de Nmap ou Nuclei fora do CIDR exato encerram o motor com falha.

Faixas públicas ficam desativadas por padrão e exigem duas liberações simultâneas:

1. `SCANNER_ALLOW_PUBLIC_TARGETS=true` no servidor;
2. `allow_public=true` no cadastro individual da faixa pela API.

Mantenha essa opção desligada na instalação normal da prefeitura.

## Subir todo o módulo com Docker

Requisitos: Linux, Docker Engine com Compose v2, rota de rede do servidor até os segmentos municipais autorizados e liberação formal da equipe de infraestrutura.

```bash
cp .env.example .env
```

Troque obrigatoriamente `POSTGRES_PASSWORD` e `SCANNER_API_KEY` no `.env`. A chave precisa ter pelo menos 24 caracteres.

```bash
docker compose build
docker compose up -d
docker compose ps
```

Serviços iniciados:

| Serviço | Função | Exposição padrão |
|---|---|---|
| `frontend` | Next.js com a interface original | `0.0.0.0:3000` |
| `api` | FastAPI e endpoints do scanner | `127.0.0.1:8000` |
| `worker` | Nmap, banners/TLS, Nuclei e Zabbix | somente rede interna |
| `scheduler` | criação das execuções agendadas | somente rede interna |
| `postgres` | persistência | somente rede interna |

Verifique a saúde da API no próprio servidor:

```bash
curl http://127.0.0.1:8000/health/ready
```

Abra `http://IP-DO-SERVIDOR:3000`. Em produção, coloque um proxy reverso HTTPS institucional na frente do frontend e não exponha diretamente Postgres, worker ou scheduler.

## Desenvolvimento sem Docker

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn govsec_scanner.api:app --reload
```

Em outro terminal, worker e scheduler:

```bash
cd backend
source .venv/bin/activate
python -m govsec_scanner.worker
python -m govsec_scanner.scheduler
```

Esse modo exige Nmap, Nuclei e os templates do Nuclei instalados no sistema. O container já prepara esses componentes.

Frontend:

```bash
cd frontend
npm ci
```

Crie `frontend/.env.local`:

```dotenv
BACKEND_URL=http://localhost:8000
SCANNER_API_KEY=use-a-mesma-chave-do-backend
```

Depois:

```bash
npm run dev
```

Os scripts funcionam diretamente no PowerShell porque não usam a sintaxe Linux de variável inline que causava o erro de `WRANGLER_LOG_PATH`.

## Testes e validações

```bash
cd backend
ruff format --check .
ruff check .
mypy govsec_scanner
pytest tests --cov=govsec_scanner

cd ../frontend
npm run lint
npm run build
```

Os testes cobrem a trava de escopo, importações, adaptadores reais por subprocesso, banner HTTP local, API e persistência completa do pipeline do worker.

## Atualização dos templates

Os templates oficiais do Nuclei são baixados durante a construção da imagem. Para atualizar de forma controlada, reconstrua e valide a imagem antes de levá-la à produção:

```bash
docker compose build --pull api worker scheduler
docker compose up -d
```

## Observações operacionais

- o worker deve alcançar apenas as VLANs, VPNs e rotas aprovadas;
- aplique regras de firewall de saída coerentes com as faixas autorizadas;
- use backup diário do volume `postgres_data`;
- mantenha `.env`, chaves e tokens fora do Git;
- o endpoint `/metrics` deve ser coletado apenas pela rede de observabilidade;
- o Zabbix é opcional e nunca recebe criação automática de host por este módulo.
