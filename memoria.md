# Memória Persistente — GovSec Shield / ScannerENtrega

- **Data de Início:** 2026-08-04T13:13:09-03:00 (UTC-3) / 2026-08-04 16:13:09 UTC
- **Última Atualização:** 2026-08-04T18:04:00-03:00 (UTC-3)
- **Autor/Agente:** IA Assistente (Arquiteto Principal GovSec Shield)

## 1. Estado Atual & O que já foi implementado
- [x] Criação do arquivo `memoria.md` na raiz do repositório.
- [x] Diagnóstico de Auditoria Inicial (Prompt 1).
- [x] Preparação e Validação do Backend (Prompt 2).
- [x] Preparação e Validação do Frontend (Prompt 3).
- [x] Validação do Banco de Dados, Schema, Fila, Worker e Scheduler (Prompt 4).
- [x] Revisão Corretiva da Recuperação do Worker (Prompt 4 - Correção).
- [x] Validação e Correção dos Motores do Scanner (Prompt 5).
- [x] Validação e Correção da Integração Frontend Next.js <-> FastAPI (Prompt 6).
- [x] Correção Pontual de Segurança e Robustez (Prompt 6 - Correção Pontual a partir do commit 2d5b0d0).
- [x] Finalização de Segurança e Robustez do Scanner (branch `fix/scanner-security-final`).
- [x] Fase 1 — Integração Docker + PostgreSQL 16 + Migrations Alembic (branch `feat/scanner-docker-postgres`):
  - Merge para `main` realizado via fast-forward (`0d1b2f3` → `8972e1f`).

- [x] Fase 2 — Integração do Worker e Scheduler com Backend e PostgreSQL (branch `feat/scanner-worker-scheduler`):
  - **Migration 002**: Tabela `service_heartbeats` e coluna `scheduled_run_at` em `scan_executions`.
  - **Claim Atômico**: `FOR UPDATE SKIP LOCKED` no PostgreSQL garante captura única por Worker.
  - **Idempotência do Scheduler**: Coluna `scheduled_run_at` + índice único `(schedule_id, scheduled_run_at)` + `begin_nested()`.
  - **Heartbeat em Scans Longos**: Atualização contínua do heartbeat do Worker em `service_heartbeats` durante a execução de scans longos.
  - **Health Check por `instance_id`**: O CLI `healthcheck.py` e os contêineres agora validam o `instance_id` específico da instância ativa (`os.environ.get("INSTANCE_ID")` ou `<service>-<hostname>`), impedindo que heartbeats obsoletos de instâncias antigas passem a verificação.
  - **Desligamento Gracioso (SIGTERM/SIGINT)**: Resposta imediata a sinais de encerramento sem aceitar novas execuções e sem marcar execuções interrompidas como concluídas.
  - **Nmap Sem Root**: Utiliza `-sT` (TCP connect scan não privilegiado) e omite `-sU` se raw sockets não estiverem disponíveis. No Compose, configurado `cap_add: ["NET_RAW", "NET_BIND_SERVICE"]` sem utilizar `privileged: true`.
  - **Suíte de Testes Aprovada**: 48/48 testes unitários/integração aprovados no Pytest (84% cobertura).

## 2. O que está pendente (Próximos Passos)
- [ ] Fase 3: Integração do Frontend no Compose e validação end-to-end do ambiente completo.

## 3. Decisões Arquiteturais Tomadas
- O serviço `migrations` no Compose é o único responsável pela execução de DDL no banco de dados via `alembic upgrade head`.
- O Backend, Worker e Scheduler utilizam `check_database_ready()` apenas para consultar a versão aplicada em `alembic_version` sem alterar o schema.
- Claim atômico: `FOR UPDATE SKIP LOCKED` + UPDATE condicional com verificação de `rowcount == 0` garante que somente um Worker captura cada execução.
- Idempotência do Scheduler: coluna `scheduled_run_at` + índice único `(schedule_id, scheduled_run_at)` + tratamento de `IntegrityError`.
- Heartbeat de serviço: tabela `service_heartbeats` com validação de `instance_id` e atualização em background durante scans longos.
- Nmap em container: capacidades mínimas `cap_add: ["NET_RAW", "NET_BIND_SERVICE"]` sem `privileged: true` e fallback automático para `-sT` quando não for root.

## 4. Lista de Arquivos Criados / Modificados
- `memoria.md` (Atualizado)
- `ScannerENtrega/docker-compose.yml` (Modificado — adicionado cap_add no worker)
- `ScannerENtrega/backend/govsec_scanner/engines/nmap.py` (Modificado — detecção de raw sockets e fallback -sT)
- `ScannerENtrega/backend/govsec_scanner/healthcheck.py` (Modificado — validação de instance_id)
- `ScannerENtrega/backend/govsec_scanner/services.py` (Modificado — heartbeat em background durante scans)
- `ScannerENtrega/backend/govsec_scanner/worker.py` (Modificado — repasse de instance_id e shutdown gracioso)
- `ScannerENtrega/backend/govsec_scanner/scheduler.py` (Modificado — instance_id e shutdown gracioso)
- `ScannerENtrega/backend/tests/test_worker_scheduler.py` (Modificado — novos testes de instance_id, scan longo, sinais e mocks)
