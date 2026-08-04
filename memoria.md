# Memória Persistente — GovSec Shield / ScannerENtrega

- **Data de Início:** 2026-08-04T13:13:09-03:00 (UTC-3) / 2026-08-04 16:13:09 UTC
- **Última Atualização:** 2026-08-04T18:25:00-03:00 (UTC-3)
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
  - **Desligamento Gracioso Ativo & Encerramento de Subprocessos (SIGTERM/SIGINT)**: O handler de sinais envia cancelamento assíncrono à task ativa (`_active_task.cancel()`). Ao capturar `asyncio.CancelledError`, o `run_process()` envia `process.terminate()`/`process.kill()` e aguarda `process.wait()`, garantindo que nenhum subprocesso Nmap/Nuclei continue rodando. O `execute_scan` marca `ScanExecution` e `EngineRun` como `failed`, **nunca** gravando a execução como `completed`.
  - **Teste com Sinal OS Real (`test_real_signal_shutdown`)**: O teste executa um processo filho Worker real via `subprocess.Popen`, envia um `SIGTERM` real via `proc.send_signal(signal.SIGTERM)`, aguarda o término e valida que a execução no banco **não** permaneceu nem foi gravada como `completed`.
  - **Sanitização Global de Logs**: Todas as exceções capturadas e formatadas nos logs do Worker, Scheduler e Services utilizam obrigatoriamente `_sanitize_error_message(exc)`. Testado via `caplog`.
  - **Tratamento de Perfil UDP sem Raw Sockets no Nmap**: Em `build_nmap_command`, perfis exclusivamente UDP sem raw sockets disparam `EngineExecutionError` explícito. No Compose, configurado `cap_add: ["NET_RAW", "NET_BIND_SERVICE"]` sem utilizar `privileged: true`.
  - **Suíte de Testes Aprovada**: 50/50 testes unitários/integração aprovados no Pytest (84% cobertura).

## 2. O que está pendente (Próximos Passos)
- [ ] Fase 3: Integração do Frontend no Compose e validação end-to-end do ambiente completo.

## 3. Decisões Arquiteturais Tomadas
- O serviço `migrations` no Compose é o único responsável pela execução de DDL no banco de dados via `alembic upgrade head`.
- O Backend, Worker e Scheduler utilizam `check_database_ready()` apenas para consultar a versão aplicada em `alembic_version` sem alterar o schema.
- Claim atômico: `FOR UPDATE SKIP LOCKED` + UPDATE condicional com verificação de `rowcount == 0` garante que somente um Worker captura cada execução.
- Idempotência do Scheduler: coluna `scheduled_run_at` + índice único `(schedule_id, scheduled_run_at)` + tratamento de `IntegrityError`.
- Heartbeat de serviço: tabela `service_heartbeats` com validação de `instance_id` e atualização em background durante scans longos.
- Cancelamento de task ativa e subprocessos OS: encerramento via `_active_task.cancel()`, `process.terminate()`/`process.kill()` + `process.wait()` e marcação do banco como `failed`/interrompido.
- Nmap em container: capacidades mínimas `cap_add: ["NET_RAW", "NET_BIND_SERVICE"]` sem `privileged: true` e erro explícito quando raw sockets forem insuficientes para UDP puro.

## 4. Lista de Arquivos Criados / Modificados
- `memoria.md` (Atualizado)
- `ScannerENtrega/docker-compose.yml` (Modificado — adicionado cap_add no worker)
- `ScannerENtrega/backend/govsec_scanner/engines/base.py` (Modificado — encerramento e wait de subprocesso no CancelledError)
- `ScannerENtrega/backend/govsec_scanner/engines/nmap.py` (Modificado — erro explícito para UDP puro sem raw sockets)
- `ScannerENtrega/backend/govsec_scanner/healthcheck.py` (Modificado — validação de instance_id)
- `ScannerENtrega/backend/govsec_scanner/services.py` (Modificado — tratamento de CancelledError e sanitização)
- `ScannerENtrega/backend/govsec_scanner/worker.py` (Modificado — cancelamento da task ativa no SIGTERM e sanitização de logs)
- `ScannerENtrega/backend/govsec_scanner/scheduler.py` (Modificado — sanitização de logs)
- `ScannerENtrega/backend/tests/test_worker_scheduler.py` (Modificado — testes de cancelamento por sinal OS real, encerramento de subprocesso em run_process, caplog e UDP sem raw sockets)
