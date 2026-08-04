# Memória Persistente — GovSec Shield / ScannerENtrega

- **Data de Início:** 2026-08-04T13:13:09-03:00 (UTC-3) / 2026-08-04 16:13:09 UTC
- **Última Atualização:** 2026-08-04T17:38:00-03:00 (UTC-3)
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
  - **Alembic Exclusivo no Serviço `migrations`**: Somente o contêiner `migrations` executa `python -m alembic upgrade head`.
  - **Remoção Total do Fallback `Base.metadata.create_all()`**: Sem Alembic ou migrations aplicadas, a aplicação falha de forma explícita.
  - **Validação Rígida de Prontidão em `/health/ready`**: Valida PostgreSQL, `alembic_version`, versão aplicada e motores Nmap/Nuclei.
  - **Suíte de Testes Aprovada**: 40/40 testes unitários aprovados no Pytest.
  - Merge para `main` realizado via fast-forward (`0d1b2f3` → `8972e1f`).

- [x] Fase 2 — Integração do Worker e Scheduler com Backend e PostgreSQL (branch `feat/scanner-worker-scheduler`):
  - **Migration 002**: Tabela `service_heartbeats` e coluna `scheduled_run_at` em `scan_executions`.
  - **Claim Atômico**: `FOR UPDATE SKIP LOCKED` no PostgreSQL garante que apenas um Worker captura cada execução.
  - **Idempotência do Scheduler**: Coluna `scheduled_run_at` + índice único `(schedule_id, scheduled_run_at)` + `begin_nested()` para tratar duplicações via `IntegrityError`.
  - **Heartbeat por Serviço**: Tabela `service_heartbeats` atualizada a cada 5s pelo Worker e Scheduler. Health check Docker verifica via CLI `python -m govsec_scanner.healthcheck --service <worker|scheduler>` com tolerância de 30s de obsolescência.
  - **Desligamento Gracioso**: Tratamento de `SIGINT`/`SIGTERM` em Worker e Scheduler sem deixar execuções incorretamente marcadas como concluídas.
  - **Docker Compose**: Serviços `worker` e `scheduler` adicionados com `depends_on` corretos e healthchecks funcionais.
  - **Suíte de Testes**: 47/47 testes aprovados (84% cobertura). Inclui: claim atômico, dois workers, deduplicação do scheduler, ausência de migrations no worker/scheduler, heartbeat, sanitização de erros e shutdown seguro.
  - **Teste Controlado**: Fluxo Scheduler→PostgreSQL→Worker→resultado→API comprovado em ambiente local 127.0.0.1/32. Dados persistiram após `docker compose restart`.

## 2. O que está pendente (Próximos Passos)
- [ ] Fase 3: Integração do Frontend no Compose e validação end-to-end do ambiente completo.

## 3. Decisões Arquiteturais Tomadas
- O serviço `migrations` no Compose é o único responsável pela execução de DDL no banco de dados via `alembic upgrade head`.
- O Backend, Worker e Scheduler utilizam `check_database_ready()` apenas para consultar a versão aplicada em `alembic_version` sem alterar o schema.
- Claim atômico: `FOR UPDATE SKIP LOCKED` + UPDATE condicional com verificação de `rowcount == 0` garante que somente um Worker captura cada execução.
- Idempotência do Scheduler: coluna `scheduled_run_at` + índice único `(schedule_id, scheduled_run_at)` + tratamento de `IntegrityError`.
- Heartbeat de serviço: tabela `service_heartbeats` com registro periódico (5s) e health check CLI com tolerância configurável (padrão 30s).

## 4. Lista de Arquivos Criados / Modificados
- `memoria.md` (Atualizado)
- `ScannerENtrega/docker-compose.yml` (Modificado — serviços worker e scheduler adicionados)
- `ScannerENtrega/backend/alembic/versions/002_service_heartbeats.py` (Criado)
- `ScannerENtrega/backend/govsec_scanner/models.py` (Modificado — ServiceHeartbeat, scheduled_run_at)
- `ScannerENtrega/backend/govsec_scanner/healthcheck.py` (Criado)
- `ScannerENtrega/backend/govsec_scanner/services.py` (Modificado — update_service_heartbeat, sanitização melhorada)
- `ScannerENtrega/backend/govsec_scanner/worker.py` (Modificado — SIGTERM, heartbeat, shutdown gracioso)
- `ScannerENtrega/backend/govsec_scanner/scheduler.py` (Modificado — idempotência, SIGTERM, heartbeat)
- `ScannerENtrega/backend/tests/test_worker_scheduler.py` (Criado)
