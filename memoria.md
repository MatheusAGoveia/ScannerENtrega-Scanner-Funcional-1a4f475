# Memória Persistente — GovSec Shield / ScannerENtrega

- **Data de Início:** 2026-08-04T13:13:09-03:00 (UTC-3) / 2026-08-04 16:13:09 UTC
- **Última Atualização:** 2026-08-04T17:18:00-03:00 (UTC-3)
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
- [x] Fase 1 da Integração Docker + PostgreSQL 16 + Migrations Alembic (branch `feat/scanner-docker-postgres`):
  - **Alembic Exclusivo no Serviço `migrations`**: Removida completamente qualquer execução de `alembic upgrade` ou `init_database()` na inicialização da API, Worker e Scheduler. Somente o contêiner `migrations` executa `python -m alembic upgrade head`.
  - **Remoção Total do Fallback `Base.metadata.create_all()`**: Eliminado qualquer fallback automatizado de criação de tabelas. Sem Alembic ou migrations aplicadas, a aplicação falha de forma explícita.
  - **Validação Rígida de Prontidão em `/health/ready`**: O endpoint valida conectividade com o PostgreSQL, existência da tabela `alembic_version`, versão aplicada igual ao head esperado (`001_initial_schema`) e motores Nmap/Nuclei disponíveis, retornando `503` caso qualquer validação falhe.
  - **Uso Estrito do SQLite**: Desativada qualquer instanciação padrão implícita do SQLite quando `DATABASE_URL` não for informada (lançando `ValueError`). O SQLite só é aceito mediante configuração explícita de ambiente.
  - **Suíte de Testes Aprovada**: Criados testes em `test_migration_and_health.py` cobrindo todas as regras descritas. 40/40 testes unitários aprovados no Pytest.
  - **Sanitização de Logs e Git Cleanliness**: `git diff --check` sem erros de espaços em branco; ausência de credenciais em logs e volume `postgres_data` preservado.

## 2. O que está pendente (Próximos Passos)
- [ ] Fase 2: Integração e orquestração dos contêineres de Worker e Scheduler.
- [ ] Fase 3: Integração do Frontend no Compose e validação end-to-end do ambiente completo.

## 3. Decisões Arquiteturais Tomadas
- O serviço `migrations` no Compose é o único responsável pela execução de DDL no banco de dados via `alembic upgrade head`.
- O Backend, Worker e Scheduler utilizam `check_database_ready()` apenas para consultar a versão aplicada em `alembic_version` sem alterar o schema.

## 4. Lista de Arquivos Criados / Modificados
- `memoria.md` (Atualizado)
- `ScannerENtrega/docker-compose.yml` (Modificado)
- `ScannerENtrega/backend/govsec_scanner/api.py` (Modificado)
- `ScannerENtrega/backend/govsec_scanner/config.py` (Modificado)
- `ScannerENtrega/backend/govsec_scanner/database.py` (Modificado)
- `ScannerENtrega/backend/govsec_scanner/scheduler.py` (Modificado)
- `ScannerENtrega/backend/govsec_scanner/worker.py` (Modificado)
- `ScannerENtrega/backend/tests/conftest.py` (Modificado)
- `ScannerENtrega/backend/tests/test_migration_and_health.py` (Criado)
