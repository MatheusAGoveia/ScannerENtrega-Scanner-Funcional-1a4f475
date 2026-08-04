# Memória Persistente — GovSec Shield / ScannerENtrega

- **Data de Início:** 2026-08-04T13:13:09-03:00 (UTC-3) / 2026-08-04 16:13:09 UTC
- **Última Atualização:** 2026-08-04T17:02:00-03:00 (UTC-3)
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
  - **Docker Compose com Variáveis Obrigatórias**: Removidas credenciais padrão do `docker-compose.yml`. Utilizada a sintaxe `${VAR:?defina VAR}` para forçar o Compose a falhar se usuário, senha, banco, chave de API ou segredo de sessão não forem informados.
  - **Fim do Fallback Silencioso para SQLite**: No ambiente de produção (`SCANNER_ENVIRONMENT=production` ou `staging`), `DATABASE_URL` é estritamente obrigatória e rejeita conexões SQLite via `model_validator` no `Settings`.
  - **Prontidão Rígida em `/health/ready`**: Retorna `HTTP 503` caso o PostgreSQL esteja inacessível, as migrations não estejam aplicadas ou motores obrigatórios (Nmap e Nuclei) não estejam disponíveis.
  - **Migrations Versionadas com Alembic**: Implementada estrutura Alembic (`backend/alembic/`) com a migration inicial `001_initial_schema.py`. A execução é 100% idempotente e o contêiner `migrations` executa `alembic upgrade head`. O registro da versão na tabela `alembic_version` foi verificado diretamente no PostgreSQL.
  - **Sanitização de URLs de Banco de Dados**: A função `sanitize_db_url()` mascara senhas em logs do backend (`logger.info`) e possui teste unitário dedicado em `test_services.py`.
  - **Testes Aprovados**: 33/33 testes no Pytest aprovados (0 falhas).
  - Commit final: `76df7c4` na branch `feat/scanner-docker-postgres`.

## 2. O que está pendente (Próximos Passos)
- [ ] Fase 2: Integração e orquestração dos contêineres de Worker e Scheduler.
- [ ] Fase 3: Integração do Frontend no Compose e validação end-to-end do ambiente completo.

## 3. Decisões Arquiteturais Tomadas
- O Alembic é a ferramenta oficial de migrations versionadas do projeto.
- O contêiner de migrations executa a aplicação das migrations antes de autorizar o boot da API Backend.
- No contêiner Docker da API, o binário do Nmap roda sem `setcap` restritivo para permitir checagem de versão pelo usuário não-root `scanner`.

## 4. Problemas Enfrentados e Soluções Adotadas
- **Alembic env.py usando URL padrão do alembic.ini**: Corrigido em `env.py` para forçar o uso da `settings.database_url`.
- **Inclusão do Alembic no Dockerfile**: Adicionado `COPY alembic.ini ./` e `COPY alembic ./alembic` no `Dockerfile` do backend.

## 5. Lista de Arquivos Criados / Modificados
- `memoria.md` (Atualizado)
- `ScannerENtrega/docker-compose.yml` (Modificado)
- `ScannerENtrega/backend/Dockerfile` (Modificado)
- `ScannerENtrega/backend/alembic.ini` (Criado)
- `ScannerENtrega/backend/alembic/env.py` (Criado)
- `ScannerENtrega/backend/alembic/script.py.mako` (Criado)
- `ScannerENtrega/backend/alembic/versions/001_initial_schema.py` (Criado)
- `ScannerENtrega/backend/govsec_scanner/api.py` (Modificado)
- `ScannerENtrega/backend/govsec_scanner/config.py` (Modificado)
- `ScannerENtrega/backend/govsec_scanner/database.py` (Modificado)
- `ScannerENtrega/backend/pyproject.toml` (Modificado)
- `ScannerENtrega/backend/tests/test_services.py` (Modificado)
