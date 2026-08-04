from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from govsec_scanner import scheduler, worker
from govsec_scanner.api import app
from govsec_scanner.config import Settings
from govsec_scanner.database import (
    Base,
    get_db,
)


def test_missing_database_url_raises_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SCANNER_DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="DATABASE_URL nao configurada"):
        Settings(_env_file=None, database_url=None, api_key="test-api-key-with-at-least-24-chars")


def test_alembic_failure_does_not_execute_create_all() -> None:
    with (
        patch.object(Base.metadata, "create_all") as mock_create_all,
        patch("govsec_scanner.database.check_database_ready", return_value=False),
        TestClient(app),
    ):
        pass
    mock_create_all.assert_not_called()


def test_api_worker_scheduler_do_not_execute_migrations() -> None:
    with patch("alembic.command.upgrade") as mock_alembic_upgrade:
        # 1. API lifespan test
        with (
            patch("govsec_scanner.database.check_database_ready", return_value=True),
            patch("govsec_scanner.api.seed_profiles"),
            TestClient(app),
        ):
            pass

        # 2. Worker main test
        with (
            patch("govsec_scanner.worker.check_database_ready", return_value=False),
            pytest.raises(RuntimeError, match="Banco de dados sem migration aplicada"),
        ):
            worker.main()

        # 3. Scheduler main test
        with (
            patch("govsec_scanner.scheduler.check_database_ready", return_value=False),
            pytest.raises(RuntimeError, match="Banco de dados sem migration aplicada"),
        ):
            scheduler.main()

        mock_alembic_upgrade.assert_not_called()


def test_health_ready_returns_200_with_valid_migration(tmp_path: Any) -> None:
    db_path = tmp_path / "valid.db"
    engine = create_engine(f"sqlite:///{db_path}")

    # Create schema and alembic_version table
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)"))
        conn.execute(text("INSERT INTO alembic_version VALUES ('001_initial_schema')"))

    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db() -> Any:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with (
        patch("govsec_scanner.api.engine_version", return_value="nmap version 7.95"),
        patch("govsec_scanner.api.get_expected_migration_head", return_value="001_initial_schema"),
        patch("govsec_scanner.api.settings.nuclei_enabled", False),
    ):
        client = TestClient(app)
        response = client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"] == "ok"
        assert data["migration_version"] == "001_initial_schema"

    app.dependency_overrides.clear()
    engine.dispose()


def test_health_ready_returns_503_without_alembic_version(tmp_path: Any) -> None:
    db_path = tmp_path / "no_alembic.db"
    engine = create_engine(f"sqlite:///{db_path}")

    with engine.begin() as conn:
        conn.execute(text("SELECT 1"))

    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db() -> Any:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert "alembic_version" in response.json()["detail"]

    app.dependency_overrides.clear()
    engine.dispose()


def test_health_ready_returns_503_with_outdated_migration(tmp_path: Any) -> None:
    db_path = tmp_path / "outdated.db"
    engine = create_engine(f"sqlite:///{db_path}")

    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)"))
        conn.execute(text("INSERT INTO alembic_version VALUES ('000_old_schema')"))

    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db() -> Any:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with patch("govsec_scanner.api.get_expected_migration_head", return_value="001_initial_schema"):
        client = TestClient(app)
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert "Migration desatualizada" in response.json()["detail"]

    app.dependency_overrides.clear()
    engine.dispose()


def test_health_ready_returns_503_without_mandatory_engine(tmp_path: Any) -> None:
    db_path = tmp_path / "valid_engine_missing.db"
    engine = create_engine(f"sqlite:///{db_path}")

    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)"))
        conn.execute(text("INSERT INTO alembic_version VALUES ('001_initial_schema')"))

    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db() -> Any:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with (
        patch("govsec_scanner.api.engine_version", return_value=None),
        patch("govsec_scanner.api.get_expected_migration_head", return_value="001_initial_schema"),
    ):
        client = TestClient(app)
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert "Motores obrigatorios indisponiveis" in response.json()["detail"]

    app.dependency_overrides.clear()
    engine.dispose()
