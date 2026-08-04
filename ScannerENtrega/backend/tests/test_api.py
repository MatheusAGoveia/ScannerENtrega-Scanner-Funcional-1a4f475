from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from govsec_scanner.api import app
from govsec_scanner.config import get_settings
from govsec_scanner.database import Base, get_db
from govsec_scanner.services import seed_profiles


def test_scanner_crud_flow_is_empty_then_real(tmp_path: Path) -> None:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'api.db'}", connect_args={"check_same_thread": False}
    )
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    with local_session() as db:
        seed_profiles(db)

    def override_db() -> Generator[Session, None, None]:
        with local_session() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    api_key = get_settings().api_key.get_secret_value()
    headers = {"X-Scanner-API-Key": api_key, "X-Scanner-Actor": "teste-integrado"}
    try:
        with TestClient(app) as client:
            assert client.get("/api/v1/scanner/ranges").status_code == 401
            assert client.get("/api/v1/scanner/ranges", headers=headers).json() == []

            created = client.post(
                "/api/v1/scanner/ranges",
                headers=headers,
                json={
                    "name": "Datacenter autorizado",
                    "cidr": "10.42.16.0/30",
                    "environment": "Homologacao",
                    "owner": "Infraestrutura",
                    "authorization_reference": "AUT-TESTE-001",
                    "allow_public": False,
                },
            )
            assert created.status_code == 201, created.text
            authorized_range = created.json()
            profiles = client.get("/api/v1/scanner/profiles", headers=headers).json()
            assert len(profiles) == 3

            queued = client.post(
                "/api/v1/scanner/executions",
                headers=headers,
                json={
                    "range_id": authorized_range["id"],
                    "profile_id": profiles[0]["id"],
                    "justification": "Teste controlado do fluxo de execucao.",
                },
            )
            assert queued.status_code == 202, queued.text
            assert queued.json()["status"] == "queued"

            summary = client.get("/api/v1/scanner/summary", headers=headers)
            assert summary.status_code == 200
            assert summary.json()["authorized_ips"] == 4
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
