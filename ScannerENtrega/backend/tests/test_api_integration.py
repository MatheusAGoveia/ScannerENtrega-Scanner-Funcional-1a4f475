from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from govsec_scanner.api import app
from govsec_scanner.config import get_settings
from govsec_scanner.database import Base, get_db
from govsec_scanner.services import seed_profiles


@pytest.fixture
def test_client(tmp_path: Path) -> Generator[TestClient, None, None]:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'integration.db'}", connect_args={"check_same_thread": False}
    )
    local_session = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    Base.metadata.create_all(engine)
    with local_session() as db:
        seed_profiles(db)

    def override_get_db() -> Generator[Session, None, None]:
        with local_session() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    engine.dispose()


def test_api_authentication_and_headers(test_client: TestClient) -> None:
    api_key = get_settings().api_key.get_secret_value()
    
    # 1. Missing header -> 401
    resp_unauth = test_client.get("/api/v1/scanner/ranges")
    assert resp_unauth.status_code == 401
    assert "ausente" in resp_unauth.json()["detail"].lower()

    # 2. Invalid header -> 401
    resp_invalid = test_client.get("/api/v1/scanner/ranges", headers={"X-Scanner-API-Key": "invalid-key"})
    assert resp_invalid.status_code == 401

    # 3. Valid header -> 200 OK
    resp_ok = test_client.get("/api/v1/scanner/ranges", headers={"X-Scanner-API-Key": api_key})
    assert resp_ok.status_code == 200
    assert resp_ok.json() == []


def test_api_range_creation_and_policy_validation(test_client: TestClient) -> None:
    api_key = get_settings().api_key.get_secret_value()
    headers = {"X-Scanner-API-Key": api_key, "X-Scanner-Actor": "operador-teste"}

    # 1. Create valid range
    payload = {
        "name": "Rede Municipal Autorizada",
        "cidr": "10.50.0.0/24",
        "environment": "Producao",
        "owner": "TI Municipal",
        "authorization_reference": "AUT-SEC-2026-001",
        "allow_public": False,
    }
    create_resp = test_client.post("/api/v1/scanner/ranges", headers=headers, json=payload)
    assert create_resp.status_code == 201
    created_range = create_resp.json()
    assert created_range["cidr"] == "10.50.0.0/24"
    assert created_range["address_count"] == 256

    # 2. Overlapping range -> 409 Conflict
    overlap_resp = test_client.post("/api/v1/scanner/ranges", headers=headers, json={
        **payload,
        "name": "Rede Sobreposta",
        "cidr": "10.50.0.128/25",
    })
    assert overlap_resp.status_code == 409
    assert "sobrepoe" in overlap_resp.json()["detail"].lower()

    # 3. Invalid CIDR -> 422 Unprocessable Entity
    invalid_resp = test_client.post("/api/v1/scanner/ranges", headers=headers, json={
        **payload,
        "cidr": "invalid-cidr-format",
    })
    assert invalid_resp.status_code == 422


def test_api_execution_lifecycle_without_real_scan(test_client: TestClient) -> None:
    api_key = get_settings().api_key.get_secret_value()
    headers = {"X-Scanner-API-Key": api_key, "X-Scanner-Actor": "operador-teste"}

    # Setup Range and Profile
    range_resp = test_client.post("/api/v1/scanner/ranges", headers=headers, json={
        "name": "Datacenter Teste",
        "cidr": "192.168.100.0/24",
        "environment": "Homologacao",
        "owner": "QA",
        "authorization_reference": "AUT-QA-2026",
    })
    range_id = range_resp.json()["id"]

    profiles_resp = test_client.get("/api/v1/scanner/profiles", headers=headers)
    profile_id = profiles_resp.json()[0]["id"]

    # 1. Enqueue execution -> 202 Accepted
    exec_resp = test_client.post("/api/v1/scanner/executions", headers=headers, json={
        "range_id": range_id,
        "profile_id": profile_id,
        "justification": "Validação de enfileiramento sem scan real.",
    })
    assert exec_resp.status_code == 202
    execution = exec_resp.json()
    assert execution["status"] == "queued"

    # 2. Cancel execution -> 200 OK
    cancel_resp = test_client.post(f"/api/v1/scanner/executions/{execution['id']}/cancel", headers=headers)
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "cancelled"


def test_api_summary_and_engines_status(test_client: TestClient) -> None:
    api_key = get_settings().api_key.get_secret_value()
    headers = {"X-Scanner-API-Key": api_key}

    summary_resp = test_client.get("/api/v1/scanner/summary", headers=headers)
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert "authorized_ips" in summary
    assert "ranges_count" in summary

    engines_resp = test_client.get("/api/v1/scanner/engines", headers=headers)
    assert engines_resp.status_code == 200
    engines = engines_resp.json()
    assert isinstance(engines, list)
    assert len(engines) >= 3
