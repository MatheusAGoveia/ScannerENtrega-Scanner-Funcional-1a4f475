import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from govsec_scanner.api import app, get_db
from govsec_scanner.config import get_settings
from govsec_scanner.models import (
    Base,
    AuthorizedRange,
    ScannerProfile,
    ScanExecution,
    DiscoveredAsset,
    DiscoveredService,
    ServiceObservation,
    ServiceRiskAssessment,
)
from govsec_scanner.engines.base import HostObservation, ServiceObservation as EngineServiceObs
from govsec_scanner.services import _persist_hosts, seed_profiles

@pytest.fixture
def api_client():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db():
        with TestingSessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    
    # Seed profiles and create test data
    with TestingSessionLocal() as db:
        seed_profiles(db)
        range_obj = AuthorizedRange(
            name="API Range",
            cidr="172.16.0.0/24",
            address_count=256,
            environment="test",
            owner="admin",
            authorization_reference="AUTH-API",
            enabled=True,
            allow_public=False,
        )
        db.add(range_obj)
        
        profile = ScannerProfile(
            slug="api-profile",
            name="API Profile",
            description="Profile for API testing",
            tcp_ports="22,80,3389",
            udp_ports="",
            discovery_enabled=True,
            service_detection_enabled=True,
            vulnerability_detection_enabled=False,
        )
        db.add(profile)
        db.commit()

        execution = ScanExecution(
            range_id=range_obj.id,
            profile_id=profile.id,
            requested_by="api-user",
            justification="API test scan justification",
            status="running",
        )
        execution.profile = profile
        db.add(execution)
        db.commit()

        hosts = [
            HostObservation(
                ip_address="172.16.0.50",
                hostname="api-host",
                os_name="Windows Server",
                services=[
                    EngineServiceObs(protocol="tcp", port=3389, state="open", service_name="ms-wbt-server", product="Terminal Services"),
                ],
            )
        ]
        _persist_hosts(db, execution, hosts)
        
        asset = db.query(DiscoveredAsset).filter_by(ip_address="172.16.0.50").first()
        service = db.query(DiscoveredService).filter_by(port=3389).first()
        
        asset_id = asset.id
        service_id = service.id
        execution_id = execution.id

    client = TestClient(app)
    api_key = get_settings().api_key.get_secret_value()
    client.headers = {"X-Scanner-API-Key": api_key, "X-Scanner-Actor": "api-tester"}
    client.test_asset_id = asset_id
    client.test_service_id = service_id
    client.test_execution_id = execution_id

    yield client

    app.dependency_overrides.clear()

def test_get_asset_services_api(api_client):
    response = api_client.get(f"/api/v1/scanner/assets/{api_client.test_asset_id}/services", headers=api_client.headers)
    assert response.status_code == 200, response.text
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["port"] == 3389
    assert data[0]["normalized_service_name"] == "rdp"
    assert data[0]["category"] == "remote_access"
    assert isinstance(data[0]["reasons"], list)

def test_get_service_detail_api(api_client):
    response = api_client.get(f"/api/v1/scanner/services/{api_client.test_service_id}", headers=api_client.headers)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["id"] == api_client.test_service_id
    assert data["ip_address"] == "172.16.0.50"
    assert data["normalized_service_name"] == "rdp"
    assert data["category"] == "remote_access"
    assert len(data["reasons"]) > 0

def test_get_service_history_api(api_client):
    response = api_client.get(f"/api/v1/scanner/services/{api_client.test_service_id}/history", headers=api_client.headers)
    assert response.status_code == 200, response.text
    data = response.json()
    assert "observations" in data
    assert "risk_assessments" in data
    assert len(data["observations"]) == 1
    assert len(data["risk_assessments"]) == 1
    assert data["observations"][0]["normalized_service_name"] == "rdp"
    assert data["risk_assessments"][0]["execution_id"] == api_client.test_execution_id

def test_api_404_handling(api_client):
    res_asset = api_client.get("/api/v1/scanner/assets/invalid-id-9999/services", headers=api_client.headers)
    assert res_asset.status_code == 404

    res_service = api_client.get("/api/v1/scanner/services/invalid-id-9999", headers=api_client.headers)
    assert res_service.status_code == 404

    res_history = api_client.get("/api/v1/scanner/services/invalid-id-9999/history", headers=api_client.headers)
    assert res_history.status_code == 404
