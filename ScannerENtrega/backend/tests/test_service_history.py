import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from govsec_scanner.models import (
    Base,
    DiscoveredAsset,
    DiscoveredService,
    ScanExecution,
    ScannerProfile,
    AuthorizedRange,
    ServiceObservation,
    ServiceRiskAssessment,
)
from govsec_scanner.engines.base import HostObservation, ServiceObservation as EngineServiceObs
from govsec_scanner.services import _persist_hosts

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_service_history_creation_and_enrichment(db_session):
    range_obj = AuthorizedRange(
        name="History Range",
        cidr="192.168.1.0/24",
        address_count=256,
        environment="prod",
        owner="admin",
        authorization_reference="AUTH-HIST",
        enabled=True,
        allow_public=False,
    )
    db_session.add(range_obj)
    
    profile = ScannerProfile(
        slug="hist-profile",
        name="History Profile",
        description="Profile for testing history",
        tcp_ports="22,80",
        udp_ports="",
        discovery_enabled=True,
        service_detection_enabled=True,
        vulnerability_detection_enabled=False,
    )
    db_session.add(profile)
    db_session.commit()

    # Execution 1
    exec1 = ScanExecution(
        range_id=range_obj.id,
        profile_id=profile.id,
        requested_by="user1",
        justification="History test 1",
        status="running",
    )
    exec1.profile = profile
    db_session.add(exec1)
    db_session.commit()

    hosts1 = [
        HostObservation(
            ip_address="192.168.1.10",
            hostname="host-hist",
            os_name="Linux",
            services=[
                EngineServiceObs(protocol="tcp", port=22, state="open", service_name="ssh", product="OpenSSH", version="8.9p1"),
            ],
        )
    ]

    _persist_hosts(db_session, exec1, hosts1)

    # Verify DiscoveredService enrichment
    service = db_session.query(DiscoveredService).filter_by(port=22).first()
    assert service is not None
    assert service.normalized_service_name == "ssh"
    assert service.normalized_product == "openssh"
    assert service.category == "remote_access"
    assert service.risk_level in ("MEDIUM", "HIGH", "CRITICAL")
    assert service.last_observation_id is not None

    # Verify ServiceObservation
    obs1 = db_session.query(ServiceObservation).filter_by(execution_id=exec1.id, service_id=service.id).first()
    assert obs1 is not None
    assert obs1.normalized_service_name == "ssh"
    assert obs1.normalized_product == "openssh"

    # Verify ServiceRiskAssessment
    risk1 = db_session.query(ServiceRiskAssessment).filter_by(execution_id=exec1.id, service_id=service.id).first()
    assert risk1 is not None
    assert risk1.score > 0
    reasons = json.loads(risk1.reasons_json)
    assert isinstance(reasons, list)
    assert len(reasons) > 0

    # Execution 2 (Second execution creates new snapshot)
    exec2 = ScanExecution(
        range_id=range_obj.id,
        profile_id=profile.id,
        requested_by="user1",
        justification="History test 2",
        status="running",
    )
    exec2.profile = profile
    db_session.add(exec2)
    db_session.commit()

    _persist_hosts(db_session, exec2, hosts1)

    total_obs = db_session.query(ServiceObservation).filter_by(service_id=service.id).count()
    assert total_obs == 2, "There should be 2 historical observations for the service"

def test_service_history_idempotency(db_session):
    range_obj = AuthorizedRange(
        name="Idempotency Range",
        cidr="192.168.2.0/24",
        address_count=256,
        environment="prod",
        owner="admin",
        authorization_reference="AUTH-IDEM",
        enabled=True,
        allow_public=False,
    )
    db_session.add(range_obj)
    
    profile = ScannerProfile(
        slug="idem-profile",
        name="Idem Profile",
        description="Profile for testing idempotency",
        tcp_ports="80",
        udp_ports="",
        discovery_enabled=True,
        service_detection_enabled=True,
        vulnerability_detection_enabled=False,
    )
    db_session.add(profile)
    db_session.commit()

    exec1 = ScanExecution(
        range_id=range_obj.id,
        profile_id=profile.id,
        requested_by="user1",
        justification="Idempotency test",
        status="running",
    )
    exec1.profile = profile
    db_session.add(exec1)
    db_session.commit()

    hosts = [
        HostObservation(
            ip_address="192.168.2.20",
            hostname="host-idem",
            os_name="Linux",
            services=[
                EngineServiceObs(protocol="tcp", port=80, state="open", service_name="ssl/http", product="Microsoft IIS httpd"),
            ],
        )
    ]

    # Run _persist_hosts first time
    _persist_hosts(db_session, exec1, hosts)

    # Run _persist_hosts second time with SAME execution_id (reprocessing)
    _persist_hosts(db_session, exec1, hosts)

    service = db_session.query(DiscoveredService).filter_by(port=80).first()
    assert service is not None

    obs_count = db_session.query(ServiceObservation).filter_by(execution_id=exec1.id, service_id=service.id).count()
    assert obs_count == 1, "Reprocessing same execution_id should NOT duplicate ServiceObservation rows"

    risk_count = db_session.query(ServiceRiskAssessment).filter_by(execution_id=exec1.id, service_id=service.id).count()
    assert risk_count == 1, "Reprocessing same execution_id should NOT duplicate ServiceRiskAssessment rows"
