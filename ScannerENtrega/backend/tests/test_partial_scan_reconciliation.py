import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from govsec_scanner.models import Base, DiscoveredAsset, DiscoveredService, ScanExecution, ScannerProfile, AuthorizedRange
from govsec_scanner.engines.base import HostObservation, ServiceObservation
from govsec_scanner.services import _persist_hosts

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_partial_scan_reconciliation(db_session):
    range_obj = AuthorizedRange(
        name="Test Range",
        cidr="10.0.0.0/24",
        address_count=256,
        environment="test",
        owner="sec-team",
        authorization_reference="AUTH-123",
        enabled=True,
        allow_public=False
    )
    db_session.add(range_obj)
    
    full_profile = ScannerProfile(
        slug="full-profile",
        name="Full Profile",
        description="Full Profile Description",
        tcp_ports="22,80,443",
        udp_ports="",
        discovery_enabled=True,
        service_detection_enabled=True,
        vulnerability_detection_enabled=False
    )
    db_session.add(full_profile)
    db_session.commit()
    
    execution1 = ScanExecution(
        range_id=range_obj.id,
        profile_id=full_profile.id,
        requested_by="tester",
        justification="Test scan 1",
        status="running"
    )
    execution1.profile = full_profile
    db_session.add(execution1)
    db_session.commit()
    
    hosts_scan1 = [
        HostObservation(
            ip_address="10.0.0.1",
            hostname="server1",
            os_name="Linux",
            services=[
                ServiceObservation(protocol="tcp", port=22, state="open", service_name="ssh"),
                ServiceObservation(protocol="tcp", port=80, state="open", service_name="http"),
                ServiceObservation(protocol="tcp", port=443, state="open", service_name="https"),
            ]
        )
    ]
    _persist_hosts(db_session, execution1, hosts_scan1)
    
    s22 = db_session.query(DiscoveredService).filter_by(port=22).first()
    assert s22 is not None
    assert s22.state == "open"
    
    partial_profile = ScannerProfile(
        slug="partial-profile",
        name="Partial Profile",
        description="Partial Profile Description",
        tcp_ports="80,443",
        udp_ports="",
        discovery_enabled=True,
        service_detection_enabled=True,
        vulnerability_detection_enabled=False
    )
    db_session.add(partial_profile)
    db_session.commit()
    
    execution2 = ScanExecution(
        range_id=range_obj.id,
        profile_id=partial_profile.id,
        requested_by="tester",
        justification="Test scan 2",
        status="running"
    )
    execution2.profile = partial_profile
    db_session.add(execution2)
    db_session.commit()
    
    # Nmap must report an explicit closed state before current inventory is
    # changed; a missing port in a partial scan is NOT evidence of closure.
    hosts_scan2 = [
        HostObservation(
            ip_address="10.0.0.1",
            hostname="server1",
            os_name="Linux",
            services=[
                ServiceObservation(protocol="tcp", port=80, state="open", service_name="http"),
                ServiceObservation(protocol="tcp", port=443, state="open", service_name="https"),
            ]
        )
    ]
    _persist_hosts(db_session, execution2, hosts_scan2)
    
    db_session.refresh(s22)
    assert s22.state == "open", "Port 22 state should remain 'open' after partial scan"

def test_complete_scan_closes_port(db_session):
    range_obj = AuthorizedRange(
        name="Test Range 2",
        cidr="10.0.1.0/24",
        address_count=256,
        environment="test",
        owner="sec-team",
        authorization_reference="AUTH-124",
        enabled=True,
        allow_public=False
    )
    db_session.add(range_obj)
    
    full_profile = ScannerProfile(
        slug="full-profile-2",
        name="Full Profile 2",
        description="Full Profile Description 2",
        tcp_ports="22,80,443",
        udp_ports="",
        discovery_enabled=True,
        service_detection_enabled=True,
        vulnerability_detection_enabled=False
    )
    db_session.add(full_profile)
    db_session.commit()
    
    execution1 = ScanExecution(
        range_id=range_obj.id,
        profile_id=full_profile.id,
        requested_by="tester",
        justification="Test scan 1",
        status="running"
    )
    execution1.profile = full_profile
    db_session.add(execution1)
    db_session.commit()
    
    hosts_scan1 = [
        HostObservation(
            ip_address="10.0.1.1",
            hostname="server2",
            os_name="Linux",
            services=[
                ServiceObservation(protocol="tcp", port=22, state="open", service_name="ssh"),
            ]
        )
    ]
    _persist_hosts(db_session, execution1, hosts_scan1)
    
    s22 = db_session.query(DiscoveredService).filter_by(port=22).first()
    assert s22.state == "open"
    
    execution2 = ScanExecution(
        range_id=range_obj.id,
        profile_id=full_profile.id,
        requested_by="tester",
        justification="Test scan 2",
        status="running"
    )
    execution2.profile = full_profile
    db_session.add(execution2)
    db_session.commit()
    
    hosts_scan2 = [
        HostObservation(
            ip_address="10.0.1.1",
            hostname="server2",
            os_name="Linux",
            services=[
                ServiceObservation(protocol="tcp", port=22, state="closed", service_name="ssh"),
            ]
        )
    ]
    _persist_hosts(db_session, execution2, hosts_scan2)
    
    db_session.refresh(s22)
    assert s22.state == "closed"
