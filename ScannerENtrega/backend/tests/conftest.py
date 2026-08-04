import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./scanner.db")
os.environ.setdefault("SCANNER_API_KEY", "test-api-key-with-at-least-24-chars")

import pytest

from govsec_scanner.models import ScannerProfile


@pytest.fixture
def scanner_profile() -> ScannerProfile:
    return ScannerProfile(
        slug="test",
        name="Perfil de teste",
        description="Perfil controlado para os testes automatizados.",
        discovery_enabled=True,
        service_detection_enabled=True,
        vulnerability_detection_enabled=True,
        tcp_ports="22,80,443",
        udp_ports="53",
        timeout_seconds=2,
        max_parallelism=2,
        rate_limit_per_second=5,
        active=True,
    )
