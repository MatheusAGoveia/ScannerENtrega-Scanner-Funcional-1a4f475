from __future__ import annotations

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
