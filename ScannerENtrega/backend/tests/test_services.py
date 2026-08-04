from __future__ import annotations

import asyncio
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from govsec_scanner.config import Settings
from govsec_scanner.database import Base
from govsec_scanner.engines.banner import BannerEngine
from govsec_scanner.engines.base import FindingObservation, HostObservation, ServiceObservation
from govsec_scanner.engines.nmap import NmapEngine
from govsec_scanner.engines.nuclei import NucleiEngine
from govsec_scanner.models import (
    AuthorizedRange,
    DiscoveredAsset,
    EngineRun,
    ScanExecution,
    ScannerProfile,
    VulnerabilityFinding,
)
from govsec_scanner.services import execute_scan, seed_profiles


def test_worker_pipeline_persists_real_engine_results(tmp_path: Path, monkeypatch: object) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'worker.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)

    async def nmap_scan(*args: object, **kwargs: object) -> list[HostObservation]:
        return [
            HostObservation(
                ip_address="127.0.0.1",
                hostname="scanner-test",
                services=[
                    ServiceObservation(
                        protocol="tcp", port=8080, service_name="http", product="test-http"
                    )
                ],
            )
        ]

    async def banner_enrich(
        self: BannerEngine,
        hosts: list[HostObservation],
        **kwargs: object,
    ) -> int:
        hosts[0].services[0].banner = "HTTP/1.0 200 OK"
        return 1

    async def nuclei_scan(*args: object, **kwargs: object) -> list[FindingObservation]:
        return [
            FindingObservation(
                ip_address="127.0.0.1",
                port=8080,
                protocol="tcp",
                template_id="test-observation",
                name="Observacao controlada",
                severity="low",
                matched_at="http://127.0.0.1:8080",
            )
        ]

    monkeypatch.setattr(NmapEngine, "scan", nmap_scan)  # type: ignore[attr-defined]
    monkeypatch.setattr(BannerEngine, "enrich", banner_enrich)  # type: ignore[attr-defined]
    monkeypatch.setattr(NucleiEngine, "scan", nuclei_scan)  # type: ignore[attr-defined]

    with local_session() as db:
        seed_profiles(db)
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "vulnerability"))
        assert profile is not None
        authorized_range = AuthorizedRange(
            name="Loopback autorizado",
            cidr="127.0.0.1",
            address_count=1,
            environment="Teste",
            owner="QA",
            authorization_reference="AUT-PIPELINE-001",
        )
        db.add(authorized_range)
        db.flush()
        execution = ScanExecution(
            range_id=authorized_range.id,
            profile_id=profile.id,
            status="running",
            trigger_type="manual",
            requested_by="pytest",
            justification="Validacao integrada do pipeline.",
        )
        db.add(execution)
        db.commit()
        execution_id = execution.id

        settings = Settings(
            api_key="test-api-key-with-at-least-24-chars",
            nuclei_templates_dir=tmp_path,
        )
        asyncio.run(execute_scan(db, execution_id, settings))

        persisted = db.get(ScanExecution, execution_id)
        assert persisted is not None
        assert persisted.status == "completed"
        assert persisted.active_ips == 1
        assert persisted.services_discovered == 1
        assert persisted.vulnerabilities_discovered == 1
        assert db.scalar(select(DiscoveredAsset).where(DiscoveredAsset.ip_address == "127.0.0.1"))
        assert db.scalar(
            select(VulnerabilityFinding).where(
                VulnerabilityFinding.template_id == "test-observation"
            )
        )
        assert len(db.scalars(select(EngineRun)).all()) == 3

    engine.dispose()


def test_sanitize_db_url_redacts_password() -> None:
    from govsec_scanner.database import sanitize_db_url

    raw_url = "postgresql+psycopg://govsec_user:secret_password_123@postgres_host:5432/govsec_db"
    sanitized = sanitize_db_url(raw_url)
    assert "secret_password_123" not in sanitized
    assert sanitized == "postgresql+psycopg://govsec_user:[redacted]@postgres_host:5432/govsec_db"


def test_production_environment_rejects_sqlite() -> None:
    import pytest

    with pytest.raises(ValueError, match="DATABASE_URL com SQLite nao e permitida"):
        Settings(
            environment="production",
            database_url="sqlite:///./scanner.db",
            api_key="test-api-key-with-at-least-24-chars",
        )
