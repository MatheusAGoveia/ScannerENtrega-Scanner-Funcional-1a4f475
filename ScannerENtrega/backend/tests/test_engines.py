from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from govsec_scanner.config import Settings
from govsec_scanner.engines.banner import BannerEngine
from govsec_scanner.engines.base import EngineExecutionError, HostObservation, ServiceObservation
from govsec_scanner.engines.nmap import NmapEngine, build_nmap_command, parse_nmap_xml
from govsec_scanner.engines.nuclei import (
    NucleiEngine,
    build_nuclei_command,
    parse_nuclei_jsonl,
    target_urls,
)
from govsec_scanner.models import ScannerProfile

NMAP_XML = b"""<?xml version='1.0'?>
<nmaprun><host><address addr='10.42.16.12' addrtype='ipv4'/>
<hostnames><hostname name='portal.local'/></hostnames>
<ports><port protocol='tcp' portid='443'><state state='open'/>
<service name='https' product='nginx' version='1.26'/></port></ports>
</host></nmaprun>"""


def _settings(**values: object) -> Settings:
    return Settings(api_key="test-api-key-with-at-least-24-chars", **values)


def _fake_executable(path: Path, payload: bytes) -> Path:
    if sys.platform == "win32" and not path.suffix:
        path = path.with_suffix(".bat")
    encoded = payload.hex()
    if sys.platform == "win32":
        path.write_text(
            f'@echo off\n"{sys.executable}" -c "import sys; sys.stdout.buffer.write(bytes.fromhex(\'{encoded}\'))"\n',
            encoding="utf-8",
        )
    else:
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.stdout.buffer.write(bytes.fromhex('{encoded}'))\n",
            encoding="utf-8",
        )
        path.chmod(0o700)
    return path


def test_nmap_command_has_bounded_defensive_flags(scanner_profile: ScannerProfile) -> None:
    command = build_nmap_command("nmap", "10.42.16.0/24", scanner_profile, intensity="low")

    assert command[0] == "nmap"
    assert command[-1] == "10.42.16.0/24"
    assert command[-2] == "--"
    assert "-sT" in command and "-sU" in command and "-sV" in command
    assert "--max-rate" in command and "--host-timeout" in command
    assert "-T2" in command


def test_nmap_empty_xml_returns_empty_list() -> None:
    assert parse_nmap_xml(b"", "10.42.16.0/24") == []
    assert parse_nmap_xml(b"\n  \n", "10.42.16.0/24") == []


def test_nuclei_jsonl_skips_malformed_lines_gracefully() -> None:
    valid_item = json.dumps({
        "template-id": "ssl-cert",
        "ip": "10.42.16.12",
        "matched-at": "https://10.42.16.12:443",
        "info": {"name": "Certificado SSL", "severity": "low"},
    })
    payload = f"INVALID_NON_JSON_LINE\n{valid_item}\nANOTHER_CORRUPTED_LINE\n".encode()
    findings = parse_nuclei_jsonl(payload, "10.42.16.0/24")

    assert len(findings) == 1
    assert findings[0].template_id == "ssl-cert"
    assert findings[0].ip_address == "10.42.16.12"


def test_nmap_xml_must_remain_inside_scope() -> None:
    hosts = parse_nmap_xml(NMAP_XML, "10.42.16.0/24")
    assert hosts[0].ip_address == "10.42.16.12"
    assert hosts[0].services[0].port == 443

    with pytest.raises(EngineExecutionError, match="fora da faixa"):
        parse_nmap_xml(NMAP_XML, "10.42.17.0/24")


def test_real_nmap_adapter_executes_a_bounded_subprocess(
    tmp_path: Path, scanner_profile: ScannerProfile
) -> None:
    binary = _fake_executable(tmp_path / "nmap-controlled", NMAP_XML)
    engine = NmapEngine(_settings(nmap_binary=str(binary)))

    hosts = asyncio.run(
        engine.scan(
            "10.42.16.0/24",
            scanner_profile,
            intensity="low",
            maximum_duration_seconds=5,
        )
    )

    assert engine.available
    assert [(host.ip_address, host.services[0].port) for host in hosts] == [("10.42.16.12", 443)]


def test_nuclei_adapter_is_non_intrusive_and_scope_checked(
    tmp_path: Path, scanner_profile: ScannerProfile
) -> None:
    host = HostObservation(
        ip_address="10.42.16.12",
        services=[ServiceObservation(protocol="tcp", port=443, service_name="https")],
    )
    assert target_urls([host]) == ["https://10.42.16.12"]

    command = build_nuclei_command("nuclei", tmp_path / "targets.txt", scanner_profile, tmp_path)
    excluded = command[command.index("-exclude-tags") + 1]
    assert {"fuzz", "dos", "intrusive", "bruteforce"}.issubset(set(excluded.split(",")))
    assert "-no-interactsh" in command and "-rate-limit" in command

    result = {
        "template-id": "tls-version",
        "ip": "10.42.16.12",
        "matched-at": "https://10.42.16.12:443",
        "info": {"name": "Versao TLS observada", "severity": "low"},
    }
    templates = tmp_path / "templates"
    templates.mkdir()
    binary = _fake_executable(
        tmp_path / "nuclei-controlled", (json.dumps(result) + "\n").encode()
    )
    engine = NucleiEngine(_settings(nuclei_binary=str(binary), nuclei_templates_dir=templates))

    findings = asyncio.run(
        engine.scan("10.42.16.0/24", [host], scanner_profile, maximum_duration_seconds=5)
    )
    assert findings[0].template_id == "tls-version"
    assert findings[0].port == 443

    outside = json.dumps({**result, "ip": "10.42.17.12"}).encode()
    with pytest.raises(EngineExecutionError, match="fora da faixa"):
        parse_nuclei_jsonl(outside, "10.42.16.0/24")


def test_banner_engine_collects_a_real_local_http_banner() -> None:
    async def scenario() -> tuple[int, str | None]:
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(2048)
            writer.write(b"HTTP/1.0 200 OK\r\nServer: govsec-test\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        service = ServiceObservation(protocol="tcp", port=port, service_name="http")
        host = HostObservation(ip_address="127.0.0.1", services=[service])
        try:
            count = await BannerEngine().enrich([host], timeout_seconds=2, max_parallelism=1)
            return count, service.banner
        finally:
            server.close()
            await server.wait_closed()

    enriched, banner = asyncio.run(scenario())
    assert enriched == 1
    assert banner is not None and "Server: govsec-test" in banner


def test_tls_verification_is_strict_by_default() -> None:
    import ssl
    ctx = ssl.create_default_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
