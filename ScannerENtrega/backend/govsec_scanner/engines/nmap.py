from __future__ import annotations

import os
import shutil
import socket
import xml.etree.ElementTree as ET
from ipaddress import ip_network

from govsec_scanner.config import Settings
from govsec_scanner.engines.base import (
    EngineExecutionError,
    EngineUnavailable,
    HostObservation,
    ServiceObservation,
    run_process,
)
from govsec_scanner.models import ScannerProfile
from govsec_scanner.scope import address_belongs_to_scope


def _can_use_raw_sockets() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        return True
    except (OSError, PermissionError):
        return False


def _ports(value: str) -> list[int]:
    ports: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError(f"Porta invalida no perfil: {port}")
        ports.append(port)
    return sorted(set(ports))


def build_nmap_command(
    binary: str,
    target: str,
    profile: ScannerProfile,
    *,
    intensity: str,
) -> list[str]:
    tcp_ports = _ports(profile.tcp_ports)
    udp_ports = _ports(profile.udp_ports)
    if not tcp_ports and not udp_ports:
        raise ValueError("O perfil nao possui portas configuradas.")

    can_raw = _can_use_raw_sockets()
    if udp_ports and not can_raw and not tcp_ports:
        raise EngineExecutionError(
            "Varredura UDP via Nmap requer privilegios de raw sockets (root ou CAP_NET_RAW)."
        )

    command = [
        binary,
        "-n",
        "-Pn",
        "--open",
        "--reason",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{max(30, profile.timeout_seconds * 12)}s",
        "--max-rate",
        str(profile.rate_limit_per_second),
        "-oX",
        "-",
    ]
    if tcp_ports:
        command.append("-sT")
    if udp_ports and can_raw:
        command.append("-sU")
    if profile.service_detection_enabled:
        command.extend(["-sV", "--version-light"])
    if intensity == "low":
        command.extend(["-T2", "--scan-delay", "25ms"])
    else:
        command.append("-T3")

    port_specs: list[str] = []
    if tcp_ports:
        port_specs.append("T:" + ",".join(str(port) for port in tcp_ports))
    if udp_ports and can_raw:
        port_specs.append("U:" + ",".join(str(port) for port in udp_ports))

    if not port_specs:
        raise EngineExecutionError(
            "Nenhuma porta valida ou disponivel para varredura sem privilegios de raw sockets."
        )

    command.extend(["-p", ",".join(port_specs), "--", target])
    return command


def parse_nmap_xml(payload: bytes, expected_scope: str) -> list[HostObservation]:
    if not payload or not payload.strip():
        return []
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise EngineExecutionError("O Nmap retornou XML invalido.") from exc

    scope = ip_network(
        expected_scope if "/" in expected_scope else f"{expected_scope}/32", strict=False
    )
    observations: list[HostObservation] = []
    for host_node in root.findall("host"):
        address_node = next(
            (
                node
                for node in host_node.findall("address")
                if node.attrib.get("addrtype") in {"ipv4", "ipv6"}
            ),
            None,
        )
        if address_node is None:
            continue
        address = address_node.attrib.get("addr", "")
        if not address_belongs_to_scope(address, scope):
            raise EngineExecutionError("O Nmap retornou um endereco fora da faixa autorizada.")

        hostname_node = host_node.find("hostnames/hostname")
        os_node = host_node.find("os/osmatch")
        services: list[ServiceObservation] = []
        for port_node in host_node.findall("ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.attrib.get("state") not in {
                "open",
                "open|filtered",
            }:
                continue
            service_node = port_node.find("service")
            services.append(
                ServiceObservation(
                    protocol=port_node.attrib.get("protocol", "tcp"),
                    port=int(port_node.attrib["portid"]),
                    state=state_node.attrib.get("state", "open"),
                    service_name=service_node.attrib.get("name")
                    if service_node is not None
                    else None,
                    product=service_node.attrib.get("product")
                    if service_node is not None
                    else None,
                    version=service_node.attrib.get("version")
                    if service_node is not None
                    else None,
                )
            )
        if services:
            observations.append(
                HostObservation(
                    ip_address=address,
                    hostname=hostname_node.attrib.get("name")
                    if hostname_node is not None
                    else None,
                    os_name=os_node.attrib.get("name") if os_node is not None else None,
                    services=services,
                )
            )
    return observations


class NmapEngine:
    name = "nmap"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def available(self) -> bool:
        return shutil.which(self.settings.nmap_binary) is not None

    async def scan(
        self,
        target: str,
        profile: ScannerProfile,
        *,
        intensity: str,
        maximum_duration_seconds: int,
    ) -> list[HostObservation]:
        if not self.available:
            raise EngineUnavailable("O binario Nmap nao esta instalado no worker.")
        command = build_nmap_command(
            self.settings.nmap_binary, target, profile, intensity=intensity
        )
        result = await run_process(
            command,
            timeout_seconds=maximum_duration_seconds,
            output_limit_bytes=self.settings.subprocess_output_limit_bytes,
        )
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace")[-2000:]
            raise EngineExecutionError(f"Nmap encerrou com codigo {result.returncode}: {message}")
        return parse_nmap_xml(result.stdout, target)
