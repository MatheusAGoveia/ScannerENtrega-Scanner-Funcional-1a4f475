from __future__ import annotations

import json
import shutil
import tempfile
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlparse

from govsec_scanner.config import Settings
from govsec_scanner.engines.base import (
    EngineExecutionError,
    EngineUnavailable,
    FindingObservation,
    HostObservation,
    run_process,
)
from govsec_scanner.models import ScannerProfile
from govsec_scanner.scope import address_belongs_to_scope


def target_urls(hosts: list[HostObservation]) -> list[str]:
    urls: set[str] = set()
    for host in hosts:
        for service in host.services:
            name = (service.service_name or "").lower()
            if service.protocol != "tcp" or (
                "http" not in name
                and service.port not in {80, 443, 8000, 8080, 8081, 8443, 8888, 9000}
            ):
                continue
            scheme = "https" if service.port in {443, 8443} or "https" in name else "http"
            default_port = (scheme == "http" and service.port == 80) or (
                scheme == "https" and service.port == 443
            )
            suffix = "" if default_port else f":{service.port}"
            urls.add(f"{scheme}://{host.ip_address}{suffix}")
    return sorted(urls)


def build_nuclei_command(
    binary: str,
    list_path: Path,
    profile: ScannerProfile,
    templates_dir: Path,
) -> list[str]:
    return [
        binary,
        "-list",
        str(list_path),
        "-templates",
        str(templates_dir),
        "-jsonl",
        "-silent",
        "-no-color",
        "-no-interactsh",
        "-disable-update-check",
        "-severity",
        "low,medium,high,critical",
        "-exclude-tags",
        "fuzz,dos,intrusive,bruteforce,default-login",
        "-type",
        "http,ssl,tcp",
        "-rate-limit",
        str(profile.rate_limit_per_second),
        "-bulk-size",
        str(max(1, min(profile.max_parallelism, 10))),
        "-concurrency",
        str(max(1, min(profile.max_parallelism, 10))),
        "-timeout",
        str(max(1, min(profile.timeout_seconds, 30))),
        "-retries",
        "0",
        "-response-size-read",
        "2",
        "-omit-raw",
        "-omit-template",
    ]


def parse_nuclei_jsonl(payload: bytes, expected_scope: str) -> list[FindingObservation]:
    scope = ip_network(
        expected_scope if "/" in expected_scope else f"{expected_scope}/32", strict=False
    )
    findings: list[FindingObservation] = []
    for raw_line in payload.splitlines():
        if not raw_line.strip():
            continue
        try:
            item = json.loads(raw_line)
        except (json.JSONDecodeError, TypeError):
            continue
        parsed = urlparse(str(item.get("matched-at") or item.get("host") or ""))
        host_value = str(item.get("ip") or parsed.hostname or "")
        try:
            normalized_ip = str(ip_address(host_value))
        except ValueError as exc:
            raise EngineExecutionError("O Nuclei retornou um achado sem IP verificavel.") from exc
        if not address_belongs_to_scope(normalized_ip, scope):
            raise EngineExecutionError("O Nuclei retornou um endereco fora da faixa autorizada.")
        try:
            matched_port = parsed.port
        except ValueError as exc:
            raise EngineExecutionError("O Nuclei retornou uma porta invalida.") from exc
        info = item.get("info") or {}
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        findings.append(
            FindingObservation(
                ip_address=normalized_ip,
                port=matched_port,
                protocol="tcp" if parsed.scheme in {"http", "https"} else None,
                template_id=str(
                    item.get("template-id") or item.get("templateID") or "nuclei-unknown"
                ),
                name=str(info.get("name") or "Achado Nuclei"),
                severity=str(info.get("severity") or "unknown").lower(),
                matched_at=str(item.get("matched-at") or item.get("host") or normalized_ip),
                description=str(info.get("description"))[:4000]
                if info.get("description")
                else None,
                reference="\n".join(str(ref) for ref in references[:20]) or None,
            )
        )
    return findings


class NucleiEngine:
    name = "nuclei"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def available(self) -> bool:
        return (
            self.settings.nuclei_enabled
            and shutil.which(self.settings.nuclei_binary) is not None
            and self.settings.nuclei_templates_dir.exists()
        )

    async def scan(
        self,
        scope: str,
        hosts: list[HostObservation],
        profile: ScannerProfile,
        *,
        maximum_duration_seconds: int,
    ) -> list[FindingObservation]:
        urls = target_urls(hosts)
        if not urls:
            return []
        if not self.available:
            raise EngineUnavailable("Nuclei ou seus templates nao estao disponiveis no worker.")

        with tempfile.TemporaryDirectory(prefix="govsec-nuclei-") as temp_dir:
            list_path = Path(temp_dir) / "targets.txt"
            list_path.write_text("\n".join(urls) + "\n", encoding="utf-8")
            command = build_nuclei_command(
                self.settings.nuclei_binary,
                list_path,
                profile,
                self.settings.nuclei_templates_dir,
            )
            result = await run_process(
                command,
                timeout_seconds=maximum_duration_seconds,
                output_limit_bytes=self.settings.subprocess_output_limit_bytes,
            )
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace")[-2000:]
            raise EngineExecutionError(f"Nuclei encerrou com codigo {result.returncode}: {message}")
        return parse_nuclei_jsonl(result.stdout, scope)
