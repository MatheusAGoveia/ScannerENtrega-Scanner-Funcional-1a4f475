from __future__ import annotations

import asyncio
import json
import re
import ssl

from govsec_scanner.engines.base import HostObservation, ServiceObservation

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 9000}
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443}
CONTROL_CHARACTERS = re.compile(r"[^\x09\x0a\x0d\x20-\x7e]")


def _clean_banner(payload: bytes) -> str | None:
    if not payload:
        return None
    text = payload.decode("utf-8", errors="replace")
    text = CONTROL_CHARACTERS.sub("", text).strip()
    return text[:1024] or None


class BannerEngine:
    name = "banner_tls"

    async def enrich(
        self,
        hosts: list[HostObservation],
        *,
        timeout_seconds: int,
        max_parallelism: int,
    ) -> int:
        semaphore = asyncio.Semaphore(max_parallelism)

        async def inspect(host: HostObservation, service: ServiceObservation) -> bool:
            if service.protocol != "tcp":
                return False
            async with semaphore:
                try:
                    banner, tls_details = await asyncio.wait_for(
                        self._inspect_service(host.ip_address, service),
                        timeout=max(1, timeout_seconds),
                    )
                except (TimeoutError, OSError, ssl.SSLError):
                    return False
                service.banner = banner
                service.tls_details = tls_details
                return bool(banner or tls_details)

        tasks = [inspect(host, service) for host in hosts for service in host.services]
        results = await asyncio.gather(*tasks) if tasks else []
        return sum(1 for result in results if result)

    async def _inspect_service(
        self,
        ip_address: str,
        service: ServiceObservation,
    ) -> tuple[str | None, str | None]:
        ssl_context: ssl.SSLContext | None = None
        tls_details: str | None = None
        is_tls = service.port in TLS_PORTS or (service.service_name or "").lower() in {
            "https",
            "ssl/http",
        }

        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None

        if is_tls:
            ssl_context = ssl.create_default_context()
            hostname = ip_address
            try:
                reader, writer = await asyncio.open_connection(
                    ip_address,
                    service.port,
                    ssl=ssl_context,
                    server_hostname=hostname,
                )
                ssl_object = writer.get_extra_info("ssl_object")
                if ssl_object is not None:
                    tls_details = json.dumps(
                        {
                            "version": ssl_object.version(),
                            "cipher": ssl_object.cipher()[0] if ssl_object.cipher() else None,
                            "verified": True,
                        },
                        separators=(",", ":"),
                    )
            except (ssl.SSLCertVerificationError, ssl.CertificateError):
                # Fallback: Second unverified connection attempted ONLY for specific certificate validation errors
                unverified_context = ssl.create_default_context()
                unverified_context.check_hostname = False
                unverified_context.verify_mode = ssl.CERT_NONE
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            ip_address,
                            service.port,
                            ssl=unverified_context,
                            server_hostname=None,
                        ),
                        timeout=2.0,
                    )
                    if writer is not None:
                        ssl_object = writer.get_extra_info("ssl_object")
                        if ssl_object is not None:
                            tls_details = json.dumps(
                                {
                                    "version": ssl_object.version(),
                                    "cipher": ssl_object.cipher()[0] if ssl_object.cipher() else None,
                                    "verified": False,
                                },
                                separators=(",", ":"),
                            )
                except (TimeoutError, OSError, ssl.SSLError):
                    return None, None
            except (TimeoutError, OSError, ssl.SSLError):
                # Generic network/OS/timeout errors DO NOT trigger fallback
                return None, None
        else:
            reader, writer = await asyncio.open_connection(
                ip_address,
                service.port,
                ssl=None,
            )

        if reader is None or writer is None:
            return None, None

        if (
            service.port in HTTP_PORTS
            or is_tls
            or "http" in (service.service_name or "")
        ):
            writer.write(
                f"HEAD / HTTP/1.0\r\nHost: {ip_address}\r\nUser-Agent: GovSec-Scanner/1.0\r\nConnection: close\r\n\r\n".encode()
            )
            await writer.drain()
        try:
            payload = await asyncio.wait_for(reader.read(2048), timeout=2)
        except TimeoutError:
            payload = b""
        writer.close()
        await writer.wait_closed()
        return _clean_banner(payload), tls_details
