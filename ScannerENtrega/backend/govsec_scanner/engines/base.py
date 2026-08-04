from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path


class EngineUnavailable(RuntimeError):
    pass


class EngineExecutionError(RuntimeError):
    pass


@dataclass
class ServiceObservation:
    protocol: str
    port: int
    state: str = "open"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    tls_details: str | None = None


@dataclass
class HostObservation:
    ip_address: str
    hostname: str | None = None
    state: str = "active"
    os_name: str | None = None
    services: list[ServiceObservation] = field(default_factory=list)


@dataclass
class FindingObservation:
    ip_address: str
    port: int | None
    protocol: str | None
    template_id: str
    name: str
    severity: str
    matched_at: str
    description: str | None = None
    reference: str | None = None


@dataclass
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


async def run_process(
    command: list[str],
    *,
    timeout_seconds: int,
    output_limit_bytes: int,
    cwd: Path | None = None,
) -> ProcessResult:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except TimeoutError as exc:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.kill()
            await process.wait()
        raise EngineExecutionError(
            f"O motor excedeu o limite de {timeout_seconds} segundos."
        ) from exc
    except asyncio.CancelledError:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except TimeoutError:
                process.kill()
                with suppress(Exception):
                    await process.wait()
        raise

    if len(stdout) > output_limit_bytes or len(stderr) > output_limit_bytes:
        raise EngineExecutionError("A saida do motor excedeu o limite de seguranca configurado.")
    return ProcessResult(returncode=process.returncode or 0, stdout=stdout, stderr=stderr)
