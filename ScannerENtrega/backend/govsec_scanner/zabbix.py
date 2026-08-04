from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from govsec_scanner.config import Settings
from govsec_scanner.engines.base import HostObservation


class ZabbixError(RuntimeError):
    pass


@dataclass
class ZabbixSyncResult:
    linked: int
    pending: int


class ZabbixClient:
    """Reconcilia apenas hosts ja existentes; nao cria hosts sem aprovacao no Zabbix."""

    def __init__(self, settings: Settings) -> None:
        self.url = settings.zabbix_url
        self.token = settings.zabbix_token.get_secret_value() if settings.zabbix_token else None

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)

    def _call(self, method: str, params: dict[str, object]) -> object:
        if not self.configured:
            raise ZabbixError("Integracao Zabbix nao configurada.")
        assert self.url is not None
        assert self.token is not None
        payload = json.dumps(
            {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        ).encode()
        request = Request(
            self.url,
            data=payload,
            headers={
                "Content-Type": "application/json-rpc",
                "Authorization": f"Bearer {self.token}",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                result = json.loads(response.read())
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ZabbixError("Falha de comunicacao com o Zabbix.") from exc
        if result.get("error"):
            raise ZabbixError(f"Zabbix rejeitou a operacao: {result['error']}")
        return result.get("result")

    def reconcile(self, hosts: list[HostObservation]) -> ZabbixSyncResult:
        linked = 0
        pending = 0
        for host in hosts:
            interfaces = self._call(
                "hostinterface.get",
                {
                    "output": ["interfaceid", "hostid", "ip"],
                    "filter": {"ip": [host.ip_address]},
                },
            )
            if not isinstance(interfaces, list) or not interfaces:
                pending += 1
                continue
            linked += 1
        return ZabbixSyncResult(linked=linked, pending=pending)
