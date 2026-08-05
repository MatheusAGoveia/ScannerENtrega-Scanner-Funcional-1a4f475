from __future__ import annotations

from dataclasses import dataclass
from typing import Any

@dataclass
class ServiceCatalogItem:
    key: str
    name: str
    category: str
    default_ports: list[int]
    protocol: str
    base_risk: str # 'low', 'medium', 'high', 'critical'
    is_encrypted: bool
    is_remote_access: bool

DEFENSIVE_CATALOG: list[ServiceCatalogItem] = [
    ServiceCatalogItem("http", "HTTP Web Service", "web", [80, 8080], "tcp", "low", False, False),
    ServiceCatalogItem("https", "HTTPS Web Service", "web", [443, 8443], "tcp", "low", True, False),
    ServiceCatalogItem("ssh", "Secure Shell", "remote_access", [22], "tcp", "medium", True, True),
    ServiceCatalogItem("rdp", "Remote Desktop Protocol", "remote_access", [3389], "tcp", "high", True, True),
    ServiceCatalogItem("smb", "Server Message Block", "file_sharing", [445, 139], "tcp", "high", False, False),
    ServiceCatalogItem("ftp", "File Transfer Protocol", "file_sharing", [21], "tcp", "medium", False, False),
    ServiceCatalogItem("smtp", "Simple Mail Transfer Protocol", "mail", [25, 587, 465], "tcp", "low", False, False),
    ServiceCatalogItem("dns", "Domain Name System", "infrastructure", [53], "udp", "low", False, False),
    ServiceCatalogItem("ldap", "Lightweight Directory Access Protocol", "identity", [389], "tcp", "medium", False, False),
    ServiceCatalogItem("ldaps", "LDAP over TLS/SSL", "identity", [636], "tcp", "low", True, False),
    ServiceCatalogItem("mysql", "MySQL Database", "database", [3306], "tcp", "medium", False, False),
    ServiceCatalogItem("postgresql", "PostgreSQL Database", "database", [5432], "tcp", "medium", False, False),
    ServiceCatalogItem("mssql", "Microsoft SQL Server", "database", [1433], "tcp", "medium", False, False),
    ServiceCatalogItem("oracle", "Oracle Database", "database", [1521], "tcp", "medium", False, False),
    ServiceCatalogItem("redis", "Redis In-Memory Store", "database", [6379], "tcp", "high", False, False),
    ServiceCatalogItem("mongodb", "MongoDB Database", "database", [27017], "tcp", "high", False, False),
    ServiceCatalogItem("winrm", "Windows Remote Management", "remote_access", [5985, 5986], "tcp", "medium", True, True),
    ServiceCatalogItem("snmp", "Simple Network Management Protocol", "infrastructure", [161, 162], "udp", "medium", False, False),
    ServiceCatalogItem("vnc", "Virtual Network Computing", "remote_access", [5900], "tcp", "high", False, True),
]

class ServiceCatalog:
    def __init__(self, items: list[ServiceCatalogItem] | None = None) -> None:
        self.items = items or DEFENSIVE_CATALOG
        self._key_map = {item.key: item for item in self.items}
        self._port_map = {port: item for item in self.items for port in item.default_ports}

    def resolve(
        self,
        service_name: str | None = None,
        product: str | None = None,
        port: int | None = None,
    ) -> ServiceCatalogItem | None:
        # Priority 1: Service Name
        if service_name:
            key = service_name.strip().lower()
            if key in self._key_map:
                return self._key_map[key]

        # Priority 2: Product Name
        if product:
            prod = product.strip().lower()
            for item in self.items:
                if item.key in prod or item.name.lower() in prod:
                    return item

        # Priority 3: Fallback Port
        if port and port in self._port_map:
            return self._port_map[port]

        return None

default_catalog = ServiceCatalog()
