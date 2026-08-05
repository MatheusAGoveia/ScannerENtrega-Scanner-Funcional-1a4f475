from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SERVICE_ALIASES = {
    "ssl/http": "https",
    "https-alt": "https",
    "http-proxy": "http",
    "ms-wbt-server": "rdp",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "domain": "dns",
    "imaps": "imap",
    "pop3s": "pop3",
    "smtps": "smtp",
    "submission": "smtp",
    "veritas-dedup": "veritas",
}

PRODUCT_ALIASES = {
    "microsoft iis httpd": "iis",
    "microsoft-iis": "iis",
    "apache httpd": "apache",
    "nginx": "nginx",
    "openssh": "openssh",
    "openssh sshd": "openssh",
}

@dataclass
class NormalizedServiceData:
    service_name_raw: str | None
    service_name_normalized: str | None
    product_raw: str | None
    product_normalized: str | None
    version_raw: str | None
    version_normalized: str | None
    cpe: str | None

def normalize_service_name(
    raw_name: str | None,
    port: int | None = None,
    protocol: str | None = None,
) -> str | None:
    if not raw_name:
        return None
    cleaned = raw_name.strip().lower()
    return SERVICE_ALIASES.get(cleaned, cleaned)

def normalize_product(raw_product: str | None) -> str | None:
    if not raw_product:
        return None
    cleaned = raw_product.strip().lower()
    if cleaned in ("unknown", "generic", "null", ""):
        return None
    return PRODUCT_ALIASES.get(cleaned, cleaned)

def normalize_version(raw_version: str | None) -> str | None:
    if not raw_version:
        return None
    cleaned = raw_version.strip()
    if cleaned.lower() in ("unknown", "generic", "null", ""):
        return None
    return cleaned

def extract_or_build_cpe(product: str | None, version: str | None) -> str | None:
    prod_norm = normalize_product(product)
    ver_norm = normalize_version(version)
    if not prod_norm:
        return None
    
    # Simple deterministic CPE builder for standard products
    cpe_vendor_product_map = {
        "iis": ("microsoft", "internet_information_services"),
        "apache": ("apache", "http_server"),
        "nginx": ("nginx", "nginx"),
        "openssh": ("openbsd", "openssh"),
    }
    
    if prod_norm in cpe_vendor_product_map:
        vendor, cpe_prod = cpe_vendor_product_map[prod_norm]
        ver_part = ver_norm if ver_norm else "*"
        return f"cpe:2.3:a:{vendor}:{cpe_prod}:{ver_part}:*:*:*:*:*:*:*"
    
    return None

def normalize_service_observation(
    service_name: str | None,
    product: str | None,
    version: str | None,
    port: int | None = None,
    protocol: str | None = None,
    cpe_raw: str | None = None,
) -> NormalizedServiceData:
    norm_name = normalize_service_name(service_name, port, protocol)
    norm_product = normalize_product(product)
    norm_version = normalize_version(version)
    cpe = cpe_raw or extract_or_build_cpe(norm_product, norm_version)
    
    return NormalizedServiceData(
        service_name_raw=service_name,
        service_name_normalized=norm_name,
        product_raw=product,
        product_normalized=norm_product,
        version_raw=version,
        version_normalized=norm_version,
        cpe=cpe,
    )
