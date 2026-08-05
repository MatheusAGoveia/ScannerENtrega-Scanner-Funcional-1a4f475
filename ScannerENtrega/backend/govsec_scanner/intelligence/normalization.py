from __future__ import annotations

from dataclasses import dataclass

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
    """Deprecated compatibility shim.

    A product/version pair is not sufficient evidence to create a CPE.  CPEs
    are therefore retained only when supplied by a scanner that reported one.
    """
    del product, version
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
    # Do not infer a CPE.  It is scanner evidence, not a normalization result.
    cpe = cpe_raw.strip() if cpe_raw and cpe_raw.strip() else None
    
    return NormalizedServiceData(
        service_name_raw=service_name,
        service_name_normalized=norm_name,
        product_raw=product,
        product_normalized=norm_product,
        version_raw=version,
        version_normalized=norm_version,
        cpe=cpe,
    )
