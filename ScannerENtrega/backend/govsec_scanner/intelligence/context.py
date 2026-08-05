from __future__ import annotations

import ipaddress
from dataclasses import dataclass

@dataclass
class ServiceContext:
    ip_address: str
    is_public_ip: bool
    category: str
    is_remote_access: bool
    is_encrypted: bool

def evaluate_context(
    ip_address: str,
    category: str = "general",
    is_remote_access: bool = False,
    is_encrypted: bool = False,
) -> ServiceContext:
    is_public = False
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        is_public = not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local
    except ValueError:
        is_public = False

    return ServiceContext(
        ip_address=ip_address,
        is_public_ip=is_public,
        category=category,
        is_remote_access=is_remote_access,
        is_encrypted=is_encrypted,
    )
