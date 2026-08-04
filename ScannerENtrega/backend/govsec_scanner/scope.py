from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network


class ScopeViolation(ValueError):
    """O alvo solicitado nao atende as regras de autorizacao do scanner."""


Network = IPv4Network | IPv6Network
Address = IPv4Address | IPv6Address


@dataclass(frozen=True)
class ValidatedScope:
    normalized: str
    network: Network
    address_count: int


def validate_scope(
    value: str,
    *,
    max_addresses: int,
    allow_public: bool,
    global_public_enabled: bool,
) -> ValidatedScope:
    raw = value.strip()
    if not raw:
        raise ScopeViolation("Informe um IP individual ou bloco CIDR.")
    if any(char.isspace() for char in raw):
        raise ScopeViolation("O alvo deve conter apenas um IP ou CIDR por cadastro.")

    try:
        network = ip_network(raw if "/" in raw else f"{raw}/32", strict=False)
    except ValueError as exc:
        raise ScopeViolation("IP ou bloco CIDR invalido.") from exc

    address_count = int(network.num_addresses)
    if address_count > max_addresses:
        raise ScopeViolation(
            f"A faixa contem {address_count} enderecos; o limite configurado e {max_addresses}."
        )

    is_public = any(
        address.is_global for address in (network.network_address, network.broadcast_address)
    )
    if is_public and not (allow_public and global_public_enabled):
        raise ScopeViolation(
            "Faixas publicas exigem autorizacao explicita no cadastro e no servidor."
        )

    normalized = (
        str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
    )
    return ValidatedScope(normalized=normalized, network=network, address_count=address_count)


def address_belongs_to_scope(address: str, scope: Network) -> bool:
    try:
        return ip_address(address) in scope
    except ValueError:
        return False


def overlaps(left: str, right: str) -> bool:
    left_network = ip_network(left if "/" in left else f"{left}/32", strict=False)
    right_network = ip_network(right if "/" in right else f"{right}/32", strict=False)
    return left_network.version == right_network.version and left_network.overlaps(right_network)
