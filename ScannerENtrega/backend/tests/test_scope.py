from __future__ import annotations

import pytest

from govsec_scanner.scope import ScopeViolation, address_belongs_to_scope, overlaps, validate_scope


def test_private_scope_is_normalized_and_bounded() -> None:
    scope = validate_scope(
        "10.42.16.7/24",
        max_addresses=256,
        allow_public=False,
        global_public_enabled=False,
    )

    assert scope.normalized == "10.42.16.0/24"
    assert scope.address_count == 256
    assert address_belongs_to_scope("10.42.16.99", scope.network)
    assert not address_belongs_to_scope("10.42.17.1", scope.network)


def test_public_scope_requires_both_authorizations() -> None:
    with pytest.raises(ScopeViolation, match="autorizacao explicita"):
        validate_scope(
            "8.8.8.8",
            max_addresses=1,
            allow_public=True,
            global_public_enabled=False,
        )

    scope = validate_scope(
        "8.8.8.8",
        max_addresses=1,
        allow_public=True,
        global_public_enabled=True,
    )
    assert scope.normalized == "8.8.8.8"


def test_scope_limit_and_overlap() -> None:
    with pytest.raises(ScopeViolation, match="limite configurado"):
        validate_scope(
            "10.0.0.0/16",
            max_addresses=4096,
            allow_public=False,
            global_public_enabled=False,
        )

    assert overlaps("10.0.0.0/24", "10.0.0.10")
    assert not overlaps("10.0.0.0/24", "10.0.1.0/24")
