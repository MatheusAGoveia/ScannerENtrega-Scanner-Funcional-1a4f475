import hmac
from typing import Annotated

from fastapi import Header, HTTPException, status

from govsec_scanner.config import get_settings


def require_api_key(
    x_scanner_api_key: Annotated[str | None, Header()] = None,
) -> None:
    expected = get_settings().api_key.get_secret_value()
    if not x_scanner_api_key or not hmac.compare_digest(x_scanner_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credencial do scanner ausente ou invalida.",
        )


def actor_from_header(
    x_scanner_actor: Annotated[str | None, Header()] = None,
) -> str:
    actor = (x_scanner_actor or "operador-scanner").strip()
    return actor[:120] or "operador-scanner"
