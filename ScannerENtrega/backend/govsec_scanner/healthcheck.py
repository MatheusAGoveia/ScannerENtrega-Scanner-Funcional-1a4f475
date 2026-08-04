from __future__ import annotations

import argparse
import sys
from datetime import timedelta

from sqlalchemy import select

from govsec_scanner.database import SessionLocal
from govsec_scanner.models import ServiceHeartbeat, utcnow


def check_health(service_name: str, max_staleness_seconds: float = 30.0) -> bool:
    now = utcnow()
    cutoff = now - timedelta(seconds=max_staleness_seconds)
    with SessionLocal() as db:
        try:
            db.execute(select(1)).scalar_one()
        except Exception as exc:
            print(f"Erro ao conectar ao banco de dados: {exc}", file=sys.stderr)
            return False

        statement = select(ServiceHeartbeat).where(
            ServiceHeartbeat.service_name == service_name,
            ServiceHeartbeat.last_heartbeat_at >= cutoff,
        )
        heartbeats = db.scalars(statement).all()
        if not heartbeats:
            print(
                f"Nenhum heartbeat recente encontrado para o servico '{service_name}' (max_staleness={max_staleness_seconds}s).",
                file=sys.stderr,
            )
            return False

        # Verifica se pelo menos um heartbeat esta em estado operacional
        healthy = [h for h in heartbeats if h.status in ("healthy", "running", "idle")]
        if not healthy:
            print(
                f"Heartbeats encontrados para '{service_name}', mas nenhum em estado operacional.",
                file=sys.stderr,
            )
            return False

        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Health check CLI para servicos do GovSec Scanner.")
    parser.add_argument(
        "--service",
        required=True,
        choices=["worker", "scheduler", "api"],
        help="Nome do servico a ter o heartbeat verificado.",
    )
    parser.add_argument(
        "--max-staleness",
        type=float,
        default=30.0,
        help="Tempo maximo tolerado desde o ultimo heartbeat (em segundos).",
    )
    args = parser.parse_args()

    if check_health(args.service, args.max_staleness):
        print(f"Healthcheck OK para servico '{args.service}'.")
        sys.exit(0)
    else:
        print(f"Healthcheck FALHOU para servico '{args.service}'.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
