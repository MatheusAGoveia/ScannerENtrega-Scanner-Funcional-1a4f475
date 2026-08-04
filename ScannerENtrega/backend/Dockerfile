FROM projectdiscovery/nuclei:latest AS nuclei

FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SCANNER_NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap libcap2-bin ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scanner

COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
RUN mkdir -p /opt/nuclei-templates \
    && nuclei -update-templates -update-template-dir /opt/nuclei-templates \
    && chown -R scanner:scanner /opt/nuclei-templates /home/scanner

WORKDIR /app
COPY pyproject.toml alembic.ini ./
COPY alembic ./alembic
COPY govsec_scanner ./govsec_scanner
RUN pip install .

USER scanner
EXPOSE 8000
CMD ["uvicorn", "govsec_scanner.api:app", "--host", "0.0.0.0", "--port", "8000"]
