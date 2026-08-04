from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SCANNER_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = "development"
    database_url: str = Field(
        default="sqlite:///./scanner.db",
        validation_alias=AliasChoices("DATABASE_URL", "SCANNER_DATABASE_URL"),
    )
    api_key: SecretStr = SecretStr("development-only-change-me")
    allow_public_targets: bool = False
    max_addresses_per_range: int = Field(default=4096, ge=1, le=65536)
    max_import_records: int = Field(default=2000, ge=1, le=10000)
    max_import_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    worker_poll_seconds: float = Field(default=2.0, ge=0.2, le=60)
    worker_stale_timeout_seconds: float = Field(default=300.0, ge=10.0, le=86400.0)
    scheduler_poll_seconds: float = Field(default=15.0, ge=1, le=300)
    subprocess_output_limit_bytes: int = Field(default=25 * 1024 * 1024, ge=1024)
    nmap_binary: str = "nmap"
    nuclei_binary: str = "nuclei"
    nuclei_templates_dir: Path = Path("/opt/nuclei-templates")
    nuclei_enabled: bool = True
    zabbix_url: str | None = None
    zabbix_token: SecretStr | None = None
    zabbix_host_group: str = "GovSec Scanner"

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: SecretStr, info: object) -> SecretStr:
        secret = value.get_secret_value()
        if len(secret) < 24:
            raise ValueError("SCANNER_API_KEY deve possuir no minimo 24 caracteres")
        return value

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        if not value or value.strip() == "":
            raise ValueError("DATABASE_URL nao pode ser vazia")
        return value

    @model_validator(mode="after")
    def validate_production_database(self) -> "Settings":
        if self.production and self.database_url.startswith("sqlite"):
            raise ValueError("DATABASE_URL com SQLite nao e permitida em ambiente de producao.")
        return self

    @property
    def production(self) -> bool:
        return self.environment.lower() in {"production", "staging"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
