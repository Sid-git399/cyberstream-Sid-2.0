from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Every field name matches a variable in .env.example exactly (case
    differs only by the standard upper/lower convention). Do not rename a
    field without updating .env.example, docker-compose.yml, and this
    docstring's counterparts in generator/config.py and streaming/src/config.py.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    cyberstream_mode: str = "dev"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "cyberstream"
    postgres_user: str = "cyberstream"
    postgres_password: str = "changeme_dev_only"

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_consumer_group: str = "cyberstream-processing"

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_cors_origins: str = "http://localhost:5173"
    log_level: str = "INFO"

    retention_alerts_days: int = 90
    retention_incidents_days: int = 180

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.api_cors_origins.split(",") if o.strip()]

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
