from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Field names match .env.example exactly - see backend/app/core/config.py for the sibling copy."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    cyberstream_mode: str = "dev"

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_consumer_group: str = "cyberstream-processing"
    kafka_client_id: str = "cyberstream-generator"
    kafka_producer_acks: str = "all"
    kafka_producer_compression: str = "snappy"

    generator_default_rate: int = 100
    generator_seed: int = 42

    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
