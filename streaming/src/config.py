from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Field names match .env.example exactly - see backend/app/core/config.py
    and generator/config.py for the sibling copies. Phase 5 imports this
    module from streaming/src/main.py once the real Structured Streaming
    job is written; nothing here is thrown away, only built upon.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    cyberstream_mode: str = "dev"

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_consumer_group: str = "cyberstream-processing"
    kafka_starting_offsets: str = "latest"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "cyberstream"
    postgres_user: str = "cyberstream"
    postgres_password: str = "changeme_dev_only"

    spark_master: str = "local[*]"
    spark_checkpoint_dir: str = "/data/checkpoints"
    spark_shuffle_partitions_dev: int = 4
    spark_shuffle_partitions_loadtest: int = 16
    spark_watermark_delay_minutes: int = 5
    spark_trigger_interval_seconds: int = 10

    parquet_data_dir: str = "/data/parquet"
    privileged_users: str = "admin,root,backup,administrator"

    detection_engine_enabled: bool = True
    detection_rules_config_path: str | None = None  # None = auto-discover infrastructure/spark/detection_rules.yaml

    log_level: str = "INFO"

    @property
    def privileged_users_list(self) -> list[str]:
        return [u.strip() for u in self.privileged_users.split(",") if u.strip()]

    @property
    def watermark_delay_interval(self) -> str:
        """Spark interval-literal string, e.g. '5 minutes', for withWatermark()."""
        return f"{self.spark_watermark_delay_minutes} minutes"

    @property
    def shuffle_partitions(self) -> int:
        return self.spark_shuffle_partitions_loadtest if self.cyberstream_mode == "loadtest" else self.spark_shuffle_partitions_dev

    @property
    def database_url(self) -> str:
        """SQLAlchemy-style URL - NOT usable directly with psycopg.connect(); see psycopg_dsn."""
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def psycopg_dsn(self) -> str:
        """
        Plain DSN for psycopg.connect() (dlq.py's foreachBatch sink) - the
        SQLAlchemy dialect suffix in database_url ("postgresql+psycopg://")
        is NOT a valid scheme for psycopg's own connect(), which expects
        "postgresql://". Kept as a separate property rather than patching
        database_url, since SQLAlchemy's engine still needs the "+psycopg"
        form - found by writing a test that actually calls psycopg's DSN
        parser (see tests/test_config.py).
        """
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
