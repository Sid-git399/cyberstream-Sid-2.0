from src.config import Settings
import pytest


def test_defaults_match_env_example():
    s = Settings(_env_file=None)
    assert s.kafka_bootstrap_servers == "localhost:9092"
    assert s.spark_master == "local[*]"
    assert s.spark_watermark_delay_minutes == 5


def test_shuffle_partitions_uses_dev_by_default():
    s = Settings(_env_file=None)
    assert s.shuffle_partitions == s.spark_shuffle_partitions_dev


def test_shuffle_partitions_switches_in_loadtest_mode(monkeypatch):
    monkeypatch.setenv("CYBERSTREAM_MODE", "loadtest")
    s = Settings(_env_file=None)
    assert s.shuffle_partitions == s.spark_shuffle_partitions_loadtest


def test_database_url_is_well_formed():
    s = Settings(_env_file=None)
    assert s.database_url.startswith("postgresql+psycopg://")
    assert s.postgres_db in s.database_url


def test_psycopg_dsn_is_directly_usable_by_psycopg():
    """
    database_url's "postgresql+psycopg://" scheme is SQLAlchemy-specific
    and psycopg.connect() cannot parse it directly - confirmed by actually
    calling psycopg's own DSN parser, not just by inspection.
    """
    import psycopg.conninfo

    s = Settings(_env_file=None)
    assert s.psycopg_dsn.startswith("postgresql://")
    parsed = psycopg.conninfo.conninfo_to_dict(s.psycopg_dsn)
    assert parsed["dbname"] == s.postgres_db
    assert parsed["host"] == s.postgres_host

    with pytest.raises(Exception):
        psycopg.conninfo.conninfo_to_dict(s.database_url)


def test_watermark_delay_interval_format():
    s = Settings(_env_file=None)
    assert s.watermark_delay_interval == "5 minutes"


def test_privileged_users_list_parses_csv():
    s = Settings(_env_file=None)
    assert "admin" in s.privileged_users_list
    assert "root" in s.privileged_users_list
