import sys
from pathlib import Path

import pytest
from pyspark.sql.types import StructType

from src.schema import (
    ALL_TOPICS_PLUS_INFRA,
    build_category_topic_map,
    build_security_event_struct_type,
    event_type_enum,
    load_event_json_schema,
)

# Cross-check against the generator's independently-defined Python model,
# to prove the two "single sources of truth" (JSON Schema here,
# Pydantic model there) actually agree - not just that each is
# internally consistent.
_GENERATOR_PATH = Path(__file__).resolve().parents[2] / "generator"
sys.path.insert(0, str(_GENERATOR_PATH))
from models.event import CATEGORY_TOPIC as GENERATOR_CATEGORY_TOPIC  # noqa: E402
from models.event import EventType  # noqa: E402


def test_schema_loads_and_has_expected_fields():
    schema = load_event_json_schema()
    assert schema["title"] == "SecurityEvent"
    assert "event_id" in schema["properties"]


def test_struct_type_has_all_required_fields():
    struct_type = build_security_event_struct_type()
    assert isinstance(struct_type, StructType)
    field_names = {f.name for f in struct_type.fields}
    expected = {
        "event_id", "timestamp", "event_type", "category", "source_ip",
        "destination_ip", "source_port", "destination_port", "protocol",
        "username", "hostname", "action", "status", "bytes_in", "bytes_out",
        "country", "metadata",
    }
    assert field_names == expected


def test_integer_fields_are_long_type():
    struct_type = build_security_event_struct_type()
    by_name = {f.name: f.dataType.typeName() for f in struct_type.fields}
    for field in ["source_port", "destination_port", "bytes_in", "bytes_out"]:
        assert by_name[field] == "long"


def test_timestamp_and_metadata_are_string_type_by_design():
    struct_type = build_security_event_struct_type()
    by_name = {f.name: f.dataType.typeName() for f in struct_type.fields}
    assert by_name["timestamp"] == "string"
    assert by_name["metadata"] == "string"


def test_username_is_nullable():
    struct_type = build_security_event_struct_type()
    by_name = {f.name: f.nullable for f in struct_type.fields}
    assert by_name["username"] is True


def test_category_topic_map_matches_generator():
    """
    The Spark-side mapping (derived from the JSON schema's category enum)
    and the generator's Python-side CATEGORY_TOPIC (hand-written in
    models/event.py) must agree, since both feed the same Kafka topics.
    """
    spark_side = build_category_topic_map()
    generator_side = {cat.value: topic for cat, topic in GENERATOR_CATEGORY_TOPIC.items()}
    assert spark_side == generator_side


def test_event_type_enum_matches_generator():
    spark_side = set(event_type_enum())
    generator_side = {e.value for e in EventType}
    assert spark_side == generator_side


def test_all_topics_plus_infra_includes_dlq_and_normalized():
    assert "security-dlq" in ALL_TOPICS_PLUS_INFRA
    assert "security-normalized" in ALL_TOPICS_PLUS_INFRA
    assert "security-alerts" in ALL_TOPICS_PLUS_INFRA
    assert len(ALL_TOPICS_PLUS_INFRA) == 9  # 6 category topics + 3 infra topics
