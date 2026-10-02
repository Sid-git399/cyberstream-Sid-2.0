"""
Spark StructType and topic routing, both DERIVED from docs/event-schema.json
at import time rather than hand-copied - the JSON Schema file (already the
source of truth for the generator and its tests) stays the only place the
event contract is spelled out. Do not add a second hand-maintained field
list here; if the JSON Schema changes, this module picks it up automatically.

Two fields are deliberately NOT given their "natural" Spark type here:
- `timestamp`: kept as StringType at parse time. Casting to a real
  TimestampType is a normalization step (normalization.py), not a parsing
  step - this keeps "parse structurally" and "interpret as event-time"
  separate, matching the pipeline diagram (Parse -> Validate -> Normalize).
- `metadata`: kept as StringType (the raw JSON text), not a Spark
  MapType/StructType. Scenario metadata mixes strings, bools, and ints in
  the same object (see generator/scenarios/*.py), which Spark's typed Map
  can't represent without picking one value type. Rules that need a
  specific metadata key (Phase B+) parse it narrowly with
  get_json_object() rather than the whole pipeline paying for a schema
  that would have to be Any-typed anyway.
"""
from __future__ import annotations

import json
from pathlib import Path

from pyspark.sql.types import LongType, StringType, StructField, StructType

_CANDIDATE_SCHEMA_PATHS = [
    # Local dev layout: streaming/src/schema.py -> repo root is parents[2]
    Path(__file__).resolve().parents[2] / "docs" / "event-schema.json",
    # Docker layout: /app/src/schema.py, docs copied to /app/docs
    Path(__file__).resolve().parents[1] / "docs" / "event-schema.json",
    Path("/app/docs/event-schema.json"),
]


def _find_schema_path() -> Path:
    for candidate in _CANDIDATE_SCHEMA_PATHS:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"docs/event-schema.json not found in any of: {_CANDIDATE_SCHEMA_PATHS}"
    )


def load_event_json_schema() -> dict:
    return json.loads(_find_schema_path().read_text())


_INTEGER_FIELDS = {"source_port", "destination_port", "bytes_in", "bytes_out"}


def build_security_event_struct_type(json_schema: dict | None = None) -> StructType:
    json_schema = json_schema or load_event_json_schema()
    properties = json_schema["properties"]
    required = set(json_schema.get("required", []))

    fields = []
    for name, prop in properties.items():
        if name == "metadata":
            spark_type = StringType()
        elif name in _INTEGER_FIELDS:
            spark_type = LongType()
        else:
            spark_type = StringType()
        nullable = name not in required or "null" in _as_type_list(prop.get("type"))
        fields.append(StructField(name, spark_type, nullable=nullable))

    return StructType(fields)


def _as_type_list(type_value) -> list[str]:
    if type_value is None:
        return []
    if isinstance(type_value, str):
        return [type_value]
    return list(type_value)


def build_category_topic_map(json_schema: dict | None = None) -> dict[str, str]:
    """
    security-authentication / security-network / etc - derived from the
    schema's `category` enum plus the fixed "security-" naming convention,
    rather than hand-copied from generator/models/event.py's CATEGORY_TOPIC.
    Both must produce the identical mapping - see
    tests/test_schema.py::test_category_topic_map_matches_generator.
    """
    json_schema = json_schema or load_event_json_schema()
    categories = json_schema["properties"]["category"]["enum"]
    return {category: f"security-{category}" for category in categories}


def event_type_enum(json_schema: dict | None = None) -> list[str]:
    json_schema = json_schema or load_event_json_schema()
    return list(json_schema["properties"]["event_type"]["enum"])


ALL_TOPICS_PLUS_INFRA = [
    # The 6 category topics, plus the 3 infra topics the cahier des
    # charges lists that don't correspond to a single `category` value.
    *build_category_topic_map().values(),
    "security-normalized",
    "security-alerts",
    "security-dlq",
]
