import json
from pathlib import Path

import jsonschema
import pytest

from models.event import EventType, SecurityEvent, new_event_id

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "docs" / "event-schema.json"


@pytest.fixture(scope="module")
def schema():
    return json.loads(SCHEMA_PATH.read_text())


def make_sample_event(**overrides) -> SecurityEvent:
    base = dict(
        event_type=EventType.LOGIN_FAILED,
        category="authentication",
        source_ip="10.10.4.23",
        destination_ip="10.10.1.10",
        source_port=54231,
        destination_port=22,
        protocol="TCP",
        username="admin",
        hostname="srv-auth-01",
        action="login",
        status="failure",
        bytes_in=0,
        bytes_out=0,
        country="DZ",
        metadata={},
    )
    base.update(overrides)
    return SecurityEvent(**base)


def test_sample_event_matches_json_schema(schema):
    jsonschema.validate(instance=make_sample_event().to_kafka_json(), schema=schema)


def test_all_event_types_produce_schema_valid_events(schema):
    for et in EventType:
        jsonschema.validate(instance=make_sample_event(event_type=et).to_kafka_json(), schema=schema)


def test_category_is_derived_and_cannot_mismatch():
    event = make_sample_event(event_type=EventType.PORT_SCAN, category="authentication")
    assert event.category == "network"


def test_event_id_default_matches_pattern():
    event = make_sample_event()
    assert event.event_id.startswith("evt-")
    assert len(event.event_id) <= 32 + 4


def test_new_event_id_is_unique():
    assert len({new_event_id() for _ in range(1000)}) == 1000


def test_invalid_port_rejected():
    with pytest.raises(Exception):
        make_sample_event(source_port=70000)


def test_invalid_protocol_rejected():
    with pytest.raises(Exception):
        make_sample_event(protocol="FTP")


def test_invalid_bytes_rejected():
    with pytest.raises(Exception):
        make_sample_event(bytes_out=-1)
    with pytest.raises(Exception):
        make_sample_event(bytes_in=-1)


def test_invalid_source_ip_type_rejected():
    with pytest.raises(Exception):
        make_sample_event(source_ip=12345)  # not a string


def test_unknown_event_type_rejected():
    with pytest.raises(Exception):
        make_sample_event(event_type="not_a_real_event_type")


@pytest.mark.parametrize("event_type,expected_topic", [
    (EventType.LOGIN_FAILED, "security-authentication"),
    (EventType.CONNECTION, "security-network"),
    (EventType.PROCESS_CREATED, "security-endpoint"),
    (EventType.PRIVILEGE_ESCALATION, "security-privilege"),
    (EventType.CLOUD_LOGIN, "security-cloud"),
    (EventType.HTTP_REQUEST, "security-web"),
])
def test_kafka_topic_routes_by_category(event_type, expected_topic):
    event = make_sample_event(event_type=event_type)
    assert event.kafka_topic() == expected_topic


def test_partition_key_defaults_to_hostname():
    event = make_sample_event(hostname="srv-auth-01", username="admin", source_ip="10.10.4.23")
    assert event.partition_key() == "srv-auth-01"


def test_partition_key_falls_back_to_username_then_source_ip():
    # hostname is required/non-empty by schema, so this exercises the
    # fallback branches directly via model_construct (bypasses validation)
    # rather than pretending the public API allows an empty hostname.
    event = make_sample_event()
    object.__setattr__(event, "hostname", "")
    assert event.partition_key() == event.username

    object.__setattr__(event, "username", None)
    assert event.partition_key() == event.source_ip
