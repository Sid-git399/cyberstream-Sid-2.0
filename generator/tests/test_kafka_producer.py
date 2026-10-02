"""
Kafka producer abstraction tests.

Most tests use FakeProducer, a minimal stand-in for confluent_kafka.Producer
that records calls instead of talking to a broker - this tests OUR
abstraction (routing, serialization, stats, error handling), not whether a
real broker accepted a message. Exactly one test
(test_real_producer_reports_failure_when_broker_unreachable) uses the real
confluent_kafka.Producer against a closed local port, with short timeouts,
to prove the honest-failure behavior end-to-end without needing a live
Kafka broker or hanging the test suite.
"""
from __future__ import annotations

import json

import pytest

from kafka_producer import (
    EventProducer,
    ProducerConfig,
    ProducerConfigurationError,
    SerializationError,
)
from models.event import EventType, SecurityEvent


class FakeProducer:
    """Stand-in for confluent_kafka.Producer. No network activity at all."""

    def __init__(self, config: dict, logger=None):
        self.config = config
        self.produced: list[dict] = []
        self.poll_calls = 0
        self.flush_calls = 0
        self._fail_next = False

    def produce(self, topic, key, value, callback):
        self.produced.append({"topic": topic, "key": key, "value": value, "callback": callback})

    def poll(self, timeout):
        self.poll_calls += 1
        return 0

    def flush(self, timeout):
        self.flush_calls += 1
        # Simulate every queued message getting its delivery callback fired.
        for msg in self.produced:
            fake_msg = _FakeMessage(msg["topic"], partition=0, offset=len(self.produced))
            msg["callback"](None, fake_msg)
        return 0


class _FakeMessage:
    def __init__(self, topic, partition, offset):
        self._topic = topic
        self._partition = partition
        self._offset = offset

    def topic(self):
        return self._topic

    def partition(self):
        return self._partition

    def offset(self):
        return self._offset


def make_event(**overrides) -> SecurityEvent:
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


@pytest.fixture
def config():
    return ProducerConfig(bootstrap_servers="localhost:9092")


# --- Configuration ---------------------------------------------------------

def test_producer_config_maps_to_confluent_config_correctly(config):
    confluent_config = config.to_confluent_config()
    assert confluent_config["bootstrap.servers"] == "localhost:9092"
    assert confluent_config["acks"] == "all"
    assert confluent_config["enable.idempotence"] is True
    assert confluent_config["compression.type"] == "snappy"


def test_producer_config_overrides_are_respected():
    config = ProducerConfig(
        bootstrap_servers="kafka:29092", client_id="my-client", acks="1",
        retries=10, compression_type="gzip", linger_ms=50, batch_num_messages=100,
    )
    confluent_config = config.to_confluent_config()
    assert confluent_config["client.id"] == "my-client"
    assert confluent_config["acks"] == "1"
    assert confluent_config["retries"] == 10
    assert confluent_config["compression.type"] == "gzip"


def test_producer_initialization_wraps_factory_errors(config):
    def broken_factory(cfg, logger=None):
        raise RuntimeError("bad broker config")

    with pytest.raises(ProducerConfigurationError):
        EventProducer(config, producer_factory=broken_factory)


# --- Serialization -----------------------------------------------------

def test_produce_serializes_event_as_json(config):
    producer = EventProducer(config, producer_factory=FakeProducer)
    event = make_event()
    producer.produce(event)

    assert len(producer._producer.produced) == 1
    sent = producer._producer.produced[0]
    payload = json.loads(sent["value"].decode("utf-8"))
    assert payload["event_id"] == event.event_id


def test_produce_raises_serialization_error_for_unserializable_metadata(config):
    producer = EventProducer(config, producer_factory=FakeProducer)
    # A bare `object()` is opaque to both Pydantic's mode="json" dump AND
    # json.dumps() - a set, by contrast, is NOT a good test case here:
    # Pydantic's model_dump(mode="json") silently converts sets to lists
    # (discovered by actually running this test - see docs/phases.md).
    event = make_event(metadata={"bad": object()})
    with pytest.raises(SerializationError):
        producer.produce(event)
    # Nothing should have reached the underlying producer.
    assert len(producer._producer.produced) == 0


# --- Topic and partition-key routing ------------------------------------

def test_produce_routes_to_correct_topic(config):
    producer = EventProducer(config, producer_factory=FakeProducer)
    event = make_event(event_type=EventType.PORT_SCAN, category="network")
    producer.produce(event)
    assert producer._producer.produced[0]["topic"] == "security-network"


def test_produce_uses_hostname_as_partition_key(config):
    producer = EventProducer(config, producer_factory=FakeProducer)
    event = make_event(hostname="srv-db-02")
    producer.produce(event)
    assert producer._producer.produced[0]["key"] == b"srv-db-02"


# --- Delivery callback / stats ------------------------------------------

def test_flush_invokes_delivery_callback_and_updates_stats(config):
    producer = EventProducer(config, producer_factory=FakeProducer)
    for _ in range(3):
        producer.produce(make_event())
    remaining = producer.flush(timeout=1.0)

    assert remaining == 0
    assert producer.stats.delivered == 3
    assert producer.stats.failed == 0
    assert producer._producer.flush_calls == 1


def test_delivery_callback_records_failures():
    class FailingProducer(FakeProducer):
        def flush(self, timeout):
            self.flush_calls += 1
            for msg in self.produced:
                fake_msg = _FakeMessage(msg["topic"], 0, 0)
                msg["callback"]("simulated broker error", fake_msg)
            return 0

    producer = EventProducer(ProducerConfig(bootstrap_servers="localhost:9092"), producer_factory=FailingProducer)
    producer.produce(make_event())
    producer.flush(timeout=1.0)

    assert producer.stats.delivered == 0
    assert producer.stats.failed == 1
    assert producer.stats.failed_topics["security-authentication"] == 1


def test_produce_polls_after_each_message(config):
    producer = EventProducer(config, producer_factory=FakeProducer)
    producer.produce(make_event())
    assert producer._producer.poll_calls == 1


# --- Real broker-unavailable behavior (bounded, no live Kafka needed) ---

def test_real_producer_reports_failure_when_broker_unreachable():
    """
    Uses the REAL confluent_kafka.Producer (not FakeProducer) against a
    closed local port, with a short delivery timeout, so this proves the
    honest-failure path end-to-end without needing a live Kafka broker and
    without hanging the test suite (bounded to a couple of seconds).
    """
    config = ProducerConfig(
        bootstrap_servers="127.0.0.1:1",  # port 1 - nothing listens here
        delivery_timeout_ms=500,
    )
    producer = EventProducer(config)  # real confluent_kafka.Producer, no factory override
    producer.produce(make_event())
    remaining = producer.flush(timeout=2.0)

    assert remaining == 0  # flush accounted for every message (as failed), didn't just time out silently
    assert producer.stats.failed == 1
    assert producer.stats.delivered == 0
