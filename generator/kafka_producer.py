"""
Kafka producer abstraction wrapping confluent-kafka.

Routing is intentionally centralized in SecurityEvent itself
(`event.kafka_topic()`, `event.partition_key()`) - this module must not
invent a second routing rule.

Delivery is fire-and-forget from the caller's perspective (produce() just
queues), with a delivery callback recording success/failure per message and
`flush()` used at shutdown to guarantee every queued message is actually
sent (or accounted for as failed) before the process exits - "no silent
message loss" (cahier des charges §3).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from confluent_kafka import KafkaError, Message, Producer

from common.errors import AppError
from models.event import SecurityEvent

logger = logging.getLogger("generator.kafka_producer")


class ProducerConfigurationError(AppError):
    code = "PRODUCER_CONFIGURATION_ERROR"
    http_status = 500


class SerializationError(AppError):
    code = "SERIALIZATION_ERROR"
    http_status = 400


@dataclass
class ProducerConfig:
    """
    Every field is env-driven upstream (see config.py) - nothing here is
    hardcoded at the call site.
    """
    bootstrap_servers: str
    client_id: str = "cyberstream-generator"
    acks: str = "all"                 # "all" = wait for every in-sync replica; safest default
    retries: int = 5
    retry_backoff_ms: int = 200
    delivery_timeout_ms: int = 30_000
    linger_ms: int = 20               # small batching window - real batching, not one-message-per-request
    batch_num_messages: int = 500
    compression_type: str = "snappy"  # good default for JSON payloads: cheap CPU cost, solid ratio

    def to_confluent_config(self) -> dict:
        return {
            "bootstrap.servers": self.bootstrap_servers,
            "client.id": self.client_id,
            "acks": self.acks,
            "retries": self.retries,
            "retry.backoff.ms": self.retry_backoff_ms,
            "delivery.timeout.ms": self.delivery_timeout_ms,
            "linger.ms": self.linger_ms,
            "batch.num.messages": self.batch_num_messages,
            "compression.type": self.compression_type,
            "enable.idempotence": True,  # prevents duplicate delivery on internal retries
        }


@dataclass
class DeliveryStats:
    delivered: int = 0
    failed: int = 0
    failed_topics: dict = field(default_factory=dict)


class EventProducer:
    """
    `producer_factory` exists so tests can inject a fake in place of a
    real confluent_kafka.Producer, without needing a broker - see
    tests/test_kafka_producer.py. Production code never passes it; the
    default (real Producer) is used.
    """

    def __init__(self, config: ProducerConfig, producer_factory=None):
        self.config = config
        self.stats = DeliveryStats()
        factory = producer_factory or Producer
        try:
            # Passing `logger` routes librdkafka's own internal log lines
            # (broker connection failures, etc) through our structured
            # JSON logging convention instead of them bypassing it and
            # printing raw text straight to stderr - confirmed by actually
            # running produce() against an unreachable broker (see
            # docs/phases.md bug log) before this was added.
            self._producer = factory(config.to_confluent_config(), logger=logger)
        except TypeError:
            # Test doubles that don't accept a `logger` kwarg still work.
            self._producer = factory(config.to_confluent_config())
        except Exception as exc:  # confluent-kafka raises KafkaException on bad config
            raise ProducerConfigurationError(f"Failed to initialize Kafka producer: {exc}") from exc

    def _delivery_callback(self, err: KafkaError | None, msg: Message) -> None:
        if err is not None:
            self.stats.failed += 1
            topic = msg.topic() if msg else "unknown"
            self.stats.failed_topics[topic] = self.stats.failed_topics.get(topic, 0) + 1
            logger.error(
                "message delivery failed: topic=%s error=%s",
                topic, err,
            )
        else:
            self.stats.delivered += 1
            logger.debug("message delivered: topic=%s partition=%s offset=%s", msg.topic(), msg.partition(), msg.offset())

    def produce(self, event: SecurityEvent) -> None:
        """
        Queues one event for delivery. Raises SerializationError if the
        event cannot be encoded (should be unreachable given SecurityEvent
        validation, but never silently drop a message that fails to
        serialize - fail loudly instead).
        """
        topic = event.kafka_topic()
        key = event.partition_key()

        try:
            payload = json.dumps(event.to_kafka_json()).encode("utf-8")
        except Exception as exc:
            # Deliberately broad: event.to_kafka_json() can raise Pydantic's
            # own PydanticSerializationError (not a TypeError/ValueError) for
            # values it can't convert (e.g. an opaque object in `metadata`),
            # and json.dumps() raises TypeError/ValueError for what's left.
            # Found by actually constructing such an event in a test - the
            # narrower except (TypeError, ValueError) missed the Pydantic
            # case entirely and would have crashed the caller instead of
            # raising the intended SerializationError.
            raise SerializationError(f"Could not serialize event {event.event_id}: {exc}", event_id=event.event_id) from exc

        try:
            self._producer.produce(
                topic=topic,
                key=key.encode("utf-8"),
                value=payload,
                callback=self._delivery_callback,
            )
        except BufferError:
            # Local queue is full - caller's responsibility to poll()/flush()
            # more often at high throughput. Not silently dropped: surfaced
            # as a real exception up the call stack.
            logger.warning("local producer queue full, forcing a poll to make room")
            self._producer.poll(1.0)
            self._producer.produce(topic=topic, key=key.encode("utf-8"), value=payload, callback=self._delivery_callback)

        # Serves queued delivery-report callbacks without blocking; keeps
        # stats reasonably current during long runs instead of only at flush().
        self._producer.poll(0)

    def flush(self, timeout: float = 30.0) -> int:
        """Blocks until every queued message is delivered or the timeout elapses. Returns the number still undelivered."""
        remaining = self._producer.flush(timeout)
        if remaining > 0:
            logger.warning("flush timed out with %d message(s) still undelivered", remaining)
        return remaining
