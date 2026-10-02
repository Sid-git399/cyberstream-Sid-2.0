#!/usr/bin/env bash
# Creates all CyberStream Kafka topics. Idempotent (safe to re-run).
# Partition count and replication factor come from env so dev vs
# load-test mode can differ without touching this script.
set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS_INTERNAL:-kafka:29092}"
PARTITIONS="${KAFKA_NUM_PARTITIONS:-3}"
RF="${KAFKA_REPLICATION_FACTOR:-1}"
BIN=/opt/kafka/bin

TOPICS=(
  "security-authentication"
  "security-network"
  "security-endpoint"
  "security-privilege"
  "security-cloud"
  "security-web"
  "security-normalized"
  "security-alerts"
  "security-dlq"
)

echo "Waiting for Kafka at ${BOOTSTRAP}..."
for i in $(seq 1 30); do
  if "${BIN}/kafka-broker-api-versions.sh" --bootstrap-server "${BOOTSTRAP}" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

for topic in "${TOPICS[@]}"; do
  echo "Ensuring topic: ${topic} (partitions=${PARTITIONS}, rf=${RF})"
  "${BIN}/kafka-topics.sh" --bootstrap-server "${BOOTSTRAP}" \
    --create --if-not-exists \
    --topic "${topic}" \
    --partitions "${PARTITIONS}" \
    --replication-factor "${RF}" \
    --config retention.ms=604800000
done

echo "Topic list:"
"${BIN}/kafka-topics.sh" --bootstrap-server "${BOOTSTRAP}" --list

echo "Kafka topic initialization complete."
