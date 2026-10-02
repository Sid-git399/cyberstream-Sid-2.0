"""
Normalization stage: takes only the valid rows from validation.py and
produces the canonical NormalizedSecurityEvent shape used by every
downstream stage (enrichment, windowing, detection).

The one substantive transformation here is casting the ISO-8601
`timestamp` string into a real `event_time` TimestampType column - this
is what makes event-time processing (as opposed to arrival-time
processing) possible; watermarks and windows in windows.py operate on
`event_time`, never on Kafka's own message timestamp.

Deliberately does NOT re-derive `category` from `event_type` here (that
mapping already lives in generator/models/event.py's EVENT_TYPE_CATEGORY
and is enforced at generation time) - duplicating it in Spark would be
exactly the kind of second copy of the same business rule the cahier des
charges warns against. This is a documented trust boundary, not an
oversight - see docs/architecture-decisions.md ADR-13.
"""
from __future__ import annotations

from pyspark.sql import DataFrame
from pyspark.sql import functions as F


def normalize_events(validated_df: DataFrame) -> DataFrame:
    """Input must already be filtered to `_is_valid == True` rows (main.py does this)."""
    return validated_df.withColumn(
        "event_time", F.to_timestamp(F.col("timestamp"))
    ).select(
        "event_id", "event_time", "timestamp", "event_type", "category",
        "source_ip", "destination_ip", "source_port", "destination_port",
        "protocol", "username", "hostname", "action", "status",
        "bytes_in", "bytes_out", "country", "metadata", "topic",
    )
