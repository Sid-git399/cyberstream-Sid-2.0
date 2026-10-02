# Detection Engine (Phase B)

## Architecture

```text
enriched DataFrame (Phase A's output)
    -> DetectionRule.apply() x 8, each independently configured/enabled
    -> unionByName
    -> one DataFrame of structured detections
```

Every rule is a small class in `streaming/src/detection/rules/*.py` - one
file per rule, never a single giant `detection.py`. `DetectionRule`
(`streaming/src/detection/base.py`) is the shared abstraction:

```text
DetectionRule (abstract)
    ├── BruteForceRule
    ├── PasswordSprayingRule
    ├── PortScanRule
    ├── SuspiciousAuthenticationRule
    ├── PrivilegeEscalationRule
    ├── SuspiciousProcessRule
    ├── LargeDataTransferRule
    └── DNSAnomalyRule
```

`streaming/src/detection/engine.py`'s `run_detections()` instantiates
every rule from config, calls `.apply()` on each (a plain Spark DataFrame
transformation - never a Python loop over collected rows, which would
both be impossible in a streaming query and wouldn't distribute), and
unions the results. A disabled rule contributes an empty-but-correctly-
typed DataFrame, so the union is always well-formed regardless of which
rules are on.

## Two rule shapes

- **Windowed** (brute force, password spraying, port scan, DNS anomaly):
  aggregate matching events into a time window, compare a count against
  a threshold. Built on `windows.py`'s new `windowed_aggregate()` helper
  (added alongside the existing `windowed_counts()`, not replacing it -
  Phase A's windowing tests are untouched and still pass).
- **Row-level** (suspicious authentication, privilege escalation,
  suspicious process, large data transfer): each qualifying event is its
  own detection, no aggregation; `window_start == window_end == event_time`.

`DetectionRule.finalize_windowed()` / `.finalize_row_level()` build the
common output columns so each concrete rule only has to produce the
columns specific to its own logic.

## Configuration

Every threshold, window, enable flag, severity, and risk-point value
comes from `infrastructure/spark/detection_rules.yaml`, loaded and
strictly validated (Pydantic, `extra="forbid"`) by
`streaming/src/detection/config.py`. No rule hardcodes a threshold.

```yaml
brute_force:
  enabled: true
  failed_attempts: 10
  window_seconds: 300
  severity: HIGH
  risk_points: 25
```

`severity`/`risk_points` express the cahier des charges §27 initial
scoring model as data, not code - Phase E (Risk Scoring) will sum
`risk_points` across co-occurring detections; that summation doesn't
exist yet, only the per-detection value does.

An explicitly-given config path that doesn't exist raises
`DetectionConfigError` (a caller's mistake should be loud); auto-discovery
finding nothing anywhere falls back to pure Pydantic defaults (every rule
enabled, documented thresholds) rather than disabling the engine.

## The 8 rules

| Rule | Shape | Trigger | Category |
|---|---|---|---|
| Brute Force | windowed | ≥N `login_failed` for the same (username, source_ip) in a window | authentication |
| Password Spraying | windowed | ≥N distinct usernames targeted by one source_ip in a window | authentication |
| Port Scan | windowed | ≥N distinct destination_ports from one source_ip in a window (any `network`-category event, not just the `port_scan` event_type) | network |
| Suspicious Authentication | row-level | a privileged user (`is_privileged_user`) logging in from a non-internal source (`is_source_internal == false`), OR any `account_locked` event | authentication |
| Privilege Escalation | row-level | `event_type` is `privilege_escalation` or `group_modified` | privilege |
| Suspicious Process | row-level | `event_type == process_created` AND `metadata.suspicious == true` | endpoint |
| Large Data Transfer | row-level | a single event's `bytes_out` ≥ threshold | network |
| DNS Anomaly | windowed | ≥N `dns_query` events from one source_ip in a window | network |

None uses external threat intelligence, geo-IP, or any field outside the
canonical `docs/event-schema.json` schema.

## Evidence model

Every detection has a stable schema
(`streaming/src/detection/base.py::DETECTION_OUTPUT_COLUMNS`):

```text
detection_id, timestamp, rule_id, rule_name, category, severity,
risk_points, source_ip, destination_ip, hostname, username,
evidence, event_ids, window_start, window_end
```

`evidence` is a JSON-encoded string (via `to_json(struct(...))`) with
rule-specific fields (e.g. brute force: `failed_attempts`, `threshold`,
`username`, `source_ip`, `window_start`, `window_end`). `event_ids` is a
real array of the `event_id`s that produced the detection - an analyst
(or a later phase's UI) can trace a detection back to its exact raw
events, not just a count.

`detection_id` is **deterministic**, not random:
`sha2(rule_id | window_start | group_keys, 256)`. The same rule firing on
the same window/group twice (e.g. after a job restart reprocesses a
batch) produces the same ID both times -
`test_run_detections_is_deterministic_across_two_independent_runs` proves
this directly, and it matters for a future Alert Engine that will want to
deduplicate on it.

## Spark integration

`streaming/src/main.py`'s `build_pipeline()` (Phase A) is untouched.
`main()` adds one more block: if `settings.detection_engine_enabled`
(default true), it calls `run_detections()` on the same `enriched`
DataFrame `build_pipeline()` already produced - no second Kafka read -
and writes the result to Parquet under `{parquet_data_dir}/detections`,
checkpointed separately from the processed-events and DLQ queries. This
is reviewed, not run (see docs/phases.md - no live Kafka here).

## Testing strategy

- **Per-rule unit tests** (`tests/detection/test_rules_*.py`, 50 tests):
  hand-built `DataFrame`s via a shared `make_enriched_df` fixture, with an
  **explicit Spark schema** - not inference - because inferring a schema
  from Python dicts fails outright when a column is `None` in every row
  of a batch (exactly what single-row "missing field" tests do by
  construction). Each rule gets: a positive case, a negative case,
  threshold boundary cases (exact match and one-below), a disabled-rule
  case, and rule-specific data-quality cases (null username, null
  source_ip, null bytes_out, malformed/empty metadata).
- **Engine tests** (`tests/detection/test_engine.py`, 7 tests): union
  behavior, schema conformance, determinism, all-disabled handling.
- **Config tests** (`tests/detection/test_config.py`, 11 tests): defaults,
  the real YAML file, strict validation (typo'd keys, invalid severity,
  out-of-range risk_points), the explicit-vs-auto-discovery path distinction.
- **Full-chain integration test** (`tests/detection/test_pipeline_integration.py`,
  3 tests): REAL `generator/scenarios/brute_force.py` and `normal_traffic.py`
  output, as real JSON, through the REAL `parse_raw_events ->
  validate_events -> normalize_events -> enrich_events -> run_detections`
  chain - not the hand-built fixture. This is what caught the window-
  boundary bug below; the per-rule unit tests, built on fixed timestamps,
  could not have.

**119 streaming tests passing total** (47 Phase A + 72 Phase B). See
`docs/phases.md` for the authoritative, file-by-file breakdown.

## Known limitations (found by running things, documented rather than hidden)

1. **Tumbling windows can split a burst across a boundary and miss it
   entirely.** `windows.py`'s windows are non-overlapping and aligned to
   absolute wall-clock boundaries (e.g. every 5 minutes on the clock),
   not to when a burst actually starts. If 16 brute-force attempts land
   8-before/8-after a boundary, neither half alone reaches a 10-attempt
   threshold, and the attack is missed - even though every event is
   within 40 seconds of every other. **This was found empirically**: an
   early version of the integration test used `datetime.now()` as the
   scenario's start time and became flaky, failing only when the
   generated burst happened to straddle a real clock boundary. Fixed the
   test to use a pinned `start_time` (tests must not depend on wall-clock
   timing), and added
   `test_brute_force_events_spanning_a_window_boundary_can_be_missed` to
   document the gap explicitly as real, current behavior - not swept
   under the rug. A sliding-window design would close this gap at a real
   state/compute cost; not implemented in Phase B.
2. **Suspicious Process depends on a synthetic metadata marker.** It
   reads `metadata.suspicious == true`, which only this project's
   generator populates (`generator/scenarios/suspicious_process.py`).
   This is explicitly not real endpoint malware analysis - a real
   deployment would need genuine EDR telemetry mapped into the same
   `metadata` shape, or a different detection approach entirely.
3. **No cross-rule deduplication or correlation yet.** Phase B produces
   independent detections per rule; linking e.g. a brute-force detection
   to a subsequent privilege-escalation detection on the same host is
   Phase D (Correlation).
4. **`collect_list`/`collect_set` in streaming aggregations hold state
   proportional to events-per-window-per-group.** Fine at this project's
   synthetic scale; a very high-cardinality or very long window in a real
   deployment would need a cap or a different evidence-collection
   strategy.
5. **Category-based routing trust boundary (ADR-13) applies here too**:
   Port Scan trusts the `category` field as parsed rather than
   re-deriving it, so a producer writing directly to Kafka with a
   mismatched category would evade the `category == "network"` filter.
