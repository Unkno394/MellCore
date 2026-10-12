CREATE DATABASE IF NOT EXISTS honeyforge;

CREATE TABLE IF NOT EXISTS honeyforge.telemetry_events
(
    agent_id UUID,
    event_id UUID,
    trap_id UUID,
    received_at_unix_ms Int64,
    occurred_at_unix_ms Int64,
    event_type LowCardinality(String),
    session_id Nullable(String),
    source_sequence_no Nullable(UInt64),
    source_ip Nullable(String),
    source_port Nullable(UInt16),
    destination_port Nullable(UInt16),
    protocol LowCardinality(String),
    service_type LowCardinality(String),
    event_payload String,
    event_metadata String
)
ENGINE = ReplacingMergeTree
ORDER BY (agent_id, event_id);
