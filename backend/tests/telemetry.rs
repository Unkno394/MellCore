use chrono::{DateTime, Duration, Utc};
use honeyforge_backend::{
    config::Config,
    telemetry::{TelemetryBatch, ValidationCode},
};
use serde_json::{Value, json};

fn now() -> DateTime<Utc> {
    "2026-10-10T12:00:00Z".parse().unwrap()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../docs/examples/telemetry-v1.json")).unwrap()
}

fn parse(value: Value) -> TelemetryBatch {
    serde_json::from_value(value).unwrap_or_else(|_| panic!("test fixture must deserialize"))
}

fn limits() -> honeyforge_backend::telemetry::TelemetryLimits {
    Config::from_lookup(|_| Ok(None)).unwrap().telemetry
}

#[test]
fn documented_batch_is_valid_and_round_trips() {
    let batch = parse(fixture());
    assert!(batch.validate(&limits(), now()).is_ok());
    let roundtrip = serde_json::to_value(&batch).unwrap();
    assert!(parse(roundtrip) == batch);
}

#[test]
fn rejects_unsupported_versions_empty_batches_and_nil_identity() {
    for (field, value, expected) in [
        (
            "schema_version",
            json!(2),
            ValidationCode::UnsupportedSchema,
        ),
        ("events", json!([]), ValidationCode::InvalidValue),
        (
            "agent_id",
            json!("00000000-0000-0000-0000-000000000000"),
            ValidationCode::InvalidValue,
        ),
    ] {
        let mut input = fixture();
        input[field] = value;
        let error = parse(input).validate(&limits(), now()).unwrap_err();
        assert_eq!(error.code, expected);
        assert_eq!(error.field, field);
        assert_eq!(error.event_index, None);
    }
}

#[test]
fn validates_batch_size_before_processing_events() {
    let mut batch = parse(fixture());
    batch.events.push(batch.events[0].clone());
    let mut limits = limits();
    limits.max_batch_events = 1;
    assert_eq!(
        batch.validate(&limits, now()).unwrap_err().code,
        ValidationCode::LimitExceeded
    );
}

#[test]
fn allows_identical_repeats_but_detects_conflicting_ids() {
    let mut batch = parse(fixture());
    batch.events.push(batch.events[0].clone());
    assert!(batch.validate(&limits(), now()).is_ok());
    batch.events[1].payload = json!({"username": "different"});
    let error = batch.validate(&limits(), now()).unwrap_err();
    assert_eq!(error.code, ValidationCode::ConflictingEventId);
    assert_eq!(error.event_index, Some(1));
}

#[test]
fn preserves_timestamp_precision_and_accepts_explicit_offsets() {
    let mut value = fixture();
    value["events"][0]["occurred_at"] = json!("2026-10-10T15:00:00.123456789+03:00");
    let batch = parse(value);
    assert!(batch.validate(&limits(), now()).is_ok());
    assert_eq!(
        batch.events[0].occurred_at.timestamp_subsec_nanos(),
        123456789
    );
}

#[test]
fn checks_age_and_future_skew_boundaries() {
    let limits = limits();
    let mut batch = parse(fixture());
    for (timestamp, expected) in [
        (
            now() - Duration::seconds(limits.max_event_age_seconds),
            None,
        ),
        (
            now() - Duration::seconds(limits.max_event_age_seconds + 1),
            Some(ValidationCode::EventTooOld),
        ),
        (
            now() + Duration::seconds(limits.max_future_skew_seconds),
            None,
        ),
        (
            now() + Duration::seconds(limits.max_future_skew_seconds + 1),
            Some(ValidationCode::EventInFuture),
        ),
    ] {
        batch.events[0].occurred_at = timestamp;
        assert_eq!(
            batch.validate(&limits, now()).err().map(|e| e.code),
            expected
        );
    }
}

#[test]
fn bounds_payload_and_metadata_without_returning_sensitive_values() {
    let mut batch = parse(fixture());
    batch.events[0].payload = json!({"password": "do-not-leak"});
    let mut limits = limits();
    limits.max_payload_bytes = 2;
    let error = batch.validate(&limits, now()).unwrap_err();
    assert_eq!(error.field, "payload");
    assert!(
        !serde_json::to_string(&error)
            .unwrap()
            .contains("do-not-leak")
    );
    limits.max_payload_bytes = 1000;
    limits.max_metadata_bytes = 2;
    assert_eq!(
        batch.validate(&limits, now()).unwrap_err().field,
        "metadata"
    );
}

#[test]
fn rejects_non_object_payloads_and_unsafe_labels() {
    for (field, value) in [
        ("payload", json!([])),
        ("metadata", json!(null)),
        ("event_type", json!("auth.failed\nforged-log")),
        ("protocol", json!("")),
        ("service_type", json!("SSH")),
        ("session_id", json!("bad\nsession")),
    ] {
        let mut input = fixture();
        input["events"][0][field] = value;
        assert_eq!(
            parse(input).validate(&limits(), now()).unwrap_err().field,
            field
        );
    }
}

#[test]
fn service_types_are_extensible_and_sessions_need_not_be_uuids() {
    let mut batch = parse(fixture());
    batch.events[0].service_type = "custom-service.v2".into();
    batch.events[0].session_id = Some("cowrie-session-id".into());
    assert!(batch.validate(&limits(), now()).is_ok());
}

#[test]
fn parses_ipv6_and_unknown_network_fields_without_inventing_values() {
    let mut input = fixture();
    input["events"][0]["source_ip"] = json!("2001:db8::15");
    input["events"][0]["source_port"] = Value::Null;
    let batch = parse(input);
    assert!(batch.events[0].source_ip.unwrap().is_ipv6());
    assert!(batch.events[0].source_port.is_none());
    assert!(batch.validate(&limits(), now()).is_ok());
}

#[test]
fn rejects_invalid_ips_ports_and_sender_supplied_received_at() {
    for (field, value) in [
        ("source_ip", json!("not-an-ip")),
        ("source_port", json!(-1)),
        ("destination_port", json!(65536)),
        ("received_at", json!("2026-10-10T12:00:00Z")),
    ] {
        let mut input = fixture();
        input["events"][0][field] = value;
        assert!(serde_json::from_value::<TelemetryBatch>(input).is_err());
    }
}
