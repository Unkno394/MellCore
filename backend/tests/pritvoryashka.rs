use honeyforge_backend::{management::ProfileInput, models::TrapLevel, pritvoryashka};
use serde_json::{Value, json};

fn profile(config: Value) -> ProfileInput {
    serde_json::from_value(json!({
        "name":"Pritvoryashka",
        "level":"medium",
        "honeypot_type":"pritvoryashka",
        "service_type":"ssh",
        "config":config
    }))
    .unwrap()
}

#[test]
fn medium_profile_accepts_safe_runtime_settings() {
    profile(json!({})).validate().unwrap();
    profile(json!({
        "bind_address":"0.0.0.0",
        "hostname":"db-staging-01",
        "credential_capture":"none",
        "max_connections":64
    }))
    .validate()
    .unwrap();
}

#[test]
fn medium_profile_rejects_wrong_level_service_and_unsafe_values() {
    let mut wrong = profile(json!({}));
    wrong.level = TrapLevel::Low;
    assert!(wrong.validate().is_err());
    let mut wrong = profile(json!({}));
    wrong.service_type = "http".into();
    assert!(wrong.validate().is_err());
    for config in [
        json!({"hostname":"bad host"}),
        json!({"max_connections":0}),
        json!({"host_key":"bad\npath"}),
        json!({"telemetry_endpoint":"https://example.test/ingest"}),
        json!({"unknown":true}),
    ] {
        assert!(profile(config).validate().is_err());
    }
}

#[test]
fn profile_identity_is_stable() {
    assert_eq!(
        pritvoryashka::PROFILE_ID.to_string(),
        "70726974-766f-4279-8000-000000000001"
    );
}
