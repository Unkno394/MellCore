use pritvoryashka::{Config, config::ConfigError};
use serde_json::json;

fn valid() -> serde_json::Value {
    serde_json::from_str(include_str!("../pritvoryashka.example.json")).unwrap()
}

#[test]
fn example_configuration_is_valid() {
    let config: Config = serde_json::from_value(valid()).unwrap();
    config.validate().unwrap();
}

#[test]
fn configured_auth_requires_secret_environment_reference() {
    let mut value = valid();
    value["auth"]["policy"] = json!("configured");
    value["auth"]["username"] = json!("admin");
    let config: Config = serde_json::from_value(value).unwrap();
    assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn telemetry_endpoint_requires_token_reference() {
    let mut value = valid();
    value["telemetry"]["endpoint"] =
        json!("https://honeyforge.example/internal/v1/telemetry/batches");
    let config: Config = serde_json::from_value(value).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn telemetry_requires_a_sink_and_rejects_remote_plaintext_http() {
    let mut value = valid();
    value["telemetry"]["jsonl_path"] = serde_json::Value::Null;
    let config: Config = serde_json::from_value(value.clone()).unwrap();
    assert!(config.validate().is_err());
    value["telemetry"]["endpoint"] = json!("http://example.test/internal/v1/telemetry/batches");
    value["telemetry"]["token_env"] = json!("TEST_TOKEN");
    let config: Config = serde_json::from_value(value).unwrap();
    assert!(config.validate().is_err());
}
