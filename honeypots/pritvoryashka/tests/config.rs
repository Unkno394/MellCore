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
fn vulnerability_profiles_must_match_middle_operating_system() {
    let mut value = valid();
    value["distribution"] = json!("windows");
    value["vulnerability_profiles"] = json!(["win_autologon_credentials", "win_guest_share"]);
    let config: Config = serde_json::from_value(value.clone()).unwrap();
    config.validate().unwrap();

    value["vulnerability_profiles"] = json!(["docker_api_exposed"]);
    let config: Config = serde_json::from_value(value.clone()).unwrap();
    assert!(config.validate().is_err());

    value["distribution"] = json!("debian");
    value["vulnerability_profiles"] = json!(["win_autologon_credentials"]);
    let config: Config = serde_json::from_value(value).unwrap();
    assert!(config.validate().is_err());
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
