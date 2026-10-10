use honeyforge_backend::{kozyavka, management::ProfileInput};
use serde_json::{Value, json};

fn profile(config: Value) -> ProfileInput {
    serde_json::from_value(json!({"name":"kozyavka","level":"low","honeypot_type":"kozyavka","service_type":"ssh","config":config})).unwrap()
}

#[test]
fn kozyavka_accepts_only_the_standalone_programs_settings() {
    profile(json!({})).validate().unwrap();
    profile(json!({"bind_address":"::1","banner":"X".repeat(253)}))
        .validate()
        .unwrap();
    for config in [
        json!({"banner":""}),
        json!({"banner":"X".repeat(254)}),
        json!({"banner":"SSH\nINJECT"}),
        json!({"banner":"Ловушка"}),
        json!({"bind_address":"host.example.test"}),
        json!({"port":2222}),
        json!({"trap_id":"6b6f7a79-6176-4b61-8000-000000000001"}),
        json!({"server_id":"6b6f7a79-6176-4b61-8000-000000000001"}),
    ] {
        assert!(profile(config).validate().is_err());
    }
    let mut wrong = profile(json!({}));
    wrong.service_type = "http".into();
    assert!(wrong.validate().is_err());
    let mut wrong = profile(json!({}));
    wrong.level = honeyforge_backend::models::TrapLevel::Medium;
    assert!(wrong.validate().is_err());
    let defaults: Value = serde_json::to_value(kozyavka::Settings::default()).unwrap();
    assert_eq!(
        defaults,
        json!({"bind_address":"127.0.0.1","banner":"SSH-2.0-OpenSSH_9.6"})
    );
}
