use honeyforge_backend::resources::{ServerInput, TrapInput, normalize_host};
use serde_json::json;
use uuid::Uuid;

#[test]
fn server_settings_reject_credentials_commands_and_invalid_addresses() {
    let valid = json!({"name":"owned","host":"example.test","ssh_user":"honeyforge"});
    let mut parsed: ServerInput = serde_json::from_value(valid.clone()).unwrap();
    parsed.validate().unwrap();
    assert_eq!(parsed.ssh_port, 22);
    for host in [
        "https://example.test",
        "user:password@host",
        "host:22",
        "-oProxyCommand=evil",
        "a/b",
        "a b",
        "a\n",
        "a..b",
        ".host",
        "host.",
        "",
    ] {
        assert!(normalize_host(host).is_err(), "{host:?}");
    }
    assert_eq!(normalize_host("EXAMPLE.Test").unwrap(), "example.test");
    assert_eq!(normalize_host("2001:db8::1").unwrap(), "2001:db8::1");
    for (field, value) in [
        ("ssh_port", json!(0)),
        ("dispatcher_port", json!(22)),
        ("ssh_user", json!("root;command")),
        ("credential_ref", json!(Uuid::nil())),
        ("settings", json!({"cpu_limit":0})),
        ("settings", json!({"memory_limit_mb":1})),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<ServerInput>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for field in ["password", "private_key", "owner_id", "user_id", "status"] {
        let mut invalid = valid.clone();
        invalid[field] = json!("secret");
        assert!(serde_json::from_value::<ServerInput>(invalid).is_err());
    }
    let mut nested = valid;
    nested["settings"] = json!({"ssh_password":"secret"});
    assert!(serde_json::from_value::<ServerInput>(nested).is_err());
}
#[test]
fn trap_ports_and_config_reject_conflicts_and_secret_material() {
    let binding =
        json!({"transport":"tcp","host_port":8080,"target_port":80,"route_mode":"direct"});
    let valid = json!({"name":"trap","profile_id":Uuid::new_v4(),"config":{},"desired_state":"stopped","ports":[binding]});
    serde_json::from_value::<TrapInput>(valid.clone())
        .unwrap()
        .validate()
        .unwrap();
    let mut duplicate = valid.clone();
    duplicate["ports"] = json!([binding, binding]);
    assert!(
        serde_json::from_value::<TrapInput>(duplicate)
            .unwrap()
            .validate()
            .is_err()
    );
    for field in ["host_port", "target_port"] {
        let mut invalid = valid.clone();
        invalid["ports"][0][field] = json!(0);
        assert!(
            serde_json::from_value::<TrapInput>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut udp = valid.clone();
    udp["ports"][0]["transport"] = json!("udp");
    udp["ports"][0]["route_mode"] = json!("dispatcher_backend");
    assert!(
        serde_json::from_value::<TrapInput>(udp)
            .unwrap()
            .validate()
            .is_err()
    );
    for config in [
        json!([]),
        json!({"nested":[{"private_key":"secret"}]}),
        json!({"large":"x".repeat(65536)}),
    ] {
        let mut invalid = valid.clone();
        invalid["config"] = config;
        assert!(
            serde_json::from_value::<TrapInput>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut excessive = valid;
    excessive["ports"] = json!(vec![binding; 33]);
    assert!(
        serde_json::from_value::<TrapInput>(excessive)
            .unwrap()
            .validate()
            .is_err()
    );
}
