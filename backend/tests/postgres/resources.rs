use super::{PASSWORD, Session, TELEMETRY_TOKEN, login, profile, request};
use axum::{Router, http::StatusCode};
use honeyforge_backend::{
    api::{AppState, router_with_state},
    config::Config,
    management, storage,
};
use serde_json::{Value, json};
use uuid::Uuid;

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    user: Option<&Session>,
    body: Value,
    expected: u16,
) -> Value {
    let (status, result, _) = request(app, method, path, user, body).await;
    assert_eq!(
        status,
        StatusCode::from_u16(expected).unwrap(),
        "{method} {path}: {result}"
    );
    result
}
fn server(name: &str) -> Value {
    json!({"name":name,"host":"Host.Example.test","ssh_user":"honeyforge","ssh_port":22,"dispatcher_port":4000,"credential_ref":Uuid::new_v4(),"settings":{"cpu_limit":2,"memory_limit_mb":512}})
}
fn binding(port: u16, transport: &str, mode: &str) -> Value {
    json!({"host_port":port,"target_port":80,"transport":transport,"route_mode":mode})
}
fn trap(profile: &str, ports: Vec<Value>) -> Value {
    json!({"name":"owned trap","profile_id":profile,"config":{"banner":"override"},"desired_state":"stopped","ports":ports})
}

pub async fn run(parent: &sqlx::PgPool, url: &str, config: &Config) {
    sqlx::query("CREATE SCHEMA resources_check")
        .execute(parent)
        .await
        .unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .after_connect(|c, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO resources_check")
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap();
    // Upgrade the earlier auth schema, then exercise resources and migration replay.
    let previous = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(storage::MIGRATOR.iter().take(2).cloned().collect()),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    previous.run(&pool).await.unwrap();
    storage::MIGRATOR.run(&pool).await.unwrap();
    let state = AppState::new(config.clone(), pool.clone()).await.unwrap();
    management::bootstrap(
        &pool,
        state.auth().unwrap(),
        "resourceadmin",
        "resourceadmin@example.test",
        PASSWORD.into(),
    )
    .await
    .unwrap();
    let app = router_with_state(state);
    let admin = login(&app, "resourceadmin", PASSWORD).await;
    let existing_profile = call(
        &app,
        "POST",
        "/api/v1/profiles",
        Some(&admin),
        profile("resource profile"),
        201,
    )
    .await;
    let profile_id = existing_profile["id"].as_str().unwrap();
    let a_user = call(
        &app,
        "POST",
        "/api/v1/auth/register",
        None,
        json!({"name":"Owner A","email":"ownera@example.test","password":PASSWORD}),
        201,
    )
    .await;
    let b_user = call(
        &app,
        "POST",
        "/api/v1/auth/register",
        None,
        json!({"name":"Owner B","email":"ownerb@example.test","password":PASSWORD}),
        201,
    )
    .await;
    let a = login(&app, "ownera", PASSWORD).await;
    let b = login(&app, "ownerb", PASSWORD).await;
    storage::MIGRATOR.run(&pool).await.unwrap();
    storage::MIGRATOR.run(&pool).await.unwrap();
    storage::check_schema(&pool).await.unwrap();
    assert_eq!(
        call(&app, "GET", "/api/v1/auth/me", Some(&a), Value::Null, 200).await["user"],
        a_user
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/api/v1/profiles/{profile_id}"),
            Some(&a),
            Value::Null,
            200
        )
        .await,
        existing_profile
    );

    for path in ["/api/v1/servers", "/api/v1/traps"] {
        call(&app, "GET", path, None, Value::Null, 401).await;
    }
    for field in [
        "user_id",
        "owner_id",
        "status",
        "server_id",
        "password",
        "private_key",
    ] {
        let mut body = server("reject");
        body[field] = json!("never-log-this");
        let rejected = call(&app, "POST", "/api/v1/servers", Some(&a), body, 422).await;
        assert!(!rejected.to_string().contains("never-log-this"));
    }
    let sa = call(&app, "POST", "/api/v1/servers", Some(&a), server("A1"), 201).await;
    let sa2 = call(&app, "POST", "/api/v1/servers", Some(&a), server("A2"), 201).await;
    let sb = call(&app, "POST", "/api/v1/servers", Some(&b), server("B1"), 201).await;
    assert_eq!(sa["user_id"], a_user["id"]);
    assert_eq!(sa["host"], "host.example.test");
    assert_eq!(sa["status"], "unknown");
    let sid = sa["server_id"].as_str().unwrap();
    let sid2 = sa2["server_id"].as_str().unwrap();
    let bid = sb["server_id"].as_str().unwrap();
    let path = format!("/api/v1/servers/{sid}");
    let port_path = format!("{path}/ports");
    let reservations = call(&app, "GET", &port_path, Some(&a), Value::Null, 200).await;
    assert_eq!(reservations.as_array().unwrap().len(), 2);
    assert!(
        reservations
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["purpose"] == "ssh" && p["host_port"] == 22)
    );
    let page = call(
        &app,
        "GET",
        "/api/v1/servers?limit=1",
        Some(&a),
        Value::Null,
        200,
    )
    .await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let next = call(
        &app,
        "GET",
        &format!(
            "/api/v1/servers?limit=1&after={}",
            page["next_cursor"].as_str().unwrap()
        ),
        Some(&a),
        Value::Null,
        200,
    )
    .await;
    assert_ne!(page["items"][0]["server_id"], next["items"][0]["server_id"]);
    assert!(next["next_cursor"].is_null());
    assert_eq!(
        call(&app, "GET", "/api/v1/servers", Some(&b), Value::Null, 200).await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        call(
            &app,
            "GET",
            "/api/v1/servers",
            Some(&admin),
            Value::Null,
            200
        )
        .await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for stranger in [&b, &admin] {
        call(&app, "GET", &path, Some(stranger), Value::Null, 404).await;
        call(
            &app,
            "PUT",
            &path,
            Some(stranger),
            json!({"expected_version":1,"server":server("stolen")}),
            404,
        )
        .await;
        call(&app, "DELETE", &path, Some(stranger), Value::Null, 404).await;
        call(&app, "GET", &port_path, Some(stranger), Value::Null, 404).await;
        call(
            &app,
            "GET",
            &format!("/api/v1/traps?server_id={sid}"),
            Some(stranger),
            Value::Null,
            404,
        )
        .await;
        call(
            &app,
            "POST",
            "/api/v1/traps",
            Some(stranger),
            json!({"server_id":sid,"trap":trap(profile_id,vec![])}),
            404,
        )
        .await;
    }
    call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":bid,"trap":trap(profile_id,vec![])}),
        404,
    )
    .await;
    let mut no_profile = trap(profile_id, vec![]);
    no_profile["profile_id"] = json!(Uuid::new_v4());
    call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":sid,"trap":no_profile}),
        404,
    )
    .await;
    for field in ["user_id", "owner_id", "actual_state", "trap_id"] {
        let mut spoofed = trap(profile_id, vec![]);
        spoofed[field] = json!("spoofed");
        call(
            &app,
            "POST",
            "/api/v1/traps",
            Some(&a),
            json!({"server_id":sid,"trap":spoofed}),
            422,
        )
        .await;
    }
    let first_input = trap(profile_id, vec![binding(8080, "tcp", "direct")]);
    let ta = call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":sid,"trap":first_input}),
        201,
    )
    .await;
    let tid = ta["trap_id"].as_str().unwrap();
    let tpath = format!("/api/v1/traps/{tid}");
    assert_eq!(ta["user_id"], a_user["id"]);
    assert_eq!(ta["server_id"], sa["server_id"]);
    assert_eq!(ta["actual_state"], "unknown");
    assert_eq!(ta["profile_version"], 1);
    assert_eq!(ta["effective_config"]["banner"], "override");
    for stranger in [&b, &admin] {
        call(&app, "GET", &tpath, Some(stranger), Value::Null, 404).await;
        call(
            &app,
            "PUT",
            &tpath,
            Some(stranger),
            json!({"expected_version":1,"trap":first_input}),
            404,
        )
        .await;
        call(&app, "DELETE", &tpath, Some(stranger), Value::Null, 404).await;
        assert!(
            call(
                &app,
                "GET",
                "/api/v1/traps",
                Some(stranger),
                Value::Null,
                200
            )
            .await["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    call(&app, "DELETE", &path, Some(&a), Value::Null, 409).await;
    call(
        &app,
        "DELETE",
        &format!("/api/v1/profiles/{profile_id}"),
        Some(&admin),
        Value::Null,
        409,
    )
    .await;
    call(
        &app,
        "DELETE",
        &format!("/api/v1/users/{}", a_user["id"].as_str().unwrap()),
        Some(&admin),
        Value::Null,
        409,
    )
    .await;

    // FK ownership cannot be bypassed by direct SQL, independently of API checks.
    let mismatch = sqlx::query("UPDATE traps SET user_id=$1 WHERE trap_id=$2")
        .bind(Uuid::parse_str(b_user["id"].as_str().unwrap()).unwrap())
        .bind(Uuid::parse_str(tid).unwrap())
        .execute(&pool)
        .await;
    assert!(mismatch.is_err());
    for port in [22, 4000, 8080] {
        call(
            &app,
            "POST",
            "/api/v1/traps",
            Some(&a),
            json!({"server_id":sid,"trap":trap(profile_id,vec![binding(port,"tcp","direct")])}),
            409,
        )
        .await;
    }
    // Different transport and different logical server may reserve the same port.
    let udp = call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":sid,"trap":trap(profile_id,vec![binding(8080,"udp","direct")])}),
        201,
    )
    .await;
    let other = call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":sid2,"trap":first_input}),
        201,
    )
    .await;
    let backend=call(&app,"POST","/api/v1/traps",Some(&a),json!({"server_id":sid,"trap":trap(profile_id,vec![binding(9000,"tcp","dispatcher_backend")])}),201).await;
    let mut remove_dispatcher = server("A1");
    remove_dispatcher["dispatcher_port"] = Value::Null;
    call(
        &app,
        "PUT",
        &path,
        Some(&a),
        json!({"expected_version":1,"server":remove_dispatcher}),
        409,
    )
    .await;
    let mut collide_ssh = server("A1");
    collide_ssh["ssh_port"] = json!(8080);
    call(
        &app,
        "PUT",
        &path,
        Some(&a),
        json!({"expected_version":1,"server":collide_ssh}),
        409,
    )
    .await;
    assert_eq!(
        call(&app, "GET", &path, Some(&a), Value::Null, 200).await,
        sa
    );
    // A multi-port replacement that collides with the server's dispatcher
    // listener rolls back config/version and every reservation.
    let mut bad_update = trap(
        profile_id,
        vec![
            binding(8081, "tcp", "direct"),
            binding(4000, "tcp", "direct"),
        ],
    );
    bad_update["name"] = json!("rolled back");
    call(
        &app,
        "PUT",
        &tpath,
        Some(&a),
        json!({"expected_version":1,"trap":bad_update}),
        409,
    )
    .await;
    assert_eq!(
        call(&app, "GET", &tpath, Some(&a), Value::Null, 200).await,
        ta
    );
    let after = call(&app, "GET", &port_path, Some(&a), Value::Null, 200).await;
    assert!(
        !after
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["host_port"] == 8081)
    );

    // Both concurrent operations start with the same available port: only one wins.
    let race_body =
        json!({"server_id":sid,"trap":trap(profile_id,vec![binding(10000,"tcp","direct")])});
    let (r1, r2) = tokio::join!(
        request(&app, "POST", "/api/v1/traps", Some(&a), race_body.clone()),
        request(&app, "POST", "/api/v1/traps", Some(&a), race_body)
    );
    assert!((r1.0 == 201 && r2.0 == 409) || (r1.0 == 409 && r2.0 == 201));
    let winner = if r1.0 == 201 { r1.1 } else { r2.1 };

    // Profile edits do not silently alter an existing trap's pinned snapshot.
    let mut new_profile = profile("profile v2");
    new_profile["config"] = json!({"banner":"profile-new","new_field":true});
    call(
        &app,
        "PUT",
        &format!("/api/v1/profiles/{profile_id}"),
        Some(&admin),
        json!({"expected_version":1,"profile":new_profile}),
        200,
    )
    .await;
    assert_eq!(
        call(&app, "GET", &tpath, Some(&a), Value::Null, 200).await["profile_snapshot"],
        ta["profile_snapshot"]
    );
    let changed = trap(profile_id, vec![binding(8081, "tcp", "direct")]);
    let upgraded = call(
        &app,
        "PUT",
        &tpath,
        Some(&a),
        json!({"expected_version":1,"trap":changed}),
        200,
    )
    .await;
    assert_eq!(upgraded["version"], 2);
    assert_eq!(upgraded["profile_version"], 2);
    assert_eq!(upgraded["effective_config"]["new_field"], true);
    call(
        &app,
        "PUT",
        &tpath,
        Some(&a),
        json!({"expected_version":1,"trap":changed}),
        409,
    )
    .await;
    let freed = call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":sid,"trap":first_input}),
        201,
    )
    .await;
    let mut server_update = server("renamed");
    server_update["ssh_port"] = json!(2222);
    let updated_server = call(
        &app,
        "PUT",
        &path,
        Some(&a),
        json!({"expected_version":1,"server":server_update}),
        200,
    )
    .await;
    assert_eq!(updated_server["version"], 2);
    assert_eq!(updated_server["status"], "unknown");
    call(
        &app,
        "PUT",
        &path,
        Some(&a),
        json!({"expected_version":1,"server":server_update}),
        409,
    )
    .await;
    let freed_ssh = call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":sid,"trap":trap(profile_id,vec![binding(22,"tcp","direct")])}),
        201,
    )
    .await;

    let list = call(
        &app,
        "GET",
        &format!("/api/v1/traps?server_id={sid}&limit=2"),
        Some(&a),
        Value::Null,
        200,
    )
    .await;
    assert_eq!(list["items"].as_array().unwrap().len(), 2);
    assert!(list["next_cursor"].is_string());
    assert!(
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["server_id"] == sid)
    );
    let next = call(
        &app,
        "GET",
        &format!(
            "/api/v1/traps?server_id={sid}&limit=2&after={}",
            list["next_cursor"].as_str().unwrap()
        ),
        Some(&a),
        Value::Null,
        200,
    )
    .await;
    assert!(next["items"].as_array().unwrap().iter().all(|t| {
        !list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|prev| prev["trap_id"] == t["trap_id"])
    }));
    for url in ["/api/v1/servers?limit=101", "/api/v1/traps?limit=0"] {
        call(&app, "GET", url, Some(&a), Value::Null, 422).await;
    }

    // Existing standalone Low is registered as kozyavka; configuration is derived,
    // not a deployment command and not an opportunity to spoof identity or ports.
    let low_profile = honeyforge_backend::kozyavka::PROFILE_ID.to_string();
    let low = call(
        &app,
        "GET",
        &format!("/api/v1/profiles/{low_profile}"),
        Some(&a),
        Value::Null,
        200,
    )
    .await;
    assert_eq!(low["name"], "kozyavka");
    assert_eq!(low["level"], "low");
    let mut low_input = trap(
        &low_profile,
        vec![json!({"host_port":2223,"target_port":2222,"transport":"tcp","route_mode":"direct"})],
    );
    low_input["name"] = json!("kozyavka");
    low_input["config"] = json!({});
    for bad in [
        json!({"trap_id":Uuid::new_v4()}),
        json!({"server_id":sid}),
        json!({"port":22}),
        json!({"banner":"bad\r\ninjected"}),
    ] {
        let mut invalid = low_input.clone();
        invalid["config"] = bad;
        call(
            &app,
            "POST",
            "/api/v1/traps",
            Some(&a),
            json!({"server_id":sid2,"trap":invalid}),
            422,
        )
        .await;
    }
    let mut invalid = low_input.clone();
    invalid["ports"][0]["transport"] = json!("udp");
    call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":sid2,"trap":invalid}),
        422,
    )
    .await;
    let kt = call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":sid2,"trap":low_input}),
        201,
    )
    .await;
    let kp = format!("/api/v1/traps/{}", kt["trap_id"].as_str().unwrap());
    let export = format!("{kp}/runtime-config");
    call(&app, "GET", &export, None, Value::Null, 401).await;
    for stranger in [&b, &admin] {
        call(&app, "GET", &export, Some(stranger), Value::Null, 404).await;
    }
    let runtime = call(&app, "GET", &export, Some(&a), Value::Null, 200).await;
    assert_eq!(
        runtime,
        json!({"bind_address":"127.0.0.1","port":2222,"banner":"SSH-2.0-OpenSSH_9.6","trap_id":kt["trap_id"]})
    );
    assert_eq!(call(&app, "GET", &kp, Some(&a), Value::Null, 200).await, kt);
    call(
        &app,
        "GET",
        &format!("{tpath}/runtime-config"),
        Some(&a),
        Value::Null,
        409,
    )
    .await;
    let mut invalid = low_input.clone();
    invalid["ports"] = json!([]);
    call(
        &app,
        "PUT",
        &kp,
        Some(&a),
        json!({"expected_version":1,"trap":invalid}),
        422,
    )
    .await;
    assert_eq!(
        call(&app, "GET", &export, Some(&a), Value::Null, 200).await,
        runtime
    );
    low_input["config"] = json!({"bind_address":"0.0.0.0","banner":"SSH-2.0-kozyavka"});
    low_input["ports"][0]["target_port"] = json!(2224);
    call(
        &app,
        "PUT",
        &kp,
        Some(&a),
        json!({"expected_version":1,"trap":low_input}),
        200,
    )
    .await;
    let runtime = call(&app, "GET", &export, Some(&a), Value::Null, 200).await;
    assert_eq!(runtime["port"], 2224);
    assert_eq!(runtime["banner"], "SSH-2.0-kozyavka");
    call(&app, "DELETE", &kp, Some(&a), Value::Null, 204).await;

    // Native Middle profile exports a directly consumable runtime config and its
    // canonical events are accepted idempotently by the existing backend.
    let middle_profile = honeyforge_backend::pritvoryashka::PROFILE_ID.to_string();
    let middle_catalog = call(
        &app,
        "GET",
        &format!("/api/v1/profiles/{middle_profile}"),
        Some(&a),
        Value::Null,
        200,
    )
    .await;
    assert_eq!(middle_catalog["level"], "medium");
    let middle_input = json!({
        "name":"Pritvoryashka",
        "profile_id":middle_profile,
        "config":{},
        "desired_state":"stopped",
        "ports":[{"host_port":2223,"target_port":2222,"transport":"tcp","route_mode":"direct"}]
    });
    let middle = call(
        &app,
        "POST",
        "/api/v1/traps",
        Some(&a),
        json!({"server_id":sid2,"trap":middle_input}),
        201,
    )
    .await;
    let middle_path = format!("/api/v1/traps/{}", middle["trap_id"].as_str().unwrap());
    let middle_runtime = call(
        &app,
        "GET",
        &format!("{middle_path}/runtime-config"),
        Some(&a),
        Value::Null,
        200,
    )
    .await;
    assert_eq!(middle_runtime["bind"], "0.0.0.0:2222");
    assert_eq!(middle_runtime["auth"]["policy"], "accept_all");
    assert_eq!(
        middle_runtime["telemetry"]["endpoint"],
        "http://127.0.0.1:8080/internal/v1/telemetry/batches"
    );
    assert_eq!(
        middle_runtime["telemetry"]["token_env"],
        "PRITVORYASHKA_TELEMETRY_TOKEN"
    );
    let telemetry = Session {
        token: TELEMETRY_TOKEN.into(),
    };
    let event_id = Uuid::new_v4();
    let batch_id = Uuid::new_v4();
    let event = json!({
        "event_id":event_id,
        "trap_id":middle["trap_id"],
        "session_id":Uuid::new_v4().to_string(),
        "sequence_no":1,
        "event_type":"command.executed",
        "occurred_at":chrono::Utc::now(),
        "source_ip":"192.0.2.15",
        "source_port":50124,
        "destination_port":2222,
        "protocol":"tcp",
        "service_type":"ssh",
        "payload":{"command":"pwd"},
        "metadata":{"source":"pritvoryashka"}
    });
    let batch = json!({
        "schema_version":1,
        "batch_id":batch_id,
        "agent_id":sid2,
        "server_id":sid2,
        "events":[event]
    });
    let accepted = call(
        &app,
        "POST",
        "/internal/v1/telemetry/batches",
        Some(&telemetry),
        batch.clone(),
        202,
    )
    .await;
    assert_eq!(accepted["accepted_events"], 1);
    let replay = call(
        &app,
        "POST",
        "/internal/v1/telemetry/batches",
        Some(&telemetry),
        batch.clone(),
        202,
    )
    .await;
    assert_eq!(replay["duplicate_events"], 1);
    let mut same_event_new_batch = batch.clone();
    same_event_new_batch["batch_id"] = json!(Uuid::new_v4());
    let replay = call(
        &app,
        "POST",
        "/internal/v1/telemetry/batches",
        Some(&telemetry),
        same_event_new_batch,
        202,
    )
    .await;
    assert_eq!(replay["duplicate_events"], 1);
    let wrong = Session {
        token: "wrong-telemetry-token".into(),
    };
    call(
        &app,
        "POST",
        "/internal/v1/telemetry/batches",
        Some(&wrong),
        batch,
        401,
    )
    .await;
    let events_path = format!("{middle_path}/events");
    call(&app, "GET", &events_path, None, Value::Null, 401).await;
    call(
        &app,
        "GET",
        &events_path,
        Some(&telemetry),
        Value::Null,
        401,
    )
    .await;
    call(&app, "GET", &events_path, Some(&b), Value::Null, 404).await;
    let events = call(&app, "GET", &events_path, Some(&a), Value::Null, 200).await;
    assert_eq!(events["items"].as_array().unwrap().len(), 1);
    assert_eq!(events["items"][0]["event_id"], event_id.to_string());
    assert_eq!(events["items"][0]["payload"]["command"], "pwd");
    assert!(events["next_cursor"].is_null());
    call(
        &app,
        "GET",
        &format!("{events_path}?limit=0"),
        Some(&a),
        Value::Null,
        422,
    )
    .await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM attack_events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    sqlx::query("DELETE FROM attack_events")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM telemetry_batches")
        .execute(&pool)
        .await
        .unwrap();
    call(&app, "DELETE", &middle_path, Some(&a), Value::Null, 204).await;

    // Demotion preserves reads but removes all mutation rights and revokes old JWT.
    let account_path = format!("/api/v1/users/{}", a_user["id"].as_str().unwrap());
    call(
        &app,
        "PUT",
        &account_path,
        Some(&admin),
        json!({"username":a_user["username"],"role":"viewer","is_active":true}),
        200,
    )
    .await;
    call(&app, "GET", &path, Some(&a), Value::Null, 401).await;
    let viewer = login(&app, "ownera", PASSWORD).await;
    call(&app, "GET", &tpath, Some(&viewer), Value::Null, 200).await;
    call(
        &app,
        "POST",
        "/api/v1/servers",
        Some(&viewer),
        server("denied"),
        403,
    )
    .await;
    call(&app, "DELETE", &tpath, Some(&viewer), Value::Null, 403).await;
    call(
        &app,
        "PUT",
        &account_path,
        Some(&admin),
        json!({"username":a_user["username"],"role":"user","is_active":true}),
        200,
    )
    .await;
    let a = login(&app, "ownera", PASSWORD).await;
    for t in [&ta, &udp, &other, &backend, &winner, &freed, &freed_ssh] {
        let target = format!("/api/v1/traps/{}", t["trap_id"].as_str().unwrap());
        call(&app, "DELETE", &target, Some(&a), Value::Null, 204).await;
        call(&app, "GET", &target, Some(&a), Value::Null, 404).await;
    }
    let remaining = call(&app, "GET", &port_path, Some(&a), Value::Null, 200).await;
    assert_eq!(remaining.as_array().unwrap().len(), 2);
    for id in [sid, sid2] {
        call(
            &app,
            "DELETE",
            &format!("/api/v1/servers/{id}"),
            Some(&a),
            Value::Null,
            204,
        )
        .await;
    }
    call(&app, "DELETE", &path, Some(&a), Value::Null, 404).await;
    call(
        &app,
        "DELETE",
        &format!("/api/v1/servers/{bid}"),
        Some(&b),
        Value::Null,
        204,
    )
    .await;
    call(
        &app,
        "DELETE",
        &format!("/api/v1/profiles/{profile_id}"),
        Some(&admin),
        Value::Null,
        204,
    )
    .await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM server_ports")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let audit:i64=sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE action IN ('server.create','server.update','server.delete','trap.create','trap.update','trap.delete')").fetch_one(&pool).await.unwrap();
    assert!(audit >= 20);
    pool.close().await;
    call(&app, "GET", "/api/v1/servers", Some(&a), Value::Null, 503).await;
    println!(
        "Verified auth-schema upgrade, owned server/trap CRUD, owner isolation including Admin, FK ownership, profile snapshots, reserved SSH/dispatcher ports, rollback, concurrent port races and kozyavka configuration export."
    );
}
