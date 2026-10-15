#[path = "postgres/resources.rs"]
mod resources;
#[path = "postgres/verification.rs"]
mod verification;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use honeyforge_backend::{
    api::{AppState, router_with_state},
    config::Config,
    management, storage,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "http://127.0.0.1:8080";
const PASSWORD: &str = "test-only-long-password";
const CENTER_TOKEN: &str = "test-only-center-secret-separate-32-bytes";
const TELEMETRY_TOKEN: &str = "test-only-telemetry-token-32-bytes-long";

struct Session {
    token: String,
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    session: Option<&Session>,
    body: Value,
) -> (StatusCode, Value, Option<String>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", ORIGIN)
        .header("content-type", "application/json");
    if let Some(session) = session {
        request = request.header("authorization", format!("Bearer {}", session.token));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get("set-cookie")
        .map(|h| h.to_str().unwrap().to_owned());
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if status.is_client_error() || status.is_server_error() {
        assert_eq!(body["error"]["request_id"], request_id);
    }
    (status, body, cookie)
}

async fn login(app: &Router, name: &str, password: &str) -> Session {
    let (status, body, cookie) = request(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        json!({"email":format!("{name}@example.test"),"password":password}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["user"].get("password_hash").is_none());
    assert!(
        cookie
            .as_deref()
            .is_some_and(|value| value.starts_with("__Host-mellcore-refresh=")
                && value.contains("HttpOnly")
                && value.contains("SameSite=Strict"))
    );
    assert_eq!(body["token_type"], "Bearer");
    Session {
        token: body["access_token"].as_str().unwrap().into(),
    }
}

fn profile(name: &str) -> Value {
    json!({"name":name,"description":"test", "level":"medium", "honeypot_type":"cowrie", "service_type":"ssh", "config":{"banner":"test"}})
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run python3 scripts/test_postgres.py"]
async fn postgres_management_and_security_end_to_end() {
    let url = std::env::var("TEST_DATABASE_URL").expect("use scripts/test_postgres.py");
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(
        parsed.host_str(),
        Some("127.0.0.1"),
        "tests require loopback"
    );
    assert_eq!(
        parsed.path(),
        "/honeyforge_test",
        "refusing a non-test database"
    );
    let config = Config::from_lookup(|key| {
        Ok(match key {
            "DATABASE_URL" => Some(url.clone()),
            "DATABASE_ALLOW_INSECURE_LOCAL" => Some("true".into()),
            "APP_ORIGIN" => Some(ORIGIN.into()),
            "JWT_SECRET" => Some("test-only-signing-secret-at-least-32-bytes".into()),
            "LOGIN_PER_MINUTE" => Some("100".into()),
            "TELEMETRY_INGEST_TOKEN" => Some(TELEMETRY_TOKEN.into()),
            "CENTER_INGEST_TOKEN" => Some(CENTER_TOKEN.into()),
            "TELEMETRY_PUBLIC_ENDPOINT" => {
                Some("http://127.0.0.1:8080/internal/v1/telemetry/batches".into())
            }
            _ => None,
        })
    })
    .unwrap();
    let pool = storage::connect(&config).await.unwrap();
    let existing: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='users')").fetch_one(&pool).await.unwrap();
    assert!(
        !existing,
        "refusing to reuse a database with existing application data"
    );
    // Upgrade a populated old schema; original migration and rows are preserved.
    let old = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(vec![storage::MIGRATOR.iter().next().unwrap().clone()]),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    old.run(&pool).await.unwrap();
    let runtime = honeyforge_backend::auth::AuthRuntime::new(2, 100)
        .await
        .unwrap();
    let legacy_hash = runtime.hash(PASSWORD.into()).await.unwrap();
    let admin_id = Uuid::new_v4();
    let legacy_token = honeyforge_backend::auth::new_token();
    sqlx::query("INSERT INTO users(id,username,password_hash,role) VALUES ($1,'admin',$2,'admin')")
        .bind(admin_id)
        .bind(&legacy_hash)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,csrf_hash,user_id,expires_at) VALUES ($1,$1,$2,now()+interval '1 hour')").bind(honeyforge_backend::auth::digest(&legacy_token)).bind(admin_id).execute(&pool).await.unwrap();
    let legacy_profile = Uuid::new_v4();
    sqlx::query("INSERT INTO trap_profiles(id,name,level,honeypot_type,service_type,config) VALUES ($1,'legacy','low','custom','http','{}')").bind(legacy_profile).execute(&pool).await.unwrap();
    let mut legacy_tx = pool.begin().await.unwrap();
    management::audit(
        &mut legacy_tx,
        admin_id,
        "test.legacy_audit",
        admin_id,
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    legacy_tx.commit().await.unwrap();
    storage::MIGRATOR.run(&pool).await.unwrap();
    storage::MIGRATOR.run(&pool).await.unwrap();
    storage::check_schema(&pool).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT action FROM audit_logs LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap(),
        "test.legacy_audit"
    );
    let legacy: (String, String, Option<String>, String) =
        sqlx::query_as("SELECT password_hash,name,email,role FROM users WHERE id=$1")
            .bind(admin_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(legacy, (legacy_hash, "admin".into(), None, "admin".into()));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT name FROM trap_profiles WHERE id=$1")
            .bind(legacy_profile)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "legacy"
    );
    management::attach_email(&pool, "admin", "ADMIN@example.test")
        .await
        .unwrap();
    assert!(
        management::attach_email(&pool, "admin", "other@example.test")
            .await
            .is_err()
    );
    resources::run(&pool, &url, &config).await;
    verification::run(&pool, &url, &config).await;
    fresh_bootstrap(&pool, &url, &config).await;
    let mut state = AppState::new(config, pool.clone()).await.unwrap();
    let without_smtp = router_with_state(state.clone());
    for email in ["admin@example.test", "missing@example.test"] {
        assert_eq!(
            request(
                &without_smtp,
                "POST",
                "/api/v1/auth/forgot-password",
                None,
                json!({"email":email})
            )
            .await
            .0,
            503
        );
    }
    assert!(
        management::bootstrap(
            &pool,
            state.auth().unwrap(),
            "another",
            "another@example.test",
            PASSWORD.into()
        )
        .await
        .is_err()
    );
    let (delivery, mut mailbox) = tokio::sync::mpsc::channel(16);
    state.password_resets = Some(honeyforge_backend::password_reset::PasswordResets::start(
        pool.clone(),
        std::sync::Arc::new(CaptureDelivery(delivery)),
    ));
    let app = router_with_state(state);

    assert_eq!(
        request(&app, "GET", "/health/ready", None, Value::Null)
            .await
            .0,
        200
    );
    assert_eq!(
        request(&app, "GET", "/api/v1/profiles", None, Value::Null)
            .await
            .0,
        401
    );
    for username in ["admin", "unknown"] {
        let (status, body, _) = request(
            &app,
            "POST",
            "/api/v1/auth/login",
            None,
            json!({"email":format!("{username}@example.test"),"password":"wrong-password"}),
        )
        .await;
        assert_eq!(status, 401);
        assert_eq!(body["error"]["code"], "unauthorized");
    }
    let admin = login(&app, "ADMIN", PASSWORD).await;
    let me = request(&app, "GET", "/api/v1/auth/me", Some(&admin), Value::Null).await;
    assert_eq!(me.1["user"]["id"], admin_id.to_string());
    let (_, _, cookie) = request(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        json!({"email":"admin@example.test","password":PASSWORD}),
    )
    .await;
    let cookie = cookie.unwrap().split(';').next().unwrap().to_owned();
    let cross_site = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("origin", "https://other.example.test")
                .header("cookie", cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_site.status(), 403);
    let refresh = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("origin", ORIGIN)
                .header("cookie", cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh.status(), 200);
    let renewed: Value =
        serde_json::from_slice(&to_bytes(refresh.into_body(), 1_048_576).await.unwrap()).unwrap();
    let renewed_session = Session {
        token: renewed["access_token"].as_str().unwrap().into(),
    };
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/auth/me",
            Some(&renewed_session),
            Value::Null
        )
        .await
        .0,
        200
    );
    let logout = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("origin", ORIGIN)
                .header("cookie", cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), 204);
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/auth/me",
            Some(&renewed_session),
            Value::Null
        )
        .await
        .0,
        401
    );
    let replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("origin", ORIGIN)
                .header("cookie", cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), 401);
    let (status, body, _) = request(
        &app,
        "POST",
        "/api/v1/users",
        Some(&admin),
        json!({"username":"Viewer", "email":"viewer@example.test", "password":PASSWORD, "role":"viewer"}),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let viewer_id = body["id"].as_str().unwrap().to_owned();
    let viewer = login(&app, "viewer", PASSWORD).await;
    assert_eq!(
        request(&app, "GET", "/api/v1/users", Some(&viewer), Value::Null)
            .await
            .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/users",
            Some(&viewer),
            json!({"username":"bad", "password":PASSWORD, "role":"admin"})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/profiles",
            Some(&viewer),
            profile("denied")
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/users",
            Some(&admin),
            json!({"username":"VIEWER", "password":PASSWORD, "role":"viewer"})
        )
        .await
        .0,
        409
    );

    let forged = Session {
        token: format!("{}tampered", admin.token),
    };
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/profiles",
            Some(&forged),
            profile("denied")
        )
        .await
        .0,
        401
    );
    // Old ambient cookie authentication cannot authorize API requests.
    let cookie_only = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("cookie", format!("hf_session={legacy_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookie_only.status(), 401);
    public_auth_scenarios(&app, &pool, &admin, &mut mailbox).await;

    let (status, body, _) = request(
        &app,
        "POST",
        "/api/v1/profiles",
        Some(&admin),
        profile("first"),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let profile_id = body["id"].as_str().unwrap();
    let path = format!("/api/v1/profiles/{profile_id}");
    assert_eq!(
        request(&app, "GET", &path, Some(&viewer), Value::Null)
            .await
            .0,
        200
    );
    assert_eq!(
        request(
            &app,
            "PUT",
            &path,
            Some(&viewer),
            json!({"expected_version":1,"profile":profile("denied")})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(&app, "DELETE", &path, Some(&viewer), Value::Null)
            .await
            .0,
        403
    );
    let updated = request(
        &app,
        "PUT",
        &path,
        Some(&admin),
        json!({"expected_version":1,"profile":profile("updated")}),
    )
    .await;
    assert_eq!(updated.0, 200, "{}", updated.1);
    assert_eq!(updated.1["version"], 2);
    assert_eq!(
        request(
            &app,
            "PUT",
            &path,
            Some(&admin),
            json!({"expected_version":1,"profile":profile("stale")})
        )
        .await
        .0,
        409
    );
    let mut malicious = profile("invalid");
    malicious["config"] = json!({"private_key":"never-log-this"});
    let rejection = request(&app, "POST", "/api/v1/profiles", Some(&admin), malicious).await;
    assert_eq!(rejection.0, 422);
    assert!(!rejection.1.to_string().contains("never-log-this"));
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/profiles/not-a-uuid",
            Some(&admin),
            Value::Null
        )
        .await
        .0,
        400
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/profiles?limit=101",
            Some(&admin),
            Value::Null
        )
        .await
        .0,
        422
    );
    for name in ["second", "third"] {
        assert_eq!(
            request(
                &app,
                "POST",
                "/api/v1/profiles",
                Some(&admin),
                profile(name)
            )
            .await
            .0,
            201
        );
    }
    let first_page = request(
        &app,
        "GET",
        "/api/v1/profiles?limit=2",
        Some(&viewer),
        Value::Null,
    )
    .await
    .1;
    let cursor = first_page["next_cursor"].as_str().unwrap();
    let second_page = request(
        &app,
        "GET",
        &format!("/api/v1/profiles?limit=2&after={cursor}"),
        Some(&viewer),
        Value::Null,
    )
    .await
    .1;
    assert_eq!(first_page["items"].as_array().unwrap().len(), 2);
    assert_eq!(second_page["items"].as_array().unwrap().len(), 2);
    let third_page = request(
        &app,
        "GET",
        &format!(
            "/api/v1/profiles?limit=2&after={}",
            second_page["next_cursor"].as_str().unwrap()
        ),
        Some(&viewer),
        Value::Null,
    )
    .await
    .1;
    assert_eq!(third_page["items"].as_array().unwrap().len(), 2);
    assert!(third_page["next_cursor"].is_null());
    let unique: std::collections::HashSet<_> = [&first_page, &second_page, &third_page]
        .into_iter()
        .flat_map(|page| page["items"].as_array().unwrap())
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(unique.len(), 6);
    assert_eq!(
        request(&app, "DELETE", &path, Some(&admin), Value::Null)
            .await
            .0,
        204
    );
    assert_eq!(
        request(&app, "GET", &path, Some(&admin), Value::Null)
            .await
            .0,
        404
    );
    assert_eq!(
        request(&app, "DELETE", &path, Some(&admin), Value::Null)
            .await
            .0,
        404
    );

    let admin_path = format!("/api/v1/users/{admin_id}");
    assert_eq!(
        request(&app, "DELETE", &admin_path, Some(&admin), Value::Null)
            .await
            .0,
        409
    );
    assert_eq!(
        request(
            &app,
            "PUT",
            &admin_path,
            Some(&admin),
            json!({"username":"admin","role":"viewer","is_active":true})
        )
        .await
        .0,
        409
    );
    assert_eq!(
        request(
            &app,
            "PUT",
            &admin_path,
            Some(&admin),
            json!({"username":"admin","role":"admin","is_active":false})
        )
        .await
        .0,
        409
    );
    let viewer_path = format!("/api/v1/users/{viewer_id}");
    let updated = request(&app,"PUT",&viewer_path,Some(&admin),json!({"username":"viewer","role":"viewer","is_active":true,"password":"new-long-password"})).await;
    assert_eq!(updated.0, 200);
    assert_eq!(
        request(&app, "GET", "/api/v1/auth/me", Some(&viewer), Value::Null)
            .await
            .0,
        401
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/login",
            None,
            json!({"email":"viewer@example.test","password":PASSWORD})
        )
        .await
        .0,
        401
    );
    let viewer = login(&app, "viewer", "new-long-password").await;
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/logout",
            Some(&viewer),
            Value::Null
        )
        .await
        .0,
        204
    );
    assert_eq!(
        request(&app, "GET", "/api/v1/auth/me", Some(&viewer), Value::Null)
            .await
            .0,
        401
    );
    let viewer = login(&app, "viewer", "new-long-password").await;
    sqlx::query("UPDATE access_tokens SET created_at=now()-interval '2 hours', expires_at=now()-interval '1 hour' WHERE user_id=$1").bind(Uuid::parse_str(&viewer_id).unwrap()).execute(&pool).await.unwrap();
    assert_eq!(
        request(&app, "GET", "/api/v1/auth/me", Some(&viewer), Value::Null)
            .await
            .0,
        401
    );
    assert_eq!(
        request(&app, "DELETE", &viewer_path, Some(&admin), Value::Null)
            .await
            .0,
        204
    );
    assert_eq!(
        request(&app, "GET", &viewer_path, Some(&admin), Value::Null)
            .await
            .0,
        404
    );

    // Two admins concurrently removing themselves must leave one active admin.
    let created = request(
        &app,
        "POST",
        "/api/v1/users",
        Some(&admin),
        json!({"username":"admin2","email":"admin2@example.test","password":PASSWORD,"role":"admin"}),
    )
    .await;
    assert_eq!(created.0, 201);
    let second_id = created.1["id"].as_str().unwrap();
    let admin2 = login(&app, "admin2", PASSWORD).await;
    let second_path = format!("/api/v1/users/{second_id}");
    let (a, b) = tokio::join!(
        request(&app, "DELETE", &admin_path, Some(&admin), Value::Null),
        request(&app, "DELETE", &second_path, Some(&admin2), Value::Null)
    );
    assert!((a.0 == 204 && b.0 == 409) || (a.0 == 409 && b.0 == 204));
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE role='admin' AND is_active")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 1);
    let audit_count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(audit_count >= 10);
    let stored: String = sqlx::query_scalar("SELECT password_hash FROM users LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(stored.starts_with("$argon2id$"));
    let constraints = sqlx::query("INSERT INTO trap_profiles(id,name,level,honeypot_type,service_type,config) VALUES ($1,'invalid','high','cowrie','ssh','{}')").bind(Uuid::new_v4()).execute(&pool).await;
    assert!(constraints.is_err());

    pool.close().await;
    assert_eq!(
        request(&app, "GET", "/health/ready", None, Value::Null)
            .await
            .0,
        503
    );
    let survivor = if a.0 == 204 { &admin2 } else { &admin };
    assert_eq!(
        request(&app, "GET", "/api/v1/profiles", Some(survivor), Value::Null)
            .await
            .0,
        503
    );
    println!(
        "Verified real PostgreSQL migrations, bootstrap, public email auth/JWT/reset/RBAC, CRUD/pagination/versioning, revocation/expiry, last-admin race, audit and database failure."
    );
}

struct CaptureDelivery(tokio::sync::mpsc::Sender<(String, String)>);
impl honeyforge_backend::password_reset::ResetDelivery for CaptureDelivery {
    fn send<'a>(
        &'a self,
        email: &'a str,
        token: &'a str,
    ) -> honeyforge_backend::password_reset::DeliveryFuture<'a> {
        Box::pin(async move {
            self.0
                .send((email.into(), token.into()))
                .await
                .map_err(|_| honeyforge_backend::errors::AppError::internal())
        })
    }
}
async fn delivered(mailbox: &mut tokio::sync::mpsc::Receiver<(String, String)>) -> String {
    let (email, token) = tokio::time::timeout(std::time::Duration::from_secs(5), mailbox.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(email, "member@example.test");
    token
}
async fn public_auth_scenarios(
    app: &Router,
    pool: &sqlx::PgPool,
    admin: &Session,
    mailbox: &mut tokio::sync::mpsc::Receiver<(String, String)>,
) {
    let registration =
        json!({"name":"Тимофей", "email":" MEMBER@EXAMPLE.TEST ", "password":PASSWORD});
    for key in ["role", "owner_id", "id", "username"] {
        let mut elevated = registration.clone();
        elevated[key] = json!("admin");
        assert_eq!(
            request(app, "POST", "/api/v1/auth/register", None, elevated)
                .await
                .0,
            422
        );
    }
    let (a, b) = tokio::join!(
        request(
            app,
            "POST",
            "/api/v1/auth/register",
            None,
            registration.clone()
        ),
        request(
            app,
            "POST",
            "/api/v1/auth/register",
            None,
            registration.clone()
        )
    );
    assert!((a.0 == 201 && b.0 == 409) || (a.0 == 409 && b.0 == 201));
    let user = if a.0 == 201 { a.1 } else { b.1 };
    assert_eq!(user["role"], "user");
    assert_eq!(user["name"], "Тимофей");
    assert_eq!(user["email"], "member@example.test");
    assert!(user.get("password").is_none());
    assert!(user.get("password_hash").is_none());
    let user_id = Uuid::parse_str(user["id"].as_str().unwrap()).unwrap();
    let member = login(app, "member", PASSWORD).await;
    for (method, path, body) in [
        ("GET", "/api/v1/users", Value::Null),
        ("POST", "/api/v1/profiles", profile("denied")),
    ] {
        assert_eq!(request(app, method, path, Some(&member), body).await.0, 403);
    }
    assert_eq!(
        request(app, "GET", "/api/v1/auth/me", Some(&member), Value::Null)
            .await
            .1["user"]["id"],
        user["id"]
    );
    assert_eq!(
        request(
            app,
            "POST",
            "/api/v1/auth/login",
            None,
            json!({"username":"member","password":PASSWORD})
        )
        .await
        .0,
        422
    );
    let known = request(
        app,
        "POST",
        "/api/v1/auth/forgot-password",
        None,
        json!({"email":"member@example.test"}),
    )
    .await;
    let unknown = request(
        app,
        "POST",
        "/api/v1/auth/forgot-password",
        None,
        json!({"email":"missing@example.test"}),
    )
    .await;
    assert_eq!(known.0, 202);
    assert_eq!(known.0, unknown.0);
    assert_eq!(known.1, unknown.1);
    let token = delivered(mailbox).await;
    assert!(!known.1.to_string().contains(&token));
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM password_resets WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(stored, honeyforge_backend::auth::digest(&token));
    assert_eq!(
        request(
            app,
            "POST",
            "/api/v1/auth/reset-password",
            None,
            json!({"token":token,"password":"short"})
        )
        .await
        .0,
        422
    );
    assert_eq!(request(app,"POST","/api/v1/auth/reset-password",None,json!({"token":honeyforge_backend::auth::new_token(),"password":"changed-long-password"})).await.0,422);
    let reset = json!({"token":token,"password":"changed-long-password"});
    let (a, b) = tokio::join!(
        request(
            app,
            "POST",
            "/api/v1/auth/reset-password",
            None,
            reset.clone()
        ),
        request(
            app,
            "POST",
            "/api/v1/auth/reset-password",
            None,
            reset.clone()
        )
    );
    assert!(
        (a.0 == 204 && b.0 == 422) || (a.0 == 422 && b.0 == 204),
        "{} {}",
        a.0,
        b.0
    );
    assert_eq!(
        request(app, "POST", "/api/v1/auth/reset-password", None, reset)
            .await
            .0,
        422
    );
    assert_eq!(
        request(app, "GET", "/api/v1/auth/me", Some(&member), Value::Null)
            .await
            .0,
        401
    );
    assert_eq!(
        request(
            app,
            "POST",
            "/api/v1/auth/login",
            None,
            json!({"email":"member@example.test","password":PASSWORD})
        )
        .await
        .0,
        401
    );
    let member = login(app, "member", "changed-long-password").await;
    assert_eq!(
        request(
            app,
            "POST",
            "/api/v1/auth/forgot-password",
            None,
            json!({"email":"member@example.test"})
        )
        .await
        .0,
        202
    );
    let expired = delivered(mailbox).await;
    sqlx::query("UPDATE password_resets SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE user_id=$1").bind(user_id).execute(pool).await.unwrap();
    assert_eq!(
        request(
            app,
            "POST",
            "/api/v1/auth/reset-password",
            None,
            json!({"token":expired,"password":PASSWORD})
        )
        .await
        .0,
        422
    );
    let path = format!("/api/v1/users/{user_id}");
    assert_eq!(
        request(
            app,
            "PUT",
            &path,
            Some(admin),
            json!({"username":user["username"],"role":"user","is_active":false})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request(app, "GET", "/api/v1/auth/me", Some(&member), Value::Null)
            .await
            .0,
        401
    );
    assert_eq!(
        request(
            app,
            "POST",
            "/api/v1/auth/login",
            None,
            json!({"email":"member@example.test","password":"changed-long-password"})
        )
        .await
        .0,
        401
    );
    assert_eq!(
        request(
            app,
            "POST",
            "/api/v1/auth/forgot-password",
            None,
            json!({"email":"member@example.test"})
        )
        .await
        .0,
        202
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), mailbox.recv())
            .await
            .is_err()
    );
}

async fn fresh_bootstrap(pool: &sqlx::PgPool, url: &str, config: &Config) {
    // Independent schema inside the same disposable test container.
    sqlx::query("CREATE SCHEMA bootstrap_check")
        .execute(pool)
        .await
        .unwrap();
    let fresh = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO bootstrap_check")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap();
    storage::MIGRATOR.run(&fresh).await.unwrap();
    let state = AppState::new(config.clone(), fresh.clone()).await.unwrap();
    let app = router_with_state(state.clone());
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/register",
            None,
            json!({"name":"First user","email":"firstuser@example.test","password":PASSWORD})
        )
        .await
        .0,
        201
    );
    let (a, b) = tokio::join!(
        management::bootstrap(
            &fresh,
            state.auth().unwrap(),
            "firstadmin",
            "firstadmin@example.test",
            PASSWORD.into()
        ),
        management::bootstrap(
            &fresh,
            state.auth().unwrap(),
            "secondadmin",
            "secondadmin@example.test",
            PASSWORD.into()
        )
    );
    assert!(a.is_ok() != b.is_ok());
    let username = if a.is_ok() {
        "firstadmin"
    } else {
        "secondadmin"
    };
    let admin = login(&app, username, PASSWORD).await;
    assert_eq!(
        request(&app, "GET", "/api/v1/users", Some(&admin), Value::Null)
            .await
            .0,
        200
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users WHERE role='user'")
            .fetch_one(&fresh)
            .await
            .unwrap(),
        1
    );
    fresh.close().await;
}
