use super::{PASSWORD, login, request};
use honeyforge_backend::{
    api::{AppState, router_with_state},
    auth,
    config::Config,
    email_verification::EmailVerifications,
    management,
    password_reset::PasswordResets,
    storage,
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

struct Mailbox(tokio::sync::mpsc::Sender<(String, String)>);
impl honeyforge_backend::mail::TokenDelivery for Mailbox {
    fn send<'a>(
        &'a self,
        email: &'a str,
        token: &'a str,
    ) -> honeyforge_backend::mail::DeliveryFuture<'a> {
        Box::pin(async move {
            self.0.send((email.into(), token.into())).await.unwrap();
            Ok(())
        })
    }
}
async fn token(rx: &mut tokio::sync::mpsc::Receiver<(String, String)>) -> String {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap()
        .1
}

pub async fn run(parent: &sqlx::PgPool, url: &str, config: &Config) {
    sqlx::query("CREATE SCHEMA verification_check")
        .execute(parent)
        .await
        .unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .after_connect(|c, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO verification_check")
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap();
    let old = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(storage::MIGRATOR.iter().take(3).cloned().collect()),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    old.run(&pool).await.unwrap();
    let runtime = auth::AuthRuntime::new(2, 100).await.unwrap();
    let hash = runtime.hash(PASSWORD.into()).await.unwrap();
    let old_user = Uuid::new_v4();
    let old_jti = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,name,email,password_hash,role) VALUES ($1,'legacy','Legacy','legacy@example.test',$2,'user')").bind(old_user).bind(&hash).execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO access_tokens(id,user_id,expires_at) VALUES ($1,$2,now()+interval '1 hour')",
    )
    .bind(old_jti)
    .bind(old_user)
    .execute(&pool)
    .await
    .unwrap();
    storage::MIGRATOR.run(&pool).await.unwrap();
    let row: (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT password_hash,email_verified_at FROM users WHERE id=$1")
            .bind(old_user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (hash, None));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM access_tokens WHERE id=$1")
            .bind(old_jti)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    let base = AppState::new(config.clone(), pool.clone()).await.unwrap();
    let app_compatible = router_with_state(base.clone());
    let legacy = login(&app_compatible, "legacy", PASSWORD).await;
    let (sender, mut mailbox) = tokio::sync::mpsc::channel(16);
    let (reset_sender, mut reset_mailbox) = tokio::sync::mpsc::channel(16);
    let mut strict_config = config.clone();
    strict_config.require_email_verification = true;
    let mut state = base;
    state.config = Arc::new(strict_config);
    state.email_verifications = Some(EmailVerifications::start(
        pool.clone(),
        Arc::new(Mailbox(sender)),
    ));
    state.password_resets = Some(PasswordResets::start(
        pool.clone(),
        Arc::new(Mailbox(reset_sender)),
    ));
    management::bootstrap(
        &pool,
        state.auth().unwrap(),
        "verifyadmin",
        "verifyadmin@example.test",
        PASSWORD.into(),
    )
    .await
    .unwrap();
    let app = router_with_state(state);
    assert_eq!(
        request(&app, "GET", "/api/v1/auth/me", Some(&legacy), Value::Null)
            .await
            .0,
        403
    );
    let registered = request(
        &app,
        "POST",
        "/api/v1/auth/register",
        None,
        json!({"name":"Email owner","email":"verify@example.test","password":PASSWORD}),
    )
    .await;
    assert_eq!(registered.0, 201, "{}", registered.1);
    assert!(registered.1["email_verified_at"].is_null());
    let user = Uuid::parse_str(registered.1["id"].as_str().unwrap()).unwrap();
    let first = token(&mut mailbox).await;
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM email_verifications WHERE user_id=$1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, auth::digest(&first));
    let denied = request(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        json!({"email":"verify@example.test","password":PASSWORD}),
    )
    .await;
    assert_eq!(denied.0, 403);
    assert_eq!(denied.1["error"]["code"], "email_not_verified");
    let known = request(
        &app,
        "POST",
        "/api/v1/auth/resend-verification",
        None,
        json!({"email":"verify@example.test"}),
    )
    .await;
    let unknown = request(
        &app,
        "POST",
        "/api/v1/auth/resend-verification",
        None,
        json!({"email":"absent@example.test"}),
    )
    .await;
    assert_eq!(known.0, 202);
    assert_eq!(known.1, unknown.1);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), mailbox.recv())
            .await
            .is_err()
    );
    // Verification tokens cannot reset passwords, and reset tokens cannot verify mail.
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/reset-password",
            None,
            json!({"token":first,"password":"new-long-password"})
        )
        .await
        .0,
        422
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/forgot-password",
            None,
            json!({"email":"verify@example.test"})
        )
        .await
        .0,
        202
    );
    let reset = token(&mut reset_mailbox).await;
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/verify-email",
            None,
            json!({"token":reset})
        )
        .await
        .0,
        422
    );
    sqlx::query("UPDATE email_verifications SET created_at=now()-interval '2 days',expires_at=now()-interval '1 day' WHERE user_id=$1").bind(user).execute(&pool).await.unwrap();
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/verify-email",
            None,
            json!({"token":first})
        )
        .await
        .0,
        422
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/resend-verification",
            None,
            json!({"email":"verify@example.test"})
        )
        .await
        .0,
        202
    );
    let current = token(&mut mailbox).await;
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/verify-email",
            None,
            json!({"token":first})
        )
        .await
        .0,
        422
    );
    let (a, b) = tokio::join!(
        request(
            &app,
            "POST",
            "/api/v1/auth/verify-email",
            None,
            json!({"token":current})
        ),
        request(
            &app,
            "POST",
            "/api/v1/auth/verify-email",
            None,
            json!({"token":current})
        )
    );
    assert!((a.0 == 204 && b.0 == 422) || (a.0 == 422 && b.0 == 204));
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/verify-email",
            None,
            json!({"token":current})
        )
        .await
        .0,
        422
    );
    let verified = login(&app, "verify", PASSWORD).await;
    let me = request(&app, "GET", "/api/v1/auth/me", Some(&verified), Value::Null).await;
    assert!(me.1["user"]["email_verified_at"].is_string());
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/logout",
            Some(&verified),
            Value::Null
        )
        .await
        .0,
        204
    );
    assert_eq!(
        request(&app, "GET", "/api/v1/auth/me", Some(&verified), Value::Null)
            .await
            .0,
        401
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/resend-verification",
            None,
            json!({"email":"verify@example.test"})
        )
        .await
        .0,
        202
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), mailbox.recv())
            .await
            .is_err()
    );
    // Admin assigning a new email clears proof and invalidates old-email links/JWTs.
    let admin = login(&app_compatible, "verifyadmin", PASSWORD).await;
    let update = json!({"username":registered.1["username"],"role":"user","is_active":true,"email":"changed@example.test"});
    let updated = request(
        &app_compatible,
        "PUT",
        &format!("/api/v1/users/{user}"),
        Some(&admin),
        update,
    )
    .await;
    assert_eq!(updated.0, 200);
    assert!(updated.1["email_verified_at"].is_null());
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/login",
            None,
            json!({"email":"changed@example.test","password":PASSWORD})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/auth/verify-email",
            None,
            json!({"token":current})
        )
        .await
        .0,
        422
    );
    let without_smtp = request(
        &app_compatible,
        "POST",
        "/api/v1/auth/resend-verification",
        None,
        json!({"email":"missing@example.test"}),
    )
    .await;
    assert_eq!(without_smtp.0, 503);
    assert_eq!(without_smtp.1["error"]["code"], "mail_unavailable");
    pool.close().await;
    println!(
        "Verified additive email migration, registration mail, opt-in verification policy, resend cooldown, expiry, one-time concurrent consumption, token purpose separation, email-change invalidation and logout."
    );
}
