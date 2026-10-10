use honeyforge_backend::{
    auth::{self, AuthRuntime, Claims, Jwt},
    config::Config,
    management::{self, ProfileInput},
};
use serde_json::json;

#[tokio::test]
async fn argon2_uses_unique_salts_and_rejects_wrong_passwords() {
    let auth = AuthRuntime::new(1, 10).await.unwrap();
    let first = auth.hash("long-enough-password".into()).await.unwrap();
    let second = auth.hash("long-enough-password".into()).await.unwrap();
    assert!(first.starts_with("$argon2id$"));
    assert_ne!(first, second);
    assert!(
        auth.verify("long-enough-password".into(), first.clone())
            .await
            .unwrap()
    );
    assert!(!auth.verify("wrong-password".into(), first).await.unwrap());
}

#[tokio::test]
async fn login_limiter_has_bounded_state_and_rejects_excess_attempts() {
    let auth = AuthRuntime::new(1, 2).await.unwrap();
    auth.allow_login().await.unwrap();
    auth.allow_login().await.unwrap();
    assert_eq!(auth.allow_login().await.unwrap_err().status, 429);
}

#[test]
fn secrets_are_redacted_and_remote_insecure_origin_settings_rejected() {
    let cfg = Config::from_lookup(|key| {
        Ok((key == "DATABASE_URL").then(|| "postgres://user:very-secret@localhost/db".into()))
    })
    .unwrap();
    assert!(!format!("{cfg:?}").contains("very-secret"));
    assert!(
        Config::from_lookup(|key| Ok(match key {
            "API_BIND" => Some("0.0.0.0:8080".into()),
            "APP_ORIGIN" => Some("http://localhost:8080".into()),
            _ => None,
        }))
        .is_err()
    );
}

#[test]
fn username_password_and_profile_validation_reject_unsafe_inputs() {
    assert_eq!(management::username("  ADMIN.User ").unwrap(), "admin.user");
    assert!(management::username("admin'; DROP TABLE users;").is_err());
    assert!(management::password("short").is_err());
    assert!(management::password(&"x".repeat(257)).is_err());
    let input: ProfileInput = serde_json::from_value(json!({"name":"SSH", "level":"medium", "honeypot_type":"cowrie", "service_type":"ssh", "config":{"nested":[{"private_key":"sensitive"}]}})).unwrap();
    let error = input.validate().unwrap_err();
    assert!(!error.message.contains("sensitive"));
    assert_eq!(error.status, 422);
}

#[test]
fn jwt_rejects_wrong_keys_expiry_algorithms_and_claims() {
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use uuid::Uuid;
    let secret = "test-only-signing-key-at-least-32-bytes";
    let jwt = Jwt::new(secret).unwrap();
    let user = Uuid::new_v4();
    let token = jwt
        .issue(user, Uuid::new_v4(), Utc::now().timestamp() + 900)
        .unwrap();
    assert_eq!(jwt.verify(&token).unwrap().sub, user);
    assert!(
        Jwt::new("other-signing-key-at-least-32-bytes")
            .unwrap()
            .verify(&token)
            .is_err()
    );
    assert!(jwt.verify("eyJhbGciOiJub25lIn0.e30.").is_err());
    for (alg, iss, aud, iat, exp) in [
        (Algorithm::HS384, "honeyforge", "honeyforge-api", -10, 900),
        (Algorithm::HS256, "other", "honeyforge-api", -10, 900),
        (Algorithm::HS256, "honeyforge", "other", -10, 900),
        (Algorithm::HS256, "honeyforge", "honeyforge-api", -100, -1),
        (Algorithm::HS256, "honeyforge", "honeyforge-api", 10, 900),
    ] {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: user,
            jti: Uuid::new_v4(),
            iat: now + iat,
            exp: now + exp,
            iss: iss.into(),
            aud: aud.into(),
        };
        let token = encode(
            &Header::new(alg),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        assert!(jwt.verify(&token).is_err());
    }
    assert_eq!(auth::new_token().len(), 64);
    assert_ne!(auth::new_token(), auth::new_token());
}

#[test]
fn public_identity_validation_and_secret_configuration() {
    assert_eq!(
        management::email(" User@Example.com ").unwrap(),
        "user@example.com"
    );
    for bad in [
        "not-mail",
        "User <user@example.com>",
        "a\r\n@example.com",
        "юзер@example.com",
    ] {
        assert!(management::email(bad).is_err(), "{bad}");
    }
    assert_eq!(management::display_name("  Тимофей  ").unwrap(), "Тимофей");
    assert!(management::display_name(" ").is_err());
    assert!(management::display_name("name\nadmin").is_err());
    for (key, value) in [
        ("JWT_SECRET", "short"),
        ("JWT_TTL_SECONDS", "3601"),
        ("SMTP_HOST", "smtp.example.com"),
    ] {
        assert!(Config::from_lookup(|k| Ok((k == key).then(|| value.into()))).is_err());
    }
    let config = Config::from_lookup(|k| {
        Ok((k == "JWT_SECRET").then(|| "never-log-this-signing-key-32-bytes".into()))
    })
    .unwrap();
    assert!(!format!("{config:?}").contains("never-log"));
}
