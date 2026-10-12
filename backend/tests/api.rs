use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use honeyforge_backend::{api::router, config::Config};
use serde_json::Value;
use tower::ServiceExt;

fn config(docs: bool) -> Config {
    Config::from_lookup(|key| Ok((key == "DOCS_ENABLED").then(|| docs.to_string()))).unwrap()
}

#[tokio::test]
async fn liveness_does_not_claim_storage_readiness() {
    let app = router(&config(false));
    let live = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::OK);
    let ready = app
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let id = ready.headers()["x-request-id"].to_str().unwrap().to_owned();
    let body: Value =
        serde_json::from_slice(&to_bytes(ready.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "storage_not_initialized");
    assert_eq!(body["error"]["request_id"], id);
}

#[tokio::test]
async fn documentation_is_disabled_by_default() {
    let app = router(&config(false));
    for uri in ["/docs", "/docs/", "/openapi.json"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn server_bootstrap_requires_user_authentication() {
    let response = router(&config(false))
        .oneshot(Request::builder().method("POST").uri("/api/v1/servers/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from("{}")).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn openapi_contains_management_and_telemetry_contracts() {
    let response = router(&config(true))
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await.unwrap()).unwrap();
    assert!(body["components"]["schemas"]["TelemetryBatch"].is_object());
    assert!(body["components"]["schemas"]["AttackEvent"].is_object());
    assert!(body["paths"]["/health/live"]["get"].is_object());
    assert!(body["paths"]["/internal/v1/telemetry/batches"]["post"].is_object());
    assert!(body["paths"]["/api/v1/auth/refresh"]["post"].is_object());
    assert_eq!(
        body["paths"]["/internal/v1/telemetry/batches"]["post"]["security"],
        serde_json::json!([{"telemetry_bearer":[]}])
    );
    assert_eq!(
        body["components"]["securitySchemes"]["bearer"]["scheme"],
        "bearer"
    );
    assert!(body["components"]["securitySchemes"]["session"].is_null());
    for route in [
        "register",
        "forgot-password",
        "reset-password",
        "verify-email",
        "resend-verification",
        "change-email",
        "change-password",
    ] {
        assert!(body["paths"][format!("/api/v1/auth/{route}")]["post"].is_object());
    }
    assert!(body["components"]["schemas"]["RegisterRequest"]["properties"]["role"].is_null());
    for route in [
        "/api/v1/servers",
        "/api/v1/servers/{server_id}",
        "/api/v1/servers/{server_id}/ports",
        "/api/v1/traps",
        "/api/v1/traps/{trap_id}",
        "/api/v1/traps/{trap_id}/runtime-config",
        "/api/v1/traps/{trap_id}/events",
    ] {
        for operation in body["paths"][route].as_object().unwrap().values() {
            assert_eq!(operation["security"], serde_json::json!([{"bearer":[]}]));
        }
    }
    for name in [
        "ServerInput",
        "TrapInput",
        "CreateTrap",
        "UpdateTrap",
        "UpdateServer",
    ] {
        let schema = &body["components"]["schemas"][name];
        assert_eq!(schema["additionalProperties"], false);
        for field in [
            "user_id",
            "owner_id",
            "actual_state",
            "status",
            "private_key",
            "password",
        ] {
            assert!(schema["properties"][field].is_null());
        }
    }
    assert_eq!(
        body["components"]["schemas"]["KozyavkaRuntimeConfig"]["properties"]["port"]["minimum"],
        1
    );
    let published: Value = serde_json::from_str(include_str!("../docs/openapi.json")).unwrap();
    assert_eq!(
        body, published,
        "Regenerate docs/openapi.json using the export_openapi example"
    );
}

#[tokio::test]
async fn swagger_assets_are_served_locally() {
    let app = router(&config(true));
    for uri in [
        "/docs/",
        "/docs/swagger-ui.css",
        "/docs/swagger-ui-bundle.js",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
    }
}

#[tokio::test]
async fn oversized_requests_use_the_standard_error_envelope() {
    let cfg = config(false);
    let response = router(&cfg)
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header("content-length", cfg.http_max_body_bytes + 1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "payload_too_large");
}

#[tokio::test]
async fn unknown_routes_do_not_echo_paths_or_trust_incoming_request_ids() {
    let response = router(&config(false))
        .oneshot(
            Request::builder()
                .uri("/unknown/secret?token=secret")
                .header("x-request-id", "attacker-controlled")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_ne!(response.headers()["x-request-id"], "attacker-controlled");
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("secret"));
}

#[tokio::test]
async fn unsupported_methods_have_a_json_error() {
    let response = router(&config(false))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "method_not_allowed");
}

#[tokio::test]
async fn telemetry_is_never_acknowledged_before_storage_exists() {
    let body = include_bytes!("../docs/examples/telemetry-v1.json");
    let response = router(&config(false))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/v1/telemetry/batches")
                .header("content-type", "application/json")
                .body(Body::from(&body[..]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn browser_cors_allows_only_configured_frontend_and_preserves_error_headers() {
    let cfg = Config::from_lookup(|key| {
        Ok((key == "FRONTEND_URL").then(|| "http://localhost:5173".into()))
    })
    .unwrap();
    let app = router(&cfg);
    for origin in ["http://localhost:5173", "https://untrusted.example"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/v1/auth/login")
                    .header("origin", origin)
                    .header("access-control-request-method", "POST")
                    .header(
                        "access-control-request-headers",
                        "authorization,content-type",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        if origin == "http://localhost:5173" {
            assert!(response.status().is_success());
            assert_eq!(response.headers()["access-control-allow-origin"], origin);
            assert!(
                response.headers()["access-control-allow-headers"]
                    .to_str()
                    .unwrap()
                    .contains("authorization")
            );
            assert!(
                response
                    .headers()
                    .get("access-control-allow-credentials")
                    .is_none()
            );
        } else {
            assert!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .is_none()
            );
        }
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("origin", "http://localhost:5173")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "http://localhost:5173"
    );
    assert!(
        response.headers()["access-control-expose-headers"]
            .to_str()
            .unwrap()
            .contains("x-request-id")
    );
    assert!(response.headers().contains_key("x-request-id"));
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "unauthorized");
}
