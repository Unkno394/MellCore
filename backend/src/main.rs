use honeyforge_backend::{
    api,
    config::{Config, IntegrationMode},
    storage,
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load local development settings when present. systemd-provided variables
    // take precedence; production still supplies them through EnvironmentFile.
    for path in ["backend/.env", ".env", "/etc/honeyforge/backend.env"] {
        if dotenvy::from_path(path).is_ok() {
            break;
        }
    }
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_new(&config.log_filter)?)
        .try_init()
        .map_err(|_| "failed to initialize tracing")?;
    if config.integration_mode == IntegrationMode::Real {
        return Err("integration_not_configured: real infrastructure is not connected".into());
    }
    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    if std::env::args().len() > 2
        || !matches!(
            command.as_str(),
            "serve" | "migrate" | "bootstrap-admin" | "attach-email"
        )
    {
        return Err(
            "usage: honeyforge-backend [serve|migrate|bootstrap-admin|attach-email]".into(),
        );
    }
    let database = if config.database_url.is_some() {
        Some(storage::connect(&config).await?)
    } else {
        None
    };
    if command == "migrate" {
        let pool = database.ok_or("DATABASE_URL is required")?;
        storage::MIGRATOR.run(&pool).await.map_err(|error| {
            tracing::error!(%error, "PostgreSQL migration failed");
            "migration failed; inspect schema and permissions"
        })?;
        tracing::info!("PostgreSQL migrations applied");
        pool.close().await;
        return Ok(());
    }
    if let Some(pool) = database.as_ref() {
        storage::check_schema(pool).await?;
    }
    if command == "attach-email" {
        let pool = database.ok_or("DATABASE_URL is required")?;
        let username =
            std::env::var("LEGACY_USERNAME").map_err(|_| "LEGACY_USERNAME is required")?;
        let email = std::env::var("LEGACY_EMAIL").map_err(|_| "LEGACY_EMAIL is required")?;
        honeyforge_backend::management::attach_email(&pool, &username, &email)
            .await
            .map_err(|e| e.message)?;
        tracing::info!("legacy account email attached");
        pool.close().await;
        return Ok(());
    }
    if command == "bootstrap-admin" {
        let pool = database.ok_or("DATABASE_URL is required")?;
        let username =
            std::env::var("BOOTSTRAP_USERNAME").map_err(|_| "BOOTSTRAP_USERNAME is required")?;
        let email = std::env::var("BOOTSTRAP_EMAIL").map_err(|_| "BOOTSTRAP_EMAIL is required")?;
        let password =
            std::env::var("BOOTSTRAP_PASSWORD").map_err(|_| "BOOTSTRAP_PASSWORD is required")?;
        let runtime = honeyforge_backend::auth::AuthRuntime::new(
            config.auth_max_concurrency,
            config.login_per_minute,
        )
        .await
        .map_err(|e| e.message)?;
        let user_id =
            honeyforge_backend::management::bootstrap(&pool, &runtime, &username, &email, password)
                .await
                .map_err(|e| e.message)?;
        tracing::info!(%user_id, "initial administrator created");
        pool.close().await;
        return Ok(());
    }
    let app = if let Some(pool) = database.clone() {
        let state = api::AppState::new(config.clone(), pool)
            .await
            .map_err(|e| e.message)?;
        tokio::spawn(api::trap_actions::reconcile_shared_jobs(state.clone()));
        api::router_with_state(state)
    } else {
        api::router(&config)
    };
    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(address = %listener.local_addr()?, management_database = database.is_some(), telemetry_ingestion = config.telemetry_ingest_token.is_some(), "HTTP listener started");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    if let Some(pool) = database {
        pool.close().await;
    }
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to register Ctrl-C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to register SIGTERM handler"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown requested");
}
