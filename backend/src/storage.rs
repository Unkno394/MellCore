use std::{str::FromStr, time::Duration};

use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};

use crate::config::Config;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn check_schema(pool: &PgPool) -> Result<(), &'static str> {
    let applied: Vec<(i64, Vec<u8>, bool)> =
        sqlx::query_as("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await
            .map_err(|_| "schema is not initialized; run the migrate command")?;
    let expected: Vec<_> = MIGRATOR.iter().collect();
    if applied.len() != expected.len()
        || applied
            .iter()
            .zip(expected)
            .any(|((version, checksum, success), migration)| {
                !success
                    || *version != migration.version
                    || checksum.as_slice() != migration.checksum.as_ref()
            })
    {
        return Err(
            "database schema differs from this application; review migrations before startup",
        );
    }
    Ok(())
}

/// Parse credentials without ever returning the original URL in an error/log.
pub async fn connect(config: &Config) -> Result<PgPool, &'static str> {
    let secret = config
        .database_url
        .as_ref()
        .ok_or("DATABASE_URL is required")?;
    let url = url::Url::parse(secret.expose()).map_err(|_| "invalid DATABASE_URL")?;
    if !matches!(url.scheme(), "postgres" | "postgresql") || url.host_str().is_none() {
        return Err("DATABASE_URL must be an explicit PostgreSQL URL");
    }
    // Limit query options so a host/hostaddr override cannot bypass the local
    // exception. Remote certificates are always verified, irrespective of DSN.
    if url
        .query_pairs()
        .any(|(key, _)| !matches!(key.as_ref(), "sslmode" | "sslrootcert"))
    {
        return Err("unsupported DATABASE_URL query option");
    }
    let host = url.host_str().unwrap_or_default();
    let local = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if config.database_allow_insecure_local && !local {
        return Err("insecure database connections require a loopback host");
    }
    let options = PgConnectOptions::from_str(secret.expose())
        .map_err(|_| "invalid DATABASE_URL")?
        .ssl_mode(if config.database_allow_insecure_local {
            PgSslMode::Disable
        } else {
            PgSslMode::VerifyFull
        })
        .disable_statement_logging();
    PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout = '5s'")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SET lock_timeout = '3s'")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .map_err(|_| "PostgreSQL connection failed; check address, credentials and TLS")
}
