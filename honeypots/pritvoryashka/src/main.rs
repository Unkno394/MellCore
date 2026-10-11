use pritvoryashka::{Config, integration::honeyforge, ssh, telemetry::EventEmitter};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "pritvoryashka=info".into()),
        )
        .try_init()
        .map_err(|_| "failed to initialize tracing")?;
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "pritvoryashka.json".into());
    if std::env::args().len() > 2 {
        return Err("usage: pritvoryashka [config.json]".into());
    }
    let config = Config::load(path).await?;
    let emitter = EventEmitter::start(
        config.telemetry.clone(),
        config.trap_id,
        config.server_id,
        config.agent_id,
        config.bind.port(),
    )?;
    let health = tokio::spawn(honeyforge::serve_health(
        config.health_bind,
        emitter.clone(),
    ));
    tokio::select! {
        result = ssh::run(config, emitter) => result?,
        result = health => {
            result.map_err(|_| "health task failed")??;
            return Err("health listener stopped unexpectedly".into());
        }
    }
    Ok(())
}
