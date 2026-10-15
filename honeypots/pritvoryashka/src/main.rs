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
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("--check-windows-parser") {
        if args.next().is_some() {
            return Err("usage: pritvoryashka --check-windows-parser".into());
        }
        pritvoryashka::shell::windows::check_parser().map_err(std::io::Error::other)?;
        println!("Windows PowerShell parser is available");
        return Ok(());
    }
    let (path, check_config_only) = match first.as_deref() {
        Some("--check-config") => {
            let Some(path) = args.next() else {
                return Err("usage: pritvoryashka [--check-config] [config.json]".into());
            };
            (path, true)
        }
        Some(path) => (path.to_owned(), false),
        None => ("pritvoryashka.json".into(), false),
    };
    if args.next().is_some() {
        return Err("usage: pritvoryashka [--check-config] [config.json]".into());
    }
    let config = Config::load(path).await?;
    if check_config_only {
        println!("configuration is valid");
        return Ok(());
    }
    let emitter = EventEmitter::start(
        config.telemetry.clone(),
        config.trap_id,
        config.server_id,
        config.agent_id,
        config.ssh_public_port.unwrap_or(config.bind.port()),
    )?;
    let health = tokio::spawn(honeyforge::serve_health(
        config.health_bind,
        emitter.clone(),
    ));
    tokio::select! {
        result = ssh::run(config.clone(), emitter.clone()) => result?,
        result = pritvoryashka::protocols::run(config.clone(), emitter.clone()) => result?,
        result = health => {
            result.map_err(|_| "health task failed")??;
            return Err("health listener stopped unexpectedly".into());
        }
    }
    Ok(())
}
