use honeyforge_low::{config::Config, network, telemetry::StdoutSink};
use std::{io, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(io::stderr)
        .with_ansi(false)
        .init();

    let mut args = std::env::args_os().skip(1);
    let config = match args.next() {
        None => Config::default(),
        Some(arg) if arg == "--config" => {
            let path = args.next().ok_or("--config requires a JSON file path")?;
            if args.next().is_some() {
                return Err("unexpected arguments; use --config <path>".into());
            }
            Config::from_path(PathBuf::from(path))?
        }
        Some(arg) if arg == "--help" || arg == "-h" => {
            eprintln!(
                "Usage: honeyforge-low [--config <path>]\nDefault: 127.0.0.1:2222; JSON Lines on stdout, diagnostics on stderr."
            );
            return Ok(());
        }
        Some(_) => return Err("unknown argument; use --config <path> or --help".into()),
    };
    config.validate()?;
    let listener = TcpListener::bind((config.bind_address, config.port)).await?;
    tracing::info!(address = %listener.local_addr()?, trap_id = %config.trap_id, "honeypot listening");
    // Register handlers before serving so registration errors fail at startup.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let shutdown = async move {
        #[cfg(unix)]
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result { tracing::error!(%error, "signal handler failed"); }
            }
            _ = terminate.recv() => {}
        }
        #[cfg(not(unix))]
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "signal handler failed");
        }
    };
    network::serve(listener, config, Arc::new(StdoutSink), shutdown).await?;
    tracing::info!("honeypot stopped");
    Ok(())
}
