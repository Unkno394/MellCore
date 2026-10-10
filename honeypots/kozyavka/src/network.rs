use crate::{
    config::Config,
    telemetry::{ConnectionEvent, EventSink},
};
use std::{future::Future, io, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinSet, time::timeout};

const MAX_CONNECTIONS: usize = 128;
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);

/// Serve a caller-owned listener; stop when `shutdown` resolves.
/// The event records the actual local socket port (including ephemeral ports).
pub async fn serve(
    listener: TcpListener,
    config: Config,
    sink: Arc<dyn EventSink>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    config.validate()?;
    let banner = Arc::new(format!("{}\r\n", config.banner).into_bytes());
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::error!(%error, "connection task failed");
                }
            }
            accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                let (mut stream, client) = accepted?;
                // Capture the timestamp at accept, before scheduling the task.
                let event = ConnectionEvent::new(config.trap_id, client, stream.local_addr()?);
                let sink = Arc::clone(&sink);
                let banner = Arc::clone(&banner);
                connections.spawn(async move {
                    if let Err(error) = sink.emit(&event) {
                        tracing::error!(%error, %client, "failed to emit connection event");
                    }
                    match timeout(WRITE_TIMEOUT, async {
                        stream.write_all(&banner).await?;
                        stream.shutdown().await
                    }).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => tracing::debug!(%error, %client, "banner delivery failed"),
                        Err(_) => tracing::debug!(%client, "banner delivery timed out"),
                    }
                    // Drop the stream: no authentication, command parsing, or shell.
                });
            }
        }
    }
    // Finish already accepted connections, including telemetry. Each network
    // write is bounded by WRITE_TIMEOUT, so an idle peer cannot stall shutdown.
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            tracing::error!(%error, "connection task failed during shutdown");
        }
    }
    Ok(())
}
