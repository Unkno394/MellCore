use crate::{
    config::Config,
    telemetry::{ConnectionEvent, EventSink},
};
use russh::{
    MethodKind, MethodSet,
    keys::{Algorithm, PrivateKey, load_secret_key},
    server::{self, Auth},
};
use std::{future::Future, io, path::Path, sync::Arc, time::Duration};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    net::TcpListener,
    task::JoinSet,
    time::timeout,
};

const MAX_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

fn advertised_auth_methods() -> MethodSet {
    [MethodKind::PublicKey, MethodKind::Password]
        .as_slice()
        .into()
}

fn reject_auth() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(advertised_auth_methods()),
        partial_success: false,
    }
}

/// Serve a caller-owned listener; stop when `shutdown` resolves.
/// Each connection performs SSH identification and key exchange, then rejects
/// authentication. There is no shell, command execution, or credential storage.
pub async fn serve(
    listener: TcpListener,
    config: Config,
    sink: Arc<dyn EventSink>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    config.validate()?;
    let host_key = load_or_create_host_key(config.host_key_path.as_deref()).await?;
    let ssh_config = Arc::new(server::Config {
        server_id: russh::SshId::Standard(config.banner.clone().into()),
        methods: advertised_auth_methods(),
        keys: vec![host_key],
        max_auth_attempts: 6,
        auth_rejection_time: Duration::from_millis(750),
        inactivity_timeout: Some(HANDSHAKE_TIMEOUT),
        maximum_packet_size: 32 * 1024,
        window_size: 256 * 1024,
        ..server::Config::default()
    });
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    if !error.is_cancelled() {
                        tracing::error!(%error, "SSH connection task failed");
                    }
                }
            }
            accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                let (stream, client) = accepted?;
                let event = ConnectionEvent::new(config.trap_id, client, stream.local_addr()?);
                let ssh_config = Arc::clone(&ssh_config);
                let sink = Arc::clone(&sink);
                connections.spawn(async move {
                    if let Err(error) = sink.emit(&event) {
                        tracing::error!(%error, %client, "failed to emit connection event");
                    }
                    let result = timeout(HANDSHAKE_TIMEOUT, async move {
                        let session = server::run_stream(ssh_config, stream, LowHandler).await?;
                        session.await
                    }).await;
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::debug!(%error, %client, "SSH handshake failed");
                        }
                        Err(_) => {
                            tracing::debug!(%client, "SSH handshake timed out");
                        }
                    }
                });
            }
        }
    }

    // Stop active SSH sessions promptly during service shutdown.
    connections.abort_all();
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            tracing::error!(%error, "SSH connection task failed during shutdown");
        }
    }
    Ok(())
}

async fn load_or_create_host_key(path: Option<&Path>) -> io::Result<PrivateKey> {
    let Some(path) = path else {
        return generate_host_key();
    };

    if path.exists() {
        return load_secret_key(path, None).map_err(io::Error::other);
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).await?;
    }
    let key = generate_host_key()?;
    let encoded = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(io::Error::other)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    match options.open(path).await {
        Ok(mut file) => {
            if let Err(error) = async {
                file.write_all(encoded.as_bytes()).await?;
                file.sync_all().await
            }
            .await
            {
                drop(file);
                let _ = fs::remove_file(path).await;
                return Err(error);
            }
            Ok(key)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            load_secret_key(path, None).map_err(io::Error::other)
        }
        Err(error) => Err(error),
    }
}

fn generate_host_key() -> io::Result<PrivateKey> {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).map_err(io::Error::other)
}

struct LowHandler;

impl server::Handler for LowHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(reject_auth())
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        // Deliberately do not retain or log supplied credentials.
        Ok(reject_auth())
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(reject_auth())
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(reject_auth())
    }
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn low_advertises_only_password_and_public_key() {
        let methods = advertised_auth_methods();
        assert!(methods.contains(&MethodKind::Password));
        assert!(methods.contains(&MethodKind::PublicKey));
        assert!(!methods.contains(&MethodKind::HostBased));
        assert!(!methods.contains(&MethodKind::KeyboardInteractive));
    }

    #[test]
    fn rejected_auth_keeps_supported_methods_available() {
        match reject_auth() {
            Auth::Reject {
                proceed_with_methods: Some(methods),
                partial_success: false,
            } => {
                assert!(methods.contains(&MethodKind::Password));
                assert!(methods.contains(&MethodKind::PublicKey));
                assert!(!methods.contains(&MethodKind::HostBased));
                assert!(!methods.contains(&MethodKind::KeyboardInteractive));
            }
            _ => panic!("rejected auth must preserve the advertised methods"),
        }
    }
}
