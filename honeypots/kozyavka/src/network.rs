use crate::{
    config::{Config, LowAuthMode},
    telemetry::{ConnectionEvent, EventSink},
};
use russh::{
    Channel, ChannelId, MethodKind, MethodSet, Preferred, Pty, cipher, kex,
    keys::{Algorithm, PrivateKey, load_secret_key},
    mac,
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use std::{borrow::Cow, future::Future, io, path::Path, sync::Arc, time::Duration};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    net::TcpListener,
    task::JoinSet,
    time::timeout,
};

const MAX_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

fn openssh_89_preferences() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(&[
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::DH_GEX_SHA256,
            kex::DH_G14_SHA256,
            kex::EXTENSION_SUPPORT_AS_SERVER,
        ]),
        key: Cow::Borrowed(&[Algorithm::Ed25519]),
        cipher: Cow::Borrowed(&[
            cipher::CHACHA20_POLY1305,
            cipher::AES_128_CTR,
            cipher::AES_256_CTR,
            cipher::AES_128_GCM,
            cipher::AES_256_GCM,
        ]),
        mac: Cow::Borrowed(&[
            mac::HMAC_SHA256_ETM,
            mac::HMAC_SHA512_ETM,
            mac::HMAC_SHA256,
            mac::HMAC_SHA512,
        ]),
        ..Preferred::default()
    }
}

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
/// Each connection uses the configured authentication policy and an isolated
/// in-memory shell. No host command is ever executed.
pub async fn serve(
    listener: TcpListener,
    config: Config,
    sink: Arc<dyn EventSink>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    config.validate()?;
    let host_key = load_or_create_host_key(config.host_key_path.as_deref()).await?;
    let preferred = if config.banner.starts_with("SSH-2.0-OpenSSH_8.9p1") {
        openssh_89_preferences()
    } else {
        Preferred::default()
    };
    let ssh_config = Arc::new(server::Config {
        server_id: russh::SshId::Standard(config.banner.clone().into()),
        methods: if config.auth_mode == LowAuthMode::Passwordless {
            [
                MethodKind::None,
                MethodKind::PublicKey,
                MethodKind::Password,
            ]
            .as_slice()
            .into()
        } else {
            advertised_auth_methods()
        },
        keys: vec![host_key],
        preferred,
        max_auth_attempts: 6,
        auth_rejection_time: Duration::from_millis(750),
        inactivity_timeout: Some(if config.auth_mode == LowAuthMode::CaptureCredentials {
            HANDSHAKE_TIMEOUT
        } else {
            Duration::from_secs(600)
        }),
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
                let policy = config.auth_mode;
                let credentials = config.credentials.clone();
                connections.spawn(async move {
                    if let Err(error) = sink.emit(&event) {
                        tracing::error!(%error, %client, "failed to emit connection event");
                    }
                    let result = timeout(if policy == LowAuthMode::CaptureCredentials { HANDSHAKE_TIMEOUT } else { Duration::from_secs(600) }, async move {
                        let handler = LowHandler { policy, credentials, sink, event, user: None, input: String::new(), shell_started: false };
                        let session = server::run_stream(ssh_config, stream, handler).await?;
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

struct LowHandler {
    policy: LowAuthMode,
    credentials: Vec<crate::config::LowCredential>,
    sink: Arc<dyn EventSink>,
    event: ConnectionEvent,
    user: Option<String>,
    input: String,
    shell_started: bool,
}

impl LowHandler {
    fn accepts(&self, user: &str, password: &str) -> bool {
        match self.policy {
            LowAuthMode::CaptureCredentials => false,
            LowAuthMode::Configured => self
                .credentials
                .iter()
                .any(|pair| pair.username == user && pair.password == password),
            LowAuthMode::AnyPassword | LowAuthMode::Passwordless => true,
        }
    }

    fn record(&self, event: &ConnectionEvent) {
        if let Err(error) = self.sink.emit(event) {
            tracing::error!(%error, "failed to emit Low SSH event");
        }
    }

    fn response(&self, line: &str) -> String {
        let command = line.trim();
        match command {
            "" => String::new(),
            "whoami" => self.user.clone().unwrap_or_else(|| "root".into()),
            "hostname" => "srv-app-01".into(),
            "pwd" => format!("/home/{}", self.user.as_deref().unwrap_or("root")),
            "id" => format!(
                "uid=1000({0}) gid=1000({0}) groups=1000({0})",
                self.user.as_deref().unwrap_or("root")
            ),
            "ls" | "ls -la" => "README.txt".into(),
            "cat README.txt" => "Welcome to srv-app-01".into(),
            _ if command.starts_with("echo ") => {
                command[5..].trim_matches('"').trim_matches('\'').into()
            }
            _ => format!(
                "bash: {}: command not found",
                command.split_whitespace().next().unwrap_or("")
            ),
        }
    }

    fn prompt(&self) -> String {
        format!("{}@srv-app-01:~$ ", self.user.as_deref().unwrap_or("root"))
    }

    fn record_command(&self, command: &str) {
        let mut event = self.event.activity("command.executed");
        event.username = self.user.clone();
        event.command = Some(command.chars().take(4096).collect());
        self.record(&event);
    }
}

impl server::Handler for LowHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        let accepted = self.policy == LowAuthMode::Passwordless;
        let mut event = self.event.activity("auth.attempted");
        event.username = Some(user.to_owned());
        event.accepted = Some(accepted);
        self.record(&event);
        if accepted {
            self.user = Some(user.to_owned());
            Ok(Auth::Accept)
        } else {
            Ok(reject_auth())
        }
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let accepted = self.accepts(user, password);
        let mut event = self.event.activity("auth.attempted");
        event.username = Some(user.chars().take(32).collect());
        event.password = Some(password.chars().take(128).collect());
        event.accepted = Some(accepted);
        self.record(&event);
        if accepted {
            self.user = Some(user.to_owned());
            Ok(Auth::Accept)
        } else {
            Ok(reject_auth())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.user.is_some() {
            reply.accept().await;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shell_started = true;
        let mut event = self.event.activity("session.started");
        event.username = self.user.clone();
        self.record(&event);
        session.channel_success(channel)?;
        session.data(
            channel,
            format!("Ubuntu 22.04.4 LTS srv-app-01\r\n\r\n{}", self.prompt()).into_bytes(),
        )?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(&data[..data.len().min(4096)]);
        self.record_command(&command);
        session.channel_success(channel)?;
        session.data(
            channel,
            format!("{}\n", self.response(&command)).into_bytes(),
        )?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.shell_started {
            return Ok(());
        }
        for &byte in data {
            match byte {
                b'\r' | b'\n' => {
                    session.data(channel, b"\r\n".to_vec())?;
                    let line = std::mem::take(&mut self.input);
                    if line.trim() == "exit" || line.trim() == "logout" {
                        let mut event = self.event.activity("session.ended");
                        event.username = self.user.clone();
                        self.record(&event);
                        session.close(channel)?;
                        return Ok(());
                    }
                    self.record_command(&line);
                    let output = self.response(&line);
                    if !output.is_empty() {
                        session.data(channel, format!("{output}\r\n").into_bytes())?;
                    }
                    session.data(channel, self.prompt().into_bytes())?;
                }
                8 | 127 => {
                    self.input.pop();
                }
                32..=126 if self.input.len() < 4096 => {
                    self.input.push(byte as char);
                    session.data(channel, vec![byte])?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let mut event = self.event.activity("auth.attempted");
        event.username = Some(user.chars().take(32).collect());
        event.accepted = Some(false);
        self.record(&event);
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
    use uuid::Uuid;

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

    #[test]
    fn low_auth_policies_match_configured_credentials() {
        let event = ConnectionEvent::new(
            Uuid::new_v4(),
            "127.0.0.1:30000".parse().unwrap(),
            "127.0.0.1:2222".parse().unwrap(),
        );
        let mut handler = LowHandler {
            policy: LowAuthMode::CaptureCredentials,
            credentials: vec![crate::config::LowCredential {
                username: "admin".into(),
                password: "secret".into(),
            }],
            sink: Arc::new(crate::telemetry::StdoutSink),
            event,
            user: None,
            input: String::new(),
            shell_started: false,
        };
        assert!(!handler.accepts("admin", "secret"));
        handler.policy = LowAuthMode::Configured;
        assert!(handler.accepts("admin", "secret"));
        assert!(!handler.accepts("admin", "wrong"));
        assert!(!handler.accepts("other", "secret"));
        handler.policy = LowAuthMode::AnyPassword;
        assert!(handler.accepts("other", "anything"));
        handler.policy = LowAuthMode::Passwordless;
        assert!(handler.accepts("other", ""));
    }
}

#[cfg(test)]
mod ssh_algorithm_tests {
    use super::*;

    #[test]
    fn openssh_89_profile_omits_mlkem_and_keeps_curve25519() {
        let preferred = openssh_89_preferences();
        let names: Vec<_> = preferred.kex.iter().map(AsRef::as_ref).collect();
        assert!(!names.contains(&"mlkem768x25519-sha256"));
        assert!(names.contains(&"curve25519-sha256"));
        assert!(names.contains(&"diffie-hellman-group14-sha256"));
    }
}
