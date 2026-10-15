use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use hf_core::SHARED_SSH_IDENTIFICATION;
use russh::{
    Channel, ChannelId, MethodKind, MethodSet, Preferred, Pty, cipher, kex,
    keys::{Algorithm, load_secret_key},
    mac,
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
};
use uuid::Uuid;

use crate::{
    config::{AuthPolicy, Config, CredentialCapture, SshAuthMode},
    filesystem::persistence::PersistentVirtualFileSystem,
    session::SessionState,
    shell::{FsActionKind, ShellOutput},
    telemetry::{EventEmitter, SessionTelemetry},
};

use super::auth::constant_time_eq;

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
    [MethodKind::Password].as_slice().into()
}

fn reject_auth() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(advertised_auth_methods()),
        partial_success: false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("cannot load SSH host key: {0}")]
    Key(#[from] russh::keys::Error),
    #[error("cannot bind SSH listener: {0}")]
    Io(#[from] std::io::Error),
    #[error("configured authentication password environment variable is missing")]
    MissingPassword,
}

pub async fn run(config: Config, emitter: EventEmitter) -> Result<(), ServerError> {
    let key = load_secret_key(&config.host_key, None)?;
    let initial_state = SessionState::with_profile_and_scenarios(
        &config.hostname,
        &config.username,
        config.distribution,
        config.max_input_bytes,
        &config.baits,
        &config.virtual_processes,
        &config.vulnerability_profiles,
    );
    let filesystem_path = config
        .host_key
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/var/lib/pritvoryashka"))
        .join("virtual-filesystem.json");
    let host_key_bytes = fs::read(&config.host_key)?;
    let mut pepper_hasher = Sha256::new();
    pepper_hasher.update(b"MellCore SSH peer password binding v1\0");
    pepper_hasher.update(&host_key_bytes);
    let peer_credentials = PeerCredentialStore::open(
        filesystem_path
            .parent()
            .unwrap_or_else(|| Path::new("/var/lib/pritvoryashka"))
            .join("peer-passwords.json"),
        pepper_hasher.finalize().into(),
    )?;
    let persistent_filesystem = Arc::new(std::sync::Mutex::new(PersistentVirtualFileSystem::open(
        filesystem_path,
        initial_state.shell.filesystem().clone(),
    )?));
    let ssh_config = Arc::new(server::Config {
        server_id: russh::SshId::Standard(
            if config.distribution == crate::config::Distribution::Windows
                && !config.shared_ssh_identity
            {
                "SSH-2.0-OpenSSH_for_Windows_8.1".into()
            } else {
                SHARED_SSH_IDENTIFICATION.into()
            },
        ),
        methods: advertised_auth_methods(),
        keys: vec![key],
        preferred: openssh_89_preferences(),
        max_auth_attempts: config.auth.max_attempts,
        inactivity_timeout: Some(config.idle_timeout()),
        auth_rejection_time: Duration::from_millis(750),
        maximum_packet_size: 32 * 1024,
        window_size: 256 * 1024,
        ..server::Config::default()
    });
    let listener = TcpListener::bind(config.bind).await?;
    let configured_password = config
        .auth
        .password_env
        .as_deref()
        .and_then(|name| std::env::var(name).ok());
    if config.auth.policy == AuthPolicy::Configured && configured_password.is_none() {
        return Err(ServerError::MissingPassword);
    }
    let shared = Arc::new(Shared {
        semaphore: Arc::new(Semaphore::new(config.max_connections)),
        configured_password,
        persistent_filesystem,
        peer_credentials: Mutex::new(peer_credentials),
        config,
        emitter,
    });
    let proxy_secret = shared.config.dispatcher_proxy_secret.clone();
    tracing::info!(address = %listener.local_addr()?, "Pritvoryashka SSH listener started");
    tokio::select! {
        () = shutdown() => {},
        result = async {
            loop {
                let (mut socket, transport_peer) = match listener.accept().await {
                    Ok(connection) => connection,
                    Err(error) => break Err(ServerError::Io(error)),
                };
                let ssh_config = ssh_config.clone();
                let shared = Arc::clone(&shared);
                let proxy_secret = proxy_secret.clone();
                tokio::spawn(async move {
                    let peer = match resolve_proxy_peer(
                        &mut socket,
                        transport_peer,
                        proxy_secret.as_deref(),
                        shared.config.trap_id,
                    ).await {
                        Ok(peer) => peer,
                        Err(error) => {
                            tracing::debug!(%error, transport_peer = %transport_peer, "rejected untrusted or malformed Dispatcher PROXY header");
                            return;
                        }
                    };
                    let handler = make_handler(shared, peer);
                    match server::run_stream(ssh_config, socket, handler).await {
                        Ok(session) => {
                            if let Err(error) = session.await {
                                tracing::debug!(%error, peer = %peer, "SSH session ended with protocol error");
                            }
                        }
                        Err(error) => tracing::debug!(%error, peer = %peer, "SSH session setup failed"),
                    }
                });
            }
        }
        => result?,
    }
    Ok(())
}

const PROXY_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const PROXY_V2_AUTH_TLV: u8 = 0xe0;

async fn resolve_proxy_peer(
    stream: &mut tokio::net::TcpStream,
    transport_peer: SocketAddr,
    secret: Option<&str>,
    trap_id: Uuid,
) -> io::Result<SocketAddr> {
    let Some(secret) = secret else {
        // Direct/public Middle listeners do not parse PROXY headers at all.
        return Ok(transport_peer);
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut prefix = [0_u8; 16];
        stream.read_exact(&mut prefix).await?;
        if &prefix[..12] != PROXY_V2_SIGNATURE || prefix[12] != 0x21 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PROXY v2 header required",
            ));
        }
        let address_length = match prefix[13] {
            0x11 => 12,
            0x21 => 36,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported PROXY v2 address family",
                ));
            }
        };
        let payload_length = u16::from_be_bytes([prefix[14], prefix[15]]) as usize;
        if payload_length != address_length + 35 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid authenticated PROXY v2 payload length",
            ));
        }
        let mut payload = vec![0_u8; payload_length];
        stream.read_exact(&mut payload).await?;
        if payload[address_length] != PROXY_V2_AUTH_TLV
            || payload[address_length + 1] != 0
            || payload[address_length + 2] != 32
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PROXY v2 authentication TLV missing",
            ));
        }
        let (source, destination) = if address_length == 12 {
            let source_ip = std::net::Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let destination_ip =
                std::net::Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            let source_port = u16::from_be_bytes([payload[8], payload[9]]);
            let destination_port = u16::from_be_bytes([payload[10], payload[11]]);
            (
                SocketAddr::from((source_ip, source_port)),
                SocketAddr::from((destination_ip, destination_port)),
            )
        } else {
            let source_ip = std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&payload[..16]).expect("checked IPv6 block"),
            );
            let destination_ip = std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&payload[16..32]).expect("checked IPv6 block"),
            );
            let source_port = u16::from_be_bytes([payload[32], payload[33]]);
            let destination_port = u16::from_be_bytes([payload[34], payload[35]]);
            (
                SocketAddr::from((source_ip, source_port)),
                SocketAddr::from((destination_ip, destination_port)),
            )
        };
        let expected = proxy_mac(secret, trap_id, source, destination);
        if !constant_time_eq(&expected, &payload[address_length + 3..]) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid Dispatcher PROXY v2 authentication",
            ));
        }
        Ok(source)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for Dispatcher PROXY header",
        )
    })?
}

fn proxy_mac(secret: &str, trap_id: Uuid, source: SocketAddr, destination: SocketAddr) -> [u8; 32] {
    let mut message = b"HoneyForge PROXYv2 source v1\0".to_vec();
    message.extend_from_slice(trap_id.as_bytes());
    match (source.ip(), destination.ip()) {
        (std::net::IpAddr::V4(source), std::net::IpAddr::V4(destination)) => {
            message.push(4);
            message.extend_from_slice(&source.octets());
            message.extend_from_slice(&destination.octets());
        }
        (std::net::IpAddr::V6(source), std::net::IpAddr::V6(destination)) => {
            message.push(6);
            message.extend_from_slice(&source.octets());
            message.extend_from_slice(&destination.octets());
        }
        _ => unreachable!("PROXY addresses must use the same IP family"),
    }
    message.extend_from_slice(&source.port().to_be_bytes());
    message.extend_from_slice(&destination.port().to_be_bytes());

    let mut key = [0_u8; 16];
    for (index, pair) in secret.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16).expect("validated hex") as u8;
        let low = (pair[1] as char).to_digit(16).expect("validated hex") as u8;
        key[index] = (high << 4) | low;
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct PeerCredential {
    username: String,
    password_sha256: String,
    #[serde(default)]
    failed_attempts: u8,
    #[serde(default)]
    accept_after_failures: u8,
}

struct PeerCredentialStore {
    path: PathBuf,
    pepper: [u8; 32],
    by_ip: BTreeMap<String, PeerCredential>,
}

impl PeerCredentialStore {
    fn open(path: PathBuf, pepper: [u8; 32]) -> io::Result<Self> {
        let by_ip = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSH peer credential store is not a regular file or exceeds its size limit",
                    ));
                }
                serde_json::from_slice(&fs::read(&path)?).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid SSH peer credential store: {error}"),
                    )
                })?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error),
        };
        let store = Self {
            path,
            pepper,
            by_ip,
        };
        if !store.path.exists() {
            store.persist()?;
        }
        Ok(store)
    }

    fn adaptive_accept_or_remember(
        &mut self,
        ip: String,
        username: &str,
        password: &str,
    ) -> io::Result<bool> {
        if password.is_empty() || password.len() > 128 || password.chars().any(char::is_control) {
            return Ok(false);
        }
        if let Some(credential) = self.by_ip.get(&ip) {
            if !credential.password_sha256.is_empty() {
                let digest = self.digest(&ip, username, password);
                return Ok(credential.username == username
                    && constant_time_eq(credential.password_sha256.as_bytes(), digest.as_bytes()));
            }
        } else if self.by_ip.len() >= 4096 {
            return Ok(false);
        }

        let previous = self.by_ip.get(&ip).cloned();
        let digest = self.digest(&ip, username, password);
        let accepted = if let Some(credential) = self.by_ip.get_mut(&ip) {
            if credential.failed_attempts < credential.accept_after_failures {
                credential.failed_attempts = credential.failed_attempts.saturating_add(1);
                false
            } else {
                credential.username = username.to_owned();
                credential.password_sha256 = digest;
                true
            }
        } else {
            let random = uuid::Uuid::new_v4();
            let accept_after_failures = random.as_bytes()[0] % 4 + 2;
            self.by_ip.insert(
                ip.clone(),
                PeerCredential {
                    username: String::new(),
                    password_sha256: String::new(),
                    failed_attempts: 1,
                    accept_after_failures,
                },
            );
            false
        };

        if let Err(error) = self.persist() {
            if let Some(previous) = previous {
                self.by_ip.insert(ip, previous);
            } else {
                self.by_ip.remove(&ip);
            }
            return Err(error);
        }
        Ok(accepted)
    }

    fn digest(&self, ip: &str, username: &str, password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.pepper);
        hasher.update((ip.len() as u64).to_be_bytes());
        hasher.update(ip.as_bytes());
        hasher.update((username.len() as u64).to_be_bytes());
        hasher.update(username.as_bytes());
        hasher.update((password.len() as u64).to_be_bytes());
        hasher.update(password.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn persist(&self) -> io::Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "credential store path has no parent",
            )
        })?;
        fs::create_dir_all(parent)?;
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if !metadata.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSH peer credential store path is not a regular file",
                ));
            }
        }
        let bytes = serde_json::to_vec(&self.by_ip).map_err(|error| {
            io::Error::other(format!("cannot encode peer credentials: {error}"))
        })?;
        let temporary = parent.join(format!(".peer-passwords-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

struct Shared {
    semaphore: Arc<Semaphore>,
    persistent_filesystem: Arc<std::sync::Mutex<PersistentVirtualFileSystem>>,
    config: Config,
    configured_password: Option<String>,
    peer_credentials: Mutex<PeerCredentialStore>,
    emitter: EventEmitter,
}

fn make_handler(shared: Arc<Shared>, peer: SocketAddr) -> Handler {
    let permit = shared.semaphore.clone().try_acquire_owned().ok();
    let telemetry = shared.emitter.session(peer);
    telemetry.emit(
        "connection.opened",
        json!({"accepted":permit.is_some(),"active_limit":shared.config.max_connections}),
    );
    Handler {
        state: SessionState::with_persistent_environment_and_scenarios(
            &shared.config.hostname,
            shared.config.max_input_bytes,
            &shared.config.baits,
            &shared.config.virtual_processes,
            shared.persistent_filesystem.clone(),
            &shared.config.username,
            shared.config.distribution,
            &shared.config.vulnerability_profiles,
        ),
        shared,
        peer,
        telemetry,
        permit,
        auth_attempts: 0,
        authenticated_user: None,
        channels: HashSet::new(),
    }
}

struct Handler {
    shared: Arc<Shared>,
    peer: SocketAddr,
    state: SessionState,
    telemetry: SessionTelemetry,
    permit: Option<OwnedSemaphorePermit>,
    auth_attempts: usize,
    authenticated_user: Option<String>,
    channels: HashSet<ChannelId>,
}

impl Handler {
    fn end_session(&mut self, reason: &str) {
        if self.state.session_ended || !self.state.shell_started {
            return;
        }
        self.state.finish_session();
        self.state.session_ended = true;
        let metrics = self.state.shell.metrics();
        self.telemetry.emit(
            "session.ended",
            json!({
                "reason":reason,
                "deception_depth":metrics.stages_reached,
                "unique_objects":metrics.unique_objects,
                "stage_transitions":metrics.transitions
            }),
        );
    }

    fn record_output(&self, line: &str, result: &ShellOutput) {
        let command = line.split_whitespace().next().unwrap_or("");
        self.telemetry.emit(
            "command.executed",
            json!({"command":command,"input":line,"exit_status":result.exit_status,"os":self.shared.config.distribution.as_str()}),
        );
        for action in &result.fs_actions {
            let event_type = match action.kind {
                FsActionKind::Accessed => "filesystem.accessed",
                FsActionKind::Modified => "filesystem.modified",
            };
            self.telemetry.emit(
                event_type,
                json!({"operation":action.operation,"path":action.path}),
            );
        }
        for bait in &result.bait_opens {
            self.telemetry.emit(
                "bait.opened",
            json!({"bait_id":bait.id,"bait_name":bait.name,"bait_kind":bait.kind.as_str(),"path":bait.path,"operation":bait.operation,"success":result.exit_status == 0}),
            );
        }
        for interaction in &result.virtual_interactions {
            self.telemetry.emit(
                "deception.interaction",
                json!({
                    "bait":interaction.bait,
                    "action":interaction.action,
                    "target":interaction.target,
                    "success":interaction.success
                }),
            );
        }
        for attempt in &result.vulnerability_attempts {
            self.telemetry.emit(
                "vulnerability.exploit_attempt",
                json!({"profile_id":attempt.profile_id,"source":"ssh_terminal","details":attempt.details}),
            );
        }
        if let Some(change) = &result.deception {
            self.telemetry.emit(
                "deception.triggered",
                json!({"trigger":change.trigger,"artifact":change.artifact}),
            );
            self.telemetry.emit(
                "deception.stage_changed",
                json!({"from":change.from,"to":change.to}),
            );
        }
    }

    async fn send_shell_output(
        &mut self,
        channel: ChannelId,
        result: ShellOutput,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        send_output_text(channel, &result.output, result.stream_output, session).await?;
        if result.close {
            self.end_session("logout");
            session.exit_status_request(channel, result.exit_status)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else if self.state.shell_started {
            session.data(channel, self.state.shell.prompt().into_bytes())?;
        }
        Ok(())
    }
}

async fn send_output_text(
    channel: ChannelId,
    output: &str,
    stream: bool,
    session: &mut Session,
) -> Result<(), russh::Error> {
    if output.is_empty() {
        return Ok(());
    }
    if stream {
        for line in output.split_inclusive('\n') {
            session.data(channel, terminal_bytes(line))?;
            tokio::time::sleep(Duration::from_millis(135)).await;
        }
    } else {
        session.data(channel, terminal_bytes(output))?;
    }
    Ok(())
}

impl Drop for Handler {
    fn drop(&mut self) {
        self.end_session("connection_closed");
        self.telemetry.emit(
            "connection.closed",
            json!({"authenticated":self.authenticated_user.is_some()}),
        );
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.record_auth(user, false);
        Ok(reject_auth())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.auth_attempts = self.auth_attempts.saturating_add(1);
        let accepted = self.permit.is_some()
            && self.auth_attempts <= self.shared.config.auth.max_attempts
            && self.accept_password(self.peer, user, password);
        self.record_auth(user, accepted);
        if accepted {
            self.authenticated_user = Some(user.to_owned());
            self.state.switch_username(user);
            Ok(Auth::Accept)
        } else {
            Ok(reject_auth())
        }
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        self.telemetry.emit(
            "auth.succeeded",
            json!({"username":self.authenticated_user}),
        );
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.permit.is_some() && self.channels.is_empty() {
            self.channels.insert(channel.id());
            reply.accept().await;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.terminal_columns = col_width.clamp(20, 1000);
        self.state.terminal_rows = row_height.clamp(5, 1000);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.terminal_columns = col_width.clamp(20, 1000);
        self.state.terminal_rows = row_height.clamp(5, 1000);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.state.shell_started {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.state.shell_started = true;
        session.channel_success(channel)?;
        self.telemetry.emit(
            "session.started",
            json!({"mode":"shell","os":self.shared.config.distribution.as_str()}),
        );
        session.data(
            channel,
            terminal_bytes(&format!(
                "{} {}\n\n{}",
                match self.shared.config.distribution {
                    crate::config::Distribution::Ubuntu => "Ubuntu 22.04.4 LTS",
                    crate::config::Distribution::Debian => "Debian GNU/Linux 13",
                    crate::config::Distribution::Arch => "Arch Linux",
                    crate::config::Distribution::Windows => "Windows Server 2022",
                },
                self.shared.config.hostname,
                self.state.shell.prompt()
            )),
        )?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data.len() > self.shared.config.max_input_bytes {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let line = String::from_utf8_lossy(data).into_owned();
        session.channel_success(channel)?;
        self.state.shell_started = true;
        self.telemetry.emit(
            "session.started",
            json!({"mode":"exec","os":self.shared.config.distribution.as_str()}),
        );
        let result = self.state.execute_command(&line);
        self.record_output(&line, &result);
        send_output_text(channel, &result.output, result.stream_output, session).await?;
        session.exit_status_request(channel, result.exit_status)?;
        self.end_session("exec_completed");
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
        if !self.state.shell_started {
            return Ok(());
        }
        for &byte in data {
            match byte {
                3 => {
                    self.state.input.clear();
                    self.state.shell.cancel_continuation();
                    session.data(channel, terminal_bytes("^C\n"))?;
                    session.data(channel, self.state.shell.prompt().into_bytes())?;
                }
                4 if self.state.input.is_empty() => {
                    self.end_session("eof");
                    session.eof(channel)?;
                    session.close(channel)?;
                    break;
                }
                8 | 127 if self.state.input.pop().is_some() => {
                    session.data(channel, b"\x08 \x08".to_vec())?;
                }
                b'\r' | b'\n' => {
                    if byte == b'\n' && self.state.last_was_cr {
                        self.state.last_was_cr = false;
                        continue;
                    }
                    self.state.last_was_cr = byte == b'\r';
                    session.data(channel, b"\r\n".to_vec())?;
                    let line = self.state.input.clone();
                    let result = self.state.execute_line();
                    self.record_output(&line, &result);
                    self.send_shell_output(channel, result, session).await?;
                }
                32..=126 if self.state.input.len() < self.shared.config.max_input_bytes => {
                    self.state.input.push(char::from(byte));
                    session.data(channel, vec![byte])?;
                    self.state.last_was_cr = false;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        self.end_session("channel_closed");
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.end_session("eof");
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        session.channel_failure(channel)?;
        Ok(false)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

impl Handler {
    fn accept_password(&self, peer: SocketAddr, user: &str, password: &str) -> bool {
        if !valid_ssh_username(user) {
            return false;
        }
        if user == "root"
            && !self
                .shared
                .config
                .vulnerability_profiles
                .iter()
                .any(|profile| profile == "ssh_root_login_enabled")
        {
            return false;
        }
        match self.shared.config.auth.policy {
            AuthPolicy::RejectAll => false,
            AuthPolicy::Configured => {
                self.shared.config.auth.username.as_deref() == Some(user)
                    && self
                        .shared
                        .configured_password
                        .as_deref()
                        .is_some_and(|expected| {
                            constant_time_eq(expected.as_bytes(), password.as_bytes())
                        })
            }
            AuthPolicy::AcceptAll => match self.shared.config.ssh_auth_mode {
                SshAuthMode::Realistic => {
                    self.shared.config.ssh_credentials.iter().any(|credential| {
                        credential.username == user && credential.password == password
                    })
                }
                SshAuthMode::Adaptive => {
                    self.shared.peer_credentials.lock().is_ok_and(|mut store| {
                        store
                            .adaptive_accept_or_remember(peer.ip().to_string(), user, password)
                            .unwrap_or(false)
                    })
                }
            },
        }
    }

    fn record_auth(&self, user: &str, accepted: bool) {
        let mut payload = serde_json::Map::new();
        if self.shared.config.auth.capture != CredentialCapture::None {
            payload.insert("username".into(), Value::String(user.into()));
        }
        payload.insert("accepted".into(), Value::Bool(accepted));
        self.telemetry
            .emit("auth.attempted", Value::Object(payload));
        for profile in self
            .shared
            .config
            .vulnerability_profiles
            .iter()
            .filter(|profile| {
                (profile.as_str() == "ssh_weak_credentials"
                    || profile.as_str() == "ssh_root_login_enabled")
                    && (profile.as_str() != "ssh_root_login_enabled" || user == "root")
            })
        {
            self.telemetry.emit(
                "vulnerability.exploit_attempt",
                json!({"profile_id":profile,"username":user,"accepted":accepted}),
            );
        }
        if !accepted {
            self.telemetry.emit("auth.failed", json!({"username":user}));
        }
        for bait in self.shared.config.baits.iter().filter(|bait| {
            bait.kind == hf_core::BaitKind::Account
                && bait.effective_implementation() == hf_core::BaitImplementation::VirtualAccount
                && bait
                    .config
                    .account
                    .as_ref()
                    .map_or(bait.name.as_str(), |account| account.login.as_str())
                    .eq_ignore_ascii_case(user)
        }) {
            self.telemetry.emit(
                "bait.opened",
                json!({
                    "bait_id": bait.id,
                    "bait_name": bait.name,
                    "bait_kind": bait.kind.as_str(),
                    "path": bait.path.as_deref().or_else(|| bait.config.account.as_ref().and_then(|account| account.home_directory.as_deref())).unwrap_or("/etc/passwd"),
                    "operation": "authenticate",
                    "accepted": accepted,
                }),
            );
        }
    }
}

fn valid_ssh_username(username: &str) -> bool {
    username.len() <= 32
        && username
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || *byte == b'_')
        && username.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn terminal_bytes(value: &str) -> Vec<u8> {
    value
        .replace("\r\n", "\n")
        .replace('\n', "\r\n")
        .into_bytes()
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
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn middle_advertises_only_password_authentication() {
        let methods = advertised_auth_methods();
        assert!(methods.contains(&MethodKind::Password));
        assert!(!methods.contains(&MethodKind::PublicKey));
        assert!(!methods.contains(&MethodKind::HostBased));
        assert!(!methods.contains(&MethodKind::KeyboardInteractive));
    }

    #[test]
    fn rejected_password_keeps_password_available_for_retry() {
        match reject_auth() {
            Auth::Reject {
                proceed_with_methods: Some(methods),
                partial_success: false,
            } => {
                assert!(methods.contains(&MethodKind::Password));
                assert!(!methods.contains(&MethodKind::PublicKey));
                assert!(!methods.contains(&MethodKind::HostBased));
                assert!(!methods.contains(&MethodKind::KeyboardInteractive));
            }
            _ => panic!("rejected auth must preserve the advertised methods"),
        }
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
