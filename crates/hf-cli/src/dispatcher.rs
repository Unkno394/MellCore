//! Public TCP entrypoint for groups of HoneyForge traps sharing one port.
//! The local CLI owns its JSON file and atomically replaces it.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::{Notify, RwLock, Semaphore},
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const HASH_KEY_0: u64 = 0x4846_4453_5041_5443;
const HASH_KEY_1: u64 = 0x4f4e_455f_504f_5254;
const MAX_ACTIVE_CONNECTIONS: usize = 256;
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

struct Activity {
    last_seen: std::sync::Mutex<tokio::time::Instant>,
    changed: Notify,
}

impl Activity {
    fn new() -> Self {
        Self {
            last_seen: std::sync::Mutex::new(tokio::time::Instant::now()),
            changed: Notify::new(),
        }
    }

    fn touch(&self) {
        if let Ok(mut last_seen) = self.last_seen.lock() {
            *last_seen = tokio::time::Instant::now();
        }
        self.changed.notify_one();
    }

    fn last_seen(&self) -> tokio::time::Instant {
        self.last_seen
            .lock()
            .map(|last_seen| *last_seen)
            .unwrap_or_else(|poisoned| *poisoned.into_inner())
    }
}

struct ActivityStream<'a> {
    stream: &'a mut TcpStream,
    activity: Arc<Activity>,
}

impl AsyncRead for ActivityStream<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let previous_length = buffer.filled().len();
        let result = Pin::new(&mut *this.stream).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) && buffer.filled().len() > previous_length {
            this.activity.touch();
        }
        result
    }
}

impl AsyncWrite for ActivityStream<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.stream).poll_write(context, bytes);
        if matches!(&result, Poll::Ready(Ok(length)) if *length > 0) {
            this.activity.touch();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_shutdown(context)
    }
}

async fn copy_with_idle_timeout(
    inbound: &mut TcpStream,
    outbound: &mut TcpStream,
) -> io::Result<(u64, u64)> {
    let activity = Arc::new(Activity::new());
    let mut inbound = ActivityStream {
        stream: inbound,
        activity: Arc::clone(&activity),
    };
    let mut outbound = ActivityStream {
        stream: outbound,
        activity: Arc::clone(&activity),
    };
    let transfer = copy_bidirectional(&mut inbound, &mut outbound);
    tokio::pin!(transfer);
    loop {
        let deadline = activity.last_seen() + SESSION_IDLE_TIMEOUT;
        tokio::select! {
            result = &mut transfer => return result,
            _ = tokio::time::sleep_until(deadline) => {
                if tokio::time::Instant::now() >= activity.last_seen() + SESSION_IDLE_TIMEOUT {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "dispatcher session was idle for 600 seconds"));
                }
            }
            _ = activity.changed.notified() => {}
        }
    }
}

#[derive(Parser)]
struct Args {
    #[arg(
        long,
        env = "HF_DISPATCHER_CONFIG",
        default_value = "/etc/honeyforge/dispatcher.json"
    )]
    config: PathBuf,
    #[arg(long, env = "HF_DISPATCHER_RELOAD_SECONDS", default_value_t = 2)]
    reload_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DispatcherConfig {
    version: u8,
    listeners: Vec<ListenerConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ListenerConfig {
    listen: SocketAddr,
    targets: Vec<TargetConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    trap_id: Uuid,
    address: SocketAddr,
    weight: u8,
    #[serde(default)]
    proxy_protocol: bool,
    #[serde(default)]
    proxy_secret: Option<String>,
    #[serde(default)]
    high_backend: bool,
}

type Routing = HashMap<SocketAddr, Vec<TargetConfig>>;

fn parse_config(bytes: &[u8]) -> anyhow::Result<DispatcherConfig> {
    let config: DispatcherConfig =
        serde_json::from_slice(bytes).context("invalid dispatcher JSON")?;
    anyhow::ensure!(config.version == 1, "unsupported dispatcher config version");
    anyhow::ensure!(
        !config.listeners.is_empty(),
        "dispatcher config has no listeners"
    );
    let mut listeners = std::collections::HashSet::new();
    for listener in &config.listeners {
        anyhow::ensure!(
            listeners.insert(listener.listen),
            "duplicate dispatcher listener"
        );
        anyhow::ensure!(
            !listener.targets.is_empty(),
            "dispatcher listener has no targets"
        );
        let total: u16 = listener
            .targets
            .iter()
            .map(|target| u16::from(target.weight))
            .sum();
        anyhow::ensure!(total == 100, "target weights must total exactly 100");
        let mut traps = std::collections::HashSet::new();
        let mut addresses = std::collections::HashSet::new();
        for target in &listener.targets {
            anyhow::ensure!(target.weight > 0, "target weight must be positive");
            anyhow::ensure!(traps.insert(target.trap_id), "duplicate target trap");
            anyhow::ensure!(addresses.insert(target.address), "duplicate target address");
            if target.high_backend {
                let valid_high_backend = match target.address {
                    SocketAddr::V4(address) => {
                        let octets = address.ip().octets();
                        octets[..3] == [192, 168, 252]
                            && (100..=200).contains(&octets[3])
                            && address.port() == 22
                    }
                    SocketAddr::V6(_) => false,
                };
                anyhow::ensure!(
                    valid_high_backend && !target.proxy_protocol && target.proxy_secret.is_none(),
                    "High backends must be isolated guest IPv4 SSH targets without PROXY protocol"
                );
            } else {
                anyhow::ensure!(
                    target.address.ip().is_loopback(),
                    "non-High target address must be loopback"
                );
            }
            anyhow::ensure!(
                target.proxy_protocol == target.proxy_secret.is_some(),
                "PROXY protocol targets require exactly one shared secret"
            );
            if let Some(secret) = &target.proxy_secret {
                anyhow::ensure!(valid_proxy_secret(secret), "invalid PROXY protocol secret");
            }
        }
    }
    Ok(config)
}

fn routing(config: &DispatcherConfig) -> Routing {
    config
        .listeners
        .iter()
        .map(|item| (item.listen, item.targets.clone()))
        .collect()
}

/// Source TCP port is excluded so a reconnect from one IP uses the same bucket.
fn source_bucket(ip: IpAddr) -> u8 {
    #[allow(deprecated)]
    let mut hasher = std::hash::SipHasher::new_with_keys(HASH_KEY_0, HASH_KEY_1);
    ip.hash(&mut hasher);
    (hasher.finish() % 100) as u8
}

fn target_for_bucket(targets: &[TargetConfig], bucket: u8) -> &TargetConfig {
    let mut upper_bound = 0_u8;
    for target in targets {
        upper_bound = upper_bound.saturating_add(target.weight);
        if bucket < upper_bound {
            return target;
        }
    }
    unreachable!("validated weights cover buckets 0..99")
}

fn valid_proxy_secret(secret: &str) -> bool {
    secret.len() == 32 && secret.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_proxy_secret(secret: &str) -> [u8; 16] {
    let mut key = [0_u8; 16];
    for (index, pair) in secret.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16).expect("validated hex") as u8;
        let low = (pair[1] as char).to_digit(16).expect("validated hex") as u8;
        key[index] = (high << 4) | low;
    }
    key
}

fn proxy_mac(secret: &str, trap_id: Uuid, source: SocketAddr, destination: SocketAddr) -> [u8; 32] {
    let mut message = b"HoneyForge PROXYv2 source v1\0".to_vec();
    message.extend_from_slice(trap_id.as_bytes());
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            message.push(4);
            message.extend_from_slice(&source.octets());
            message.extend_from_slice(&destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            message.push(6);
            message.extend_from_slice(&source.octets());
            message.extend_from_slice(&destination.octets());
        }
        _ => unreachable!("PROXY addresses must use the same IP family"),
    }
    message.extend_from_slice(&source.port().to_be_bytes());
    message.extend_from_slice(&destination.port().to_be_bytes());

    let key = decode_proxy_secret(secret);
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

fn proxy_v2_header(
    trap_id: Uuid,
    source: SocketAddr,
    destination: SocketAddr,
    secret: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    let (family, address_bytes) = match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            let mut addresses = Vec::with_capacity(12);
            addresses.extend_from_slice(&source.ip().octets());
            addresses.extend_from_slice(&destination.ip().octets());
            addresses.extend_from_slice(&source.port().to_be_bytes());
            addresses.extend_from_slice(&destination.port().to_be_bytes());
            (0x11, addresses)
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            let mut addresses = Vec::with_capacity(36);
            addresses.extend_from_slice(&source.ip().octets());
            addresses.extend_from_slice(&destination.ip().octets());
            addresses.extend_from_slice(&source.port().to_be_bytes());
            addresses.extend_from_slice(&destination.port().to_be_bytes());
            (0x21, addresses)
        }
        _ => anyhow::bail!("Dispatcher source and destination IP families differ"),
    };
    let payload_length = address_bytes.len() + 3 + 32;
    header.extend_from_slice(&[0x21, family]);
    header.extend_from_slice(&(payload_length as u16).to_be_bytes());
    header.extend_from_slice(&address_bytes);
    header.extend_from_slice(&[0xe0, 0, 32]);
    header.extend_from_slice(&proxy_mac(secret, trap_id, source, destination));
    Ok(header)
}

async fn serve_listener(
    listener: TcpListener,
    address: SocketAddr,
    routes: Arc<RwLock<Routing>>,
    connections: Arc<Semaphore>,
) {
    loop {
        let (mut inbound, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                error!(%error, listen = %address, "dispatcher accept failed");
                continue;
            }
        };
        let connection_permit = match Arc::clone(&connections).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!(listen = %address, peer = %peer, "dispatcher connection limit reached; rejecting connection");
                drop(inbound);
                tokio::time::sleep(Duration::from_millis(25)).await;
                continue;
            }
        };
        let routes = Arc::clone(&routes);
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let target = {
                let table = routes.read().await;
                table
                    .get(&address)
                    .map(|items| target_for_bucket(items, source_bucket(peer.ip())).clone())
            };
            let Some(target) = target else {
                return;
            };
            let mut outbound = match tokio::time::timeout(
                BACKEND_CONNECT_TIMEOUT,
                TcpStream::connect(target.address),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    warn!(%error, peer = %peer, trap_id = %target.trap_id, target = %target.address, "trap backend unavailable");
                    return;
                }
                Err(_) => {
                    warn!(peer = %peer, trap_id = %target.trap_id, target = %target.address, "trap backend connection timed out");
                    return;
                }
            };
            if target.proxy_protocol {
                let destination = match inbound.local_addr() {
                    Ok(address) => address,
                    Err(_) => return,
                };
                let secret = target
                    .proxy_secret
                    .as_deref()
                    .expect("validated target secret");
                let header = match proxy_v2_header(target.trap_id, peer, destination, secret) {
                    Ok(header) => header,
                    Err(_) => return,
                };
                if outbound.write_all(&header).await.is_err() {
                    return;
                }
            }
            if let Err(error) = copy_with_idle_timeout(&mut inbound, &mut outbound).await {
                warn!(%error, peer = %peer, trap_id = %target.trap_id, "dispatch stream failed");
            }
        });
    }
}

async fn reload_loop(
    path: PathBuf,
    expected: std::collections::HashSet<SocketAddr>,
    routes: Arc<RwLock<Routing>>,
    every: Duration,
) {
    let mut previous = Vec::new();
    loop {
        match tokio::fs::read(&path).await {
            Ok(bytes) if bytes != previous => match parse_config(&bytes) {
                Ok(config) => {
                    let listeners: std::collections::HashSet<_> =
                        config.listeners.iter().map(|item| item.listen).collect();
                    if listeners != expected {
                        warn!(
                            "listener set changed; restart dispatcher to add or remove public ports"
                        );
                    } else {
                        *routes.write().await = routing(&config);
                        previous = bytes;
                        info!("dispatcher routing configuration reloaded");
                    }
                }
                Err(error) => warn!(%error, "refusing invalid dispatcher configuration"),
            },
            Ok(_) => {}
            Err(error) => {
                warn!(%error, path = %path.display(), "cannot read dispatcher configuration")
            }
        }
        tokio::time::sleep(every).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "hf_local_dispatcher=info".into()),
        )
        .init();
    let args = Args::parse();
    let bytes = tokio::fs::read(&args.config)
        .await
        .with_context(|| format!("cannot read {}", args.config.display()))?;
    let config = parse_config(&bytes)?;
    let addresses: Vec<_> = config.listeners.iter().map(|item| item.listen).collect();
    let expected: std::collections::HashSet<_> = addresses.iter().copied().collect();
    let routes = Arc::new(RwLock::new(routing(&config)));
    let connections = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    for address in &addresses {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("cannot bind dispatcher {address}"))?;
        info!(%address, "dispatcher listening");
        tokio::spawn(serve_listener(
            listener,
            *address,
            Arc::clone(&routes),
            Arc::clone(&connections),
        ));
    }
    tokio::spawn(reload_loop(
        args.config,
        expected,
        routes,
        Duration::from_secs(args.reload_seconds.max(1)),
    ));
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_config;

    #[test]
    fn accepts_loopback_middle_and_isolated_high_backends_together() {
        let config = br#"{
            "version": 1,
            "listeners": [{
                "listen": "0.0.0.0:25222",
                "targets": [
                    {"trap_id":"00000000-0000-0000-0000-000000000001","address":"127.0.0.1:45917","weight":50,"proxy_protocol":true,"proxy_secret":"0123456789abcdef0123456789abcdef"},
                    {"trap_id":"00000000-0000-0000-0000-000000000002","address":"192.168.252.123:22","weight":50,"high_backend":true}
                ]
            }]
        }"#;

        parse_config(config).unwrap();
    }

    #[test]
    fn rejects_high_backend_outside_guest_pool_or_with_proxy_protocol() {
        for (address, proxy) in [
            ("192.168.252.99:22", "false"),
            ("192.168.252.123:2222", "false"),
            ("192.168.252.123:22", "true"),
        ] {
            let config = format!(
                r#"{{"version":1,"listeners":[{{"listen":"0.0.0.0:25222","targets":[{{"trap_id":"00000000-0000-0000-0000-000000000001","address":"{address}","weight":100,"high_backend":true,"proxy_protocol":{proxy},"proxy_secret":{}}}]}}]}}"#,
                if proxy == "true" {
                    "\"secret\""
                } else {
                    "null"
                }
            );
            assert!(
                parse_config(config.as_bytes()).is_err(),
                "accepted {address}"
            );
        }
    }
}
