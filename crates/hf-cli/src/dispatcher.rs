//! Public TCP entrypoint for groups of HoneyForge traps sharing one port.
//! The local CLI owns its JSON file and atomically replaces it.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const HASH_KEY_0: u64 = 0x4846_4453_5041_5443;
const HASH_KEY_1: u64 = 0x4f4e_455f_504f_5254;

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
            anyhow::ensure!(
                target.address.ip().is_loopback(),
                "target address must be loopback"
            );
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

async fn serve_listener(listener: TcpListener, address: SocketAddr, routes: Arc<RwLock<Routing>>) {
    loop {
        let (mut inbound, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                error!(%error, listen = %address, "dispatcher accept failed");
                continue;
            }
        };
        let routes = Arc::clone(&routes);
        tokio::spawn(async move {
            let target = {
                let table = routes.read().await;
                table
                    .get(&address)
                    .map(|items| target_for_bucket(items, source_bucket(peer.ip())).clone())
            };
            let Some(target) = target else {
                return;
            };
            let mut outbound = match TcpStream::connect(target.address).await {
                Ok(stream) => stream,
                Err(_) => return,
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
            let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
        });
    }
}

async fn reload_loop(
    path: PathBuf,
    expected: Vec<SocketAddr>,
    routes: Arc<RwLock<Routing>>,
    every: Duration,
) {
    let mut previous = Vec::new();
    loop {
        match tokio::fs::read(&path).await {
            Ok(bytes) if bytes != previous => match parse_config(&bytes) {
                Ok(config) => {
                    let listeners: Vec<_> =
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
    let routes = Arc::new(RwLock::new(routing(&config)));
    for address in &addresses {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("cannot bind dispatcher {address}"))?;
        info!(%address, "dispatcher listening");
        tokio::spawn(serve_listener(listener, *address, Arc::clone(&routes)));
    }
    tokio::spawn(reload_loop(
        args.config,
        addresses,
        routes,
        Duration::from_secs(args.reload_seconds.max(1)),
    ));
    tokio::signal::ctrl_c().await?;
    Ok(())
}
