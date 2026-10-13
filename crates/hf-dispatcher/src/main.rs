//! Public TCP entrypoint for groups of HoneyForge traps sharing one port.
//! Control Plane owns its JSON file and atomically replaces it.

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
use tokio::{
    io::copy_bidirectional,
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
                warn!(listen = %address, peer = %peer, "listener has no current routing table");
                return;
            };
            let mut outbound = match TcpStream::connect(target.address).await {
                Ok(stream) => stream,
                Err(error) => {
                    warn!(%error, peer = %peer, trap_id = %target.trap_id, target = %target.address, "trap backend unavailable");
                    return;
                }
            };
            match copy_bidirectional(&mut inbound, &mut outbound).await {
                Ok((from_client, from_trap)) => {
                    info!(peer = %peer, trap_id = %target.trap_id, from_client, from_trap, "dispatch connection closed")
                }
                Err(error) => {
                    warn!(%error, peer = %peer, trap_id = %target.trap_id, "dispatch stream failed")
                }
            }
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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "hf_dispatcher=info".into()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn target(weight: u8) -> TargetConfig {
        TargetConfig {
            trap_id: Uuid::new_v4(),
            address: "127.0.0.1:2200".parse().unwrap(),
            weight,
        }
    }

    #[test]
    fn weighted_ranges_match_the_control_plane_definition() {
        let targets = vec![target(50), target(30), target(20)];
        assert_eq!(target_for_bucket(&targets, 0).trap_id, targets[0].trap_id);
        assert_eq!(target_for_bucket(&targets, 49).trap_id, targets[0].trap_id);
        assert_eq!(target_for_bucket(&targets, 50).trap_id, targets[1].trap_id);
        assert_eq!(target_for_bucket(&targets, 79).trap_id, targets[1].trap_id);
        assert_eq!(target_for_bucket(&targets, 80).trap_id, targets[2].trap_id);
        assert_eq!(target_for_bucket(&targets, 99).trap_id, targets[2].trap_id);
    }

    #[test]
    fn source_ip_is_stable_and_public_backends_are_rejected() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(source_bucket(ip), source_bucket(ip));
        let invalid = br#"{"version":1,"listeners":[{"listen":"0.0.0.0:2222","targets":[{"trap_id":"00000000-0000-0000-0000-000000000001","address":"192.0.2.4:22","weight":100}]}]}"#;
        assert!(parse_config(invalid).is_err());
    }

    #[tokio::test]
    #[ignore = "opens loopback TCP sockets; run explicitly in an integration-capable environment"]
    async fn dispatcher_proxies_a_real_tcp_connection_to_its_selected_backend() {
        let backend_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address_a = backend_a.local_addr().unwrap();
        let address_b = backend_b.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = backend_a.accept().await.unwrap();
            let mut received = [0_u8; 4];
            stream.read_exact(&mut received).await.unwrap();
            stream.write_all(b"a").await.unwrap();
        });
        tokio::spawn(async move {
            let (mut stream, _) = backend_b.accept().await.unwrap();
            let mut received = [0_u8; 4];
            stream.read_exact(&mut received).await.unwrap();
            stream.write_all(b"b").await.unwrap();
        });
        let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = public.local_addr().unwrap();
        let source: IpAddr = "127.0.0.1".parse().unwrap();
        let expected = source_bucket(source);
        let targets = vec![
            TargetConfig {
                trap_id: Uuid::new_v4(),
                address: address_a,
                weight: 50,
            },
            TargetConfig {
                trap_id: Uuid::new_v4(),
                address: address_b,
                weight: 50,
            },
        ];
        let expected_reply = if expected < 50 { b"a" } else { b"b" };
        let routes = Arc::new(RwLock::new(HashMap::from([(address, targets)])));
        let task = tokio::spawn(serve_listener(public, address, routes));

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut reply = [0_u8; 1];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, expected_reply);
        task.abort();
    }
}
