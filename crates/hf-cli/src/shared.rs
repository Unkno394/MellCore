use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{Ipv4Addr, TcpListener},
    path::Path,
    process::Command,
};
use uuid::Uuid;

use crate::{State, atomic_write, set_owner_and_mode};

const UNIT: &str = "hf-local-dispatcher.service";

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    listeners: Vec<Listener>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Listener {
    listen: String,
    targets: Vec<Target>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    trap_id: Uuid,
    address: String,
    weight: u8,
    proxy_protocol: bool,
    proxy_secret: Option<String>,
}

fn config_path(state: &State) -> std::path::PathBuf {
    state.root.join("dispatcher.json")
}
fn load(state: &State) -> anyhow::Result<Config> {
    match fs::read(config_path(state)) {
        Ok(data) => Ok(serde_json::from_slice(&data)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config {
            version: 1,
            listeners: Vec::new(),
        }),
        Err(error) => Err(error.into()),
    }
}
fn save(state: &State, config: &Config) -> anyhow::Result<()> {
    if config.listeners.is_empty() {
        service(&["stop", UNIT])?;
        match fs::remove_file(config_path(state)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        return Ok(());
    }
    atomic_write(
        &config_path(state),
        &serde_json::to_vec_pretty(config)?,
        0o600,
    )?;
    let exe = std::env::current_exe()?.with_file_name("hf-local-dispatcher");
    anyhow::ensure!(
        exe.is_file(),
        "hf-local-dispatcher must be installed beside hf"
    );
    let unit_path = Path::new("/etc/systemd/system").join(UNIT);
    let content = format!(
        "[Unit]\nDescription=HoneyForge local TCP dispatcher\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={} --config {}\nRestart=on-failure\nNoNewPrivileges=true\n\n[Install]\nWantedBy=multi-user.target\n",
        exe.display(),
        config_path(state).display()
    );
    atomic_write(&unit_path, content.as_bytes(), 0o644)?;
    service(&["daemon-reload"])?;
    service(&["enable", UNIT])?;
    service(&["restart", UNIT])?;
    anyhow::ensure!(
        service_active(),
        "local dispatcher did not remain active after restart"
    );
    Ok(())
}
fn service(args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .context("systemctl failed")?;
    anyhow::ensure!(
        output.status.success(),
        "systemctl {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}
pub fn has_listener(state: &State, port: u16) -> anyhow::Result<bool> {
    Ok(load(state)?
        .listeners
        .iter()
        .any(|l| l.listen == format!("0.0.0.0:{port}")))
}
pub fn backend_port() -> anyhow::Result<u16> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
        .local_addr()?
        .port())
}
pub fn identity(state: &State, port: u16) -> anyhow::Result<std::path::PathBuf> {
    let dir = state
        .root
        .join("ssh-identities")
        .join(format!("tcp-{port}"));
    fs::create_dir_all(&dir)?;
    set_owner_and_mode(&dir, 65_532, 0o700)?;
    let key = dir.join("host_ed25519");
    if !key.exists() {
        let output = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()
            .context("ssh-keygen is required for shared SSH identity")?;
        anyhow::ensure!(output.status.success(), "ssh-keygen failed");
        set_owner_and_mode(&key, 65_532, 0o600)?;
    }
    Ok(dir)
}
pub fn proxy_secret() -> String {
    let random = Uuid::new_v4();
    random.simple().to_string()
}
pub fn add(
    state: &State,
    port: u16,
    trap_id: Uuid,
    backend_port: u16,
    requested_weight: Option<u8>,
    proxy_secret: Option<String>,
) -> anyhow::Result<()> {
    let mut config = load(state)?;
    let listen = format!("0.0.0.0:{port}");
    let index = config.listeners.iter().position(|l| l.listen == listen);
    if index.is_none() {
        config.listeners.push(Listener {
            listen: listen.clone(),
            targets: Vec::new(),
        });
    }
    let listener = config
        .listeners
        .iter_mut()
        .find(|l| l.listen == listen)
        .unwrap();
    if listener.targets.is_empty() && requested_weight.is_some() {
        eprintln!(
            "Первый участник общего порта получает 100%; заданный --weight начнёт учитываться при добавлении следующей ловушки."
        );
    }
    let weight = if listener.targets.is_empty() {
        100
    } else {
        requested_weight.unwrap_or(50)
    };
    anyhow::ensure!(
        weight > 0 && weight as usize + listener.targets.len() <= 100,
        "weight leaves less than 1% for an existing member"
    );
    if !listener.targets.is_empty() {
        let remainder = 100 - weight as u16;
        let previous: Vec<u8> = listener.targets.iter().map(|t| t.weight).collect();
        let mut assigned = 0u16;
        for (target, prior) in listener.targets.iter_mut().zip(previous) {
            target.weight = ((prior as u16 * remainder / 100).max(1)) as u8;
            assigned += target.weight as u16;
        }
        while assigned < remainder {
            for target in &mut listener.targets {
                if assigned == remainder {
                    break;
                }
                target.weight += 1;
                assigned += 1;
            }
        }
        while assigned > remainder {
            for target in &mut listener.targets {
                if assigned == remainder {
                    break;
                }
                if target.weight > 1 {
                    target.weight -= 1;
                    assigned -= 1;
                }
            }
        }
    }
    listener.targets.push(Target {
        trap_id,
        address: format!("127.0.0.1:{backend_port}"),
        weight,
        proxy_protocol: proxy_secret.is_some(),
        proxy_secret,
    });
    save(state, &config)
}
pub fn remove(state: &State, trap_id: Uuid) -> anyhow::Result<()> {
    let mut config = load(state)?;
    let mut changed = false;
    for listener in &mut config.listeners {
        let previous = listener.targets.len();
        listener.targets.retain(|target| target.trap_id != trap_id);
        if listener.targets.len() != previous {
            changed = true;
            if !listener.targets.is_empty() {
                let sum: u16 = listener.targets.iter().map(|t| t.weight as u16).sum();
                let mut assigned = 0u16;
                for target in &mut listener.targets {
                    target.weight = ((target.weight as u16 * 100 / sum).max(1)) as u8;
                    assigned += target.weight as u16;
                }
                while assigned < 100 {
                    listener.targets[0].weight += 1;
                    assigned += 1;
                }
                while assigned > 100 {
                    for target in &mut listener.targets {
                        if assigned == 100 {
                            break;
                        }
                        if target.weight > 1 {
                            target.weight -= 1;
                            assigned -= 1;
                        }
                    }
                }
            }
        }
    }
    if !changed {
        return Ok(());
    }
    config
        .listeners
        .retain(|listener| !listener.targets.is_empty());
    save(state, &config)
}

pub fn is_member(state: &State, trap_id: Uuid) -> anyhow::Result<bool> {
    Ok(load(state)?.listeners.iter().any(|listener| {
        listener
            .targets
            .iter()
            .any(|target| target.trap_id == trap_id)
    }))
}

pub fn service_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", UNIT])
        .status()
        .is_ok_and(|status| status.success())
}
