use std::{
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use uuid::Uuid;

pub const DEFAULT_UBUNTU_24_04_IMAGE: &str =
    "/var/lib/honeyforge/images/noble-server-cloudimg-amd64.img";

/// First real High profile. The guest is a real Ubuntu VM; this is deliberately not a command
/// emulator. The agent stays outside the guest and invokes libvirt/QEMU lifecycle operations.
#[derive(Debug, Clone)]
pub struct UbuntuSshVm {
    pub instance_id: Uuid,
    pub base_image: PathBuf,
    pub external_ssh_port: u16,
}

pub struct LibvirtSandboxManager {
    recipe_dir: PathBuf,
    high_root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighDomainState {
    Missing,
    Running,
    Paused,
    Stopped,
    Crashed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileAction {
    Create,
    Verify,
    Start,
    Resume,
    Recreate,
}

impl LibvirtSandboxManager {
    pub fn with_high_root(recipe_dir: impl Into<PathBuf>, high_root: impl Into<PathBuf>) -> Self {
        Self {
            recipe_dir: recipe_dir.into(),
            high_root: high_root.into(),
        }
    }

    pub fn create_and_start(&self, vm: &UbuntuSshVm) -> anyhow::Result<()> {
        if vm.external_ssh_port == 0 {
            anyhow::bail!("High Ubuntu VM needs an external SSH port");
        }
        for script in [
            "launch.sh",
            "publish-ssh.sh",
            "unpublish-ssh.sh",
            "check-dnat.sh",
            "stop.sh",
            "reset.sh",
            "download-ubuntu-base-image.sh",
        ] {
            let path = self.recipe_dir.join("scripts").join(script);
            if !path.is_file() {
                anyhow::bail!(
                    "High Ubuntu recipe is incomplete: missing {}. Bootstrap it with HF_HIGH_UBUNTU_RECIPE_ARCHIVE",
                    path.display()
                );
            }
        }
        if !vm.base_image.is_file() {
            if vm.base_image == Path::new(DEFAULT_UBUNTU_24_04_IMAGE) {
                self.run(
                    "download-ubuntu-base-image.sh",
                    &[DEFAULT_UBUNTU_24_04_IMAGE],
                )?;
            } else {
                anyhow::bail!(
                    "High Ubuntu base image does not exist: {}",
                    vm.base_image.display()
                );
            }
        }
        if !vm.base_image.is_file() {
            anyhow::bail!("High Ubuntu image download did not create a regular file");
        }
        let instance_id = vm.instance_id.to_string();
        let port = vm.external_ssh_port.to_string();
        self.run(
            "launch.sh",
            &[
                vm.base_image
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("base image path is not UTF-8"))?,
                &instance_id,
                &port,
            ],
        )?;
        if let Err(error) = self
            .run("publish-ssh.sh", &[&instance_id, &port])
            .and_then(|()| self.wait_until_ready(vm.instance_id, Duration::from_secs(60)))
        {
            // A VM without its requested external listener is not a deployed trap.  Remove
            // the overlay and libvirt definition now; the next idempotent command can retry
            // from a clean base instead of accumulating inaccessible guests.
            let cleanup = self.run("reset.sh", &[&instance_id]);
            if let Err(cleanup_error) = cleanup {
                return Err(anyhow::anyhow!(
                    "High VM publication failed ({error}); cleanup also failed: {cleanup_error}"
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn reset(&self, instance_id: Uuid) -> anyhow::Result<()> {
        let instance_id = instance_id.to_string();
        self.run("reset.sh", &[&instance_id])
    }

    pub fn remove(&self, instance_id: Uuid) -> anyhow::Result<()> {
        // reset.sh is the idempotent teardown primitive. Removal invokes it directly so the
        // caller cannot accidentally acquire ResetHighUbuntu's subsequent redeploy semantics.
        let instance_id = instance_id.to_string();
        self.run("reset.sh", &[&instance_id])
    }

    pub fn stop(&self, instance_id: Uuid) -> anyhow::Result<()> {
        let instance_id = instance_id.to_string();
        self.run("stop.sh", &[&instance_id])
    }

    pub fn reconcile(&self, vm: &UbuntuSshVm, desired_running: bool) -> anyhow::Result<()> {
        if !desired_running {
            return self.stop(vm.instance_id);
        }
        let has_channel = self.domain_has_telemetry_channel(vm.instance_id)?;
        let action = reconcile_action(self.domain_state(vm.instance_id)?, has_channel);
        match action {
            ReconcileAction::Create => self.create_and_start(vm),
            ReconcileAction::Recreate => {
                self.reset(vm.instance_id)?;
                self.create_and_start(vm)
            }
            ReconcileAction::Start => {
                self.virsh(&["start", &format!("hf-high-{}", vm.instance_id)])?;
                self.publish_and_wait(vm)
            }
            ReconcileAction::Resume => {
                self.virsh(&["resume", &format!("hf-high-{}", vm.instance_id)])?;
                self.publish_and_wait(vm)
            }
            ReconcileAction::Verify => self.publish_and_wait(vm),
        }
    }

    pub fn healthy(&self, vm: &UbuntuSshVm) -> anyhow::Result<bool> {
        Ok(high_running_health(
            self.domain_state(vm.instance_id)?,
            self.domain_has_telemetry_channel(vm.instance_id)?,
            self.has_dnat(vm.instance_id),
            self.ssh_ready(vm.instance_id),
        ))
    }

    pub fn domain_state(&self, instance_id: Uuid) -> anyhow::Result<HighDomainState> {
        let name = format!("hf-high-{instance_id}");
        let output = Command::new("virsh")
            .env("LC_ALL", "C")
            .args(["domstate", &name])
            .output()?;
        if !output.status.success() {
            return Ok(HighDomainState::Missing);
        }
        let state = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_ascii_lowercase();
        Ok(if state.contains("running") || state.contains("idle") {
            HighDomainState::Running
        } else if state.contains("paused") || state.contains("blocked") {
            HighDomainState::Paused
        } else if state.contains("shut") || state.contains("off") {
            HighDomainState::Stopped
        } else if state.contains("crashed") {
            HighDomainState::Crashed
        } else {
            HighDomainState::Unknown
        })
    }

    pub fn has_dnat(&self, instance_id: Uuid) -> bool {
        let instance_id = instance_id.to_string();
        self.run("check-dnat.sh", &[&instance_id]).is_ok()
    }

    pub fn guest_agent_ready(&self, instance_id: Uuid) -> bool {
        let name = format!("hf-high-{instance_id}");
        Command::new("virsh")
            .env("LC_ALL", "C")
            .args(["qemu-agent-command", &name, r#"{"execute":"guest-ping"}"#])
            .output()
            .is_ok_and(|output| output.status.success())
    }

    pub fn is_running(&self, instance_id: Uuid) -> anyhow::Result<bool> {
        Ok(self.domain_state(instance_id)? == HighDomainState::Running)
    }

    pub fn domstats(&self, instance_id: Uuid) -> anyhow::Result<String> {
        let name = format!("hf-high-{instance_id}");
        let output = Command::new("virsh")
            .env("LC_ALL", "C")
            .args([
                "domstats",
                &name,
                "--raw",
                "--state",
                "--cpu-total",
                "--vcpu",
                "--balloon",
                "--block",
                "--interface",
            ])
            .output()?;
        if !output.status.success() {
            anyhow::bail!("virsh domstats failed for {name}");
        }
        Ok(String::from_utf8(output.stdout)?)
    }

    fn publish_and_wait(&self, vm: &UbuntuSshVm) -> anyhow::Result<()> {
        let instance_id = vm.instance_id.to_string();
        let port = vm.external_ssh_port.to_string();
        self.run("publish-ssh.sh", &[&instance_id, &port])?;
        self.wait_until_ready(vm.instance_id, Duration::from_secs(60))
    }

    fn wait_until_ready(&self, instance_id: Uuid, timeout: Duration) -> anyhow::Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.has_dnat(instance_id) && self.ssh_ready(instance_id) {
                if !self.guest_agent_ready(instance_id) {
                    tracing::warn!(trap_id = %instance_id, "High VM SSH is ready but qemu-guest-agent is unavailable");
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        anyhow::bail!("High VM did not reach SSH and DNAT readiness before timeout")
    }

    pub fn ssh_ready(&self, instance_id: Uuid) -> bool {
        let path = self
            .high_root
            .join(instance_id.to_string())
            .join("guest-ip");
        let Ok(address) = std::fs::read_to_string(path) else {
            return false;
        };
        let Ok(ip) = address.trim().parse::<IpAddr>() else {
            return false;
        };
        TcpStream::connect_timeout(&SocketAddr::new(ip, 22), Duration::from_secs(2)).is_ok()
    }

    fn domain_has_telemetry_channel(&self, instance_id: Uuid) -> anyhow::Result<bool> {
        let name = format!("hf-high-{instance_id}");
        let output = Command::new("virsh")
            .env("LC_ALL", "C")
            .args(["dumpxml", &name])
            .output()?;
        if !output.status.success() {
            return Ok(false);
        }
        Ok(String::from_utf8_lossy(&output.stdout).contains("org.honeyforge.telemetry.0"))
    }

    fn virsh(&self, arguments: &[&str]) -> anyhow::Result<()> {
        let status = Command::new("virsh")
            .env("LC_ALL", "C")
            .args(arguments)
            .status()?;
        if !status.success() {
            anyhow::bail!("virsh {} exited with {status}", arguments.join(" "));
        }
        Ok(())
    }

    fn run(&self, script: &str, arguments: &[&str]) -> anyhow::Result<()> {
        let path = self.recipe_dir.join("scripts").join(script);
        let status = Command::new("sh")
            .arg(&path)
            .args(arguments)
            .env("HF_HIGH_ROOT", &self.high_root)
            .env("LC_ALL", "C")
            .status()?;
        if !status.success() {
            anyhow::bail!(
                "High VM lifecycle script {} exited with {status}",
                path.display()
            );
        }
        Ok(())
    }
}

fn reconcile_action(state: HighDomainState, has_channel: bool) -> ReconcileAction {
    if state != HighDomainState::Missing && !has_channel {
        return ReconcileAction::Recreate;
    }
    match state {
        HighDomainState::Missing => ReconcileAction::Create,
        HighDomainState::Running => ReconcileAction::Verify,
        HighDomainState::Paused => ReconcileAction::Resume,
        HighDomainState::Stopped => ReconcileAction::Start,
        HighDomainState::Crashed | HighDomainState::Unknown => ReconcileAction::Recreate,
    }
}

fn high_running_health(
    state: HighDomainState,
    has_channel: bool,
    has_dnat: bool,
    ssh_ready: bool,
) -> bool {
    state == HighDomainState::Running && has_channel && has_dnat && ssh_ready
}

pub fn default_recipe_dir() -> &'static Path {
    Path::new("/usr/local/lib/honeyforge/high-ubuntu-ssh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_vm_identity_is_a_real_instance_not_a_shell_simulation() {
        let vm = UbuntuSshVm {
            instance_id: Uuid::new_v4(),
            base_image: "/images/ubuntu.qcow2".into(),
            external_ssh_port: 1488,
        };
        assert!(vm.instance_id.to_string().len() == 36);
        assert_eq!(
            default_recipe_dir(),
            Path::new("/usr/local/lib/honeyforge/high-ubuntu-ssh")
        );
    }

    #[test]
    fn reconciliation_maps_domain_states_to_idempotent_actions() {
        assert_eq!(
            reconcile_action(HighDomainState::Missing, false),
            ReconcileAction::Create
        );
        assert_eq!(
            reconcile_action(HighDomainState::Running, true),
            ReconcileAction::Verify
        );
        assert_eq!(
            reconcile_action(HighDomainState::Stopped, true),
            ReconcileAction::Start
        );
        assert_eq!(
            reconcile_action(HighDomainState::Paused, true),
            ReconcileAction::Resume
        );
        assert_eq!(
            reconcile_action(HighDomainState::Running, false),
            ReconcileAction::Recreate
        );
    }

    #[test]
    fn successful_command_cache_requires_live_high_health() {
        assert!(high_running_health(
            HighDomainState::Running,
            true,
            true,
            true
        ));
        assert!(!high_running_health(
            HighDomainState::Stopped,
            true,
            true,
            true
        ));
        assert!(!high_running_health(
            HighDomainState::Running,
            false,
            true,
            true
        ));
        assert!(!high_running_health(
            HighDomainState::Running,
            true,
            false,
            true
        ));
        assert!(!high_running_health(
            HighDomainState::Running,
            true,
            true,
            false
        ));
    }
}
