use std::{
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use hf_core::{HighGuestConnection, HighGuestOs, HighOsProfile};
use uuid::Uuid;

pub const DEFAULT_UBUNTU_24_04_IMAGE: &str =
    "/var/lib/honeyforge/images/noble-server-cloudimg-amd64.img";

const DEFAULT_ARCH_LINUX_IMAGE: &str =
    "/var/lib/honeyforge/images/arch-linux-x86_64-cloudimg.qcow2";
const DEFAULT_WINDOWS_SERVER_ISO: &str = "/var/lib/honeyforge/images/windows-server-eval.iso";

pub fn default_image_for(profile: HighOsProfile) -> &'static str {
    match profile.guest_os {
        HighGuestOs::Ubuntu => DEFAULT_UBUNTU_24_04_IMAGE,
        HighGuestOs::ArchLinux => DEFAULT_ARCH_LINUX_IMAGE,
        HighGuestOs::Windows => DEFAULT_WINDOWS_SERVER_ISO,
    }
}

/// A concrete libvirt guest independent of its operating system.
#[derive(Debug, Clone)]
pub struct HighVm {
    pub instance_id: Uuid,
    pub base_image: PathBuf,
    pub external_service_port: u16,
    pub profile: HighOsProfile,
}

impl HighVm {
    pub fn with_profile(
        instance_id: Uuid,
        base_image: PathBuf,
        external_service_port: u16,
        profile: HighOsProfile,
    ) -> Self {
        Self {
            instance_id,
            base_image,
            external_service_port,
            profile,
        }
    }

    /// Compatibility constructor for the currently supported command and recipe.
    pub fn ubuntu_ssh(instance_id: Uuid, base_image: PathBuf, external_ssh_port: u16) -> Self {
        Self::with_profile(
            instance_id,
            base_image,
            external_ssh_port,
            HighOsProfile::ubuntu_ssh(),
        )
    }
}

pub struct LibvirtSandboxManager {
    adapters: Vec<HighOsAdapter>,
    high_root: PathBuf,
}

#[derive(Clone)]
struct HighOsAdapter {
    profile: HighOsProfile,
    recipe_dir: PathBuf,
    default_image: &'static str,
    readiness_timeout: Duration,
    dhcp_wait_attempts: u16,
    scripts: HighLifecycleScripts,
}

#[derive(Clone, Copy)]
struct HighLifecycleScripts {
    download: &'static str,
    launch: &'static str,
    publish: &'static str,
    check_publication: &'static str,
    stop: &'static str,
    reset: &'static str,
    required: &'static [&'static str],
}

const UBUNTU_SCRIPTS: HighLifecycleScripts = HighLifecycleScripts {
    download: "download-ubuntu-base-image.sh",
    launch: "launch.sh",
    publish: "publish-ssh.sh",
    check_publication: "check-dnat.sh",
    stop: "stop.sh",
    reset: "reset.sh",
    required: &[
        "launch.sh",
        "create-overlay.sh",
        "create-network.sh",
        "firewall-common.sh",
        "publish-ssh.sh",
        "unpublish-ssh.sh",
        "check-dnat.sh",
        "stop.sh",
        "reset.sh",
        "download-ubuntu-base-image.sh",
    ],
};

const GENERIC_SCRIPTS: HighLifecycleScripts = HighLifecycleScripts {
    download: "download-base-image.sh",
    launch: "launch.sh",
    publish: "publish-service.sh",
    check_publication: "check-publication.sh",
    stop: "stop.sh",
    reset: "reset.sh",
    required: &[
        "launch.sh",
        "create-overlay.sh",
        "create-network.sh",
        "firewall-common.sh",
        "publish-service.sh",
        "unpublish-service.sh",
        "check-publication.sh",
        "stop.sh",
        "reset.sh",
        "download-base-image.sh",
    ],
};

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
        let ubuntu_recipe_dir = recipe_dir.into();
        let recipes_root = ubuntu_recipe_dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/usr/local/lib/honeyforge"));
        Self {
            adapters: vec![
                HighOsAdapter {
                    profile: HighOsProfile::ubuntu_ssh(),
                    recipe_dir: ubuntu_recipe_dir,
                    default_image: default_image_for(HighOsProfile::ubuntu_ssh()),
                    readiness_timeout: Duration::from_secs(60),
                    dhcp_wait_attempts: 12,
                    scripts: UBUNTU_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::arch_linux_ssh(),
                    recipe_dir: recipes_root.join("high-arch-ssh"),
                    default_image: default_image_for(HighOsProfile::arch_linux_ssh()),
                    readiness_timeout: Duration::from_secs(90),
                    dhcp_wait_attempts: 18,
                    scripts: GENERIC_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::windows_rdp(),
                    recipe_dir: recipes_root.join("high-windows-rdp"),
                    default_image: default_image_for(HighOsProfile::windows_rdp()),
                    // The first unattended Windows setup can take several minutes.  Do not
                    // mark a healthy installer as failed using the cloud-image timeout.
                    readiness_timeout: Duration::from_secs(900),
                    dhcp_wait_attempts: 180,
                    scripts: GENERIC_SCRIPTS,
                },
            ],
            high_root: high_root.into(),
        }
    }

    pub fn create_and_start(&self, vm: &HighVm) -> anyhow::Result<()> {
        if vm.external_service_port == 0 {
            anyhow::bail!(
                "High {} VM needs an external service port",
                profile_recipe_name(vm.profile)
            );
        }
        let adapter = self.adapter_for(vm.profile)?;
        for script in adapter.scripts.required {
            let path = adapter.recipe_dir.join("scripts").join(script);
            if !path.is_file() {
                anyhow::bail!(
                    "High {} recipe is incomplete: missing {}. Bootstrap its recipe archive before deploying it",
                    profile_recipe_name(vm.profile),
                    path.display()
                );
            }
        }
        if !vm.base_image.is_file() {
            if vm.base_image == Path::new(adapter.default_image) {
                self.run(
                    vm.profile,
                    adapter.scripts.download,
                    &[adapter.default_image],
                )?;
            } else {
                anyhow::bail!(
                    "High {} base image does not exist: {}",
                    profile_recipe_name(vm.profile),
                    vm.base_image.display()
                );
            }
        }
        if !vm.base_image.is_file() {
            anyhow::bail!(
                "High {} image download did not create a regular file",
                profile_recipe_name(vm.profile)
            );
        }
        let instance_id = vm.instance_id.to_string();
        let port = vm.external_service_port.to_string();
        self.run(
            vm.profile,
            adapter.scripts.launch,
            &[
                vm.base_image
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("base image path is not UTF-8"))?,
                &instance_id,
                &port,
            ],
        )?;
        if let Err(error) = self
            .run(vm.profile, adapter.scripts.publish, &[&instance_id, &port])
            .and_then(|()| self.wait_until_ready(vm))
        {
            // A VM without its requested external listener is not a deployed trap.  Remove
            // the overlay and libvirt definition now; the next idempotent command can retry
            // from a clean base instead of accumulating inaccessible guests.
            let cleanup = self.run(vm.profile, adapter.scripts.reset, &[&instance_id]);
            if let Err(cleanup_error) = cleanup {
                return Err(anyhow::anyhow!(
                    "High VM publication failed ({error}); cleanup also failed: {cleanup_error}"
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn reset(&self, vm: &HighVm) -> anyhow::Result<()> {
        let instance_id = vm.instance_id.to_string();
        let adapter = self.adapter_for(vm.profile)?;
        self.run(vm.profile, adapter.scripts.reset, &[&instance_id])
    }

    pub fn remove(&self, vm: &HighVm) -> anyhow::Result<()> {
        // reset.sh is the idempotent teardown primitive. Removal invokes it directly so the
        // caller cannot accidentally acquire ResetHighVm's subsequent redeploy semantics.
        let instance_id = vm.instance_id.to_string();
        let adapter = self.adapter_for(vm.profile)?;
        self.run(vm.profile, adapter.scripts.reset, &[&instance_id])
    }

    pub fn stop(&self, vm: &HighVm) -> anyhow::Result<()> {
        let instance_id = vm.instance_id.to_string();
        let adapter = self.adapter_for(vm.profile)?;
        self.run(vm.profile, adapter.scripts.stop, &[&instance_id])
    }

    pub fn reconcile(&self, vm: &HighVm, desired_running: bool) -> anyhow::Result<()> {
        // Refuse a declared-but-uninstalled profile before querying or mutating libvirt.  This
        // keeps a future control-plane profile from falling through to the Ubuntu recipe.
        self.adapter_for(vm.profile)?;
        if !desired_running {
            return self.stop(vm);
        }
        let matches_profile = self.domain_matches_security_profile(vm)?;
        let action = reconcile_action(self.domain_state(vm.instance_id)?, matches_profile);
        match action {
            ReconcileAction::Create => self.create_and_start(vm),
            ReconcileAction::Recreate => {
                self.reset(vm)?;
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

    pub fn healthy(&self, vm: &HighVm) -> anyhow::Result<bool> {
        Ok(high_running_health(
            self.domain_state(vm.instance_id)?,
            self.domain_matches_security_profile(vm)?,
            self.has_published_service(vm),
            self.guest_service_ready(vm),
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
        let Ok(adapter) = self.adapter_for(HighOsProfile::ubuntu_ssh()) else {
            return false;
        };
        self.run(
            HighOsProfile::ubuntu_ssh(),
            adapter.scripts.check_publication,
            &[&instance_id],
        )
        .is_ok()
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

    fn publish_and_wait(&self, vm: &HighVm) -> anyhow::Result<()> {
        let adapter = self.adapter_for(vm.profile)?;
        let instance_id = vm.instance_id.to_string();
        let port = vm.external_service_port.to_string();
        self.run(vm.profile, adapter.scripts.publish, &[&instance_id, &port])?;
        self.wait_until_ready(vm)
    }

    fn wait_until_ready(&self, vm: &HighVm) -> anyhow::Result<()> {
        let timeout = self.adapter_for(vm.profile)?.readiness_timeout;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.has_published_service(vm) && self.guest_service_ready(vm) {
                if !self.guest_agent_ready(vm.instance_id) {
                    tracing::warn!(trap_id = %vm.instance_id, "High VM service is ready but qemu-guest-agent is unavailable");
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        anyhow::bail!(
            "High VM did not reach guest service and publication readiness before timeout"
        )
    }

    fn has_published_service(&self, vm: &HighVm) -> bool {
        let Ok(adapter) = self.adapter_for(vm.profile) else {
            return false;
        };
        let instance_id = vm.instance_id.to_string();
        self.run(
            vm.profile,
            adapter.scripts.check_publication,
            &[&instance_id],
        )
        .is_ok()
    }

    fn guest_service_ready(&self, vm: &HighVm) -> bool {
        let path = self
            .high_root
            .join(vm.instance_id.to_string())
            .join("guest-ip");
        let Ok(address) = std::fs::read_to_string(path) else {
            return false;
        };
        let Ok(ip) = address.trim().parse::<IpAddr>() else {
            return false;
        };
        let guest_port = match vm.profile.connection {
            HighGuestConnection::Ssh { guest_port } | HighGuestConnection::Rdp { guest_port } => {
                guest_port
            }
        };
        TcpStream::connect_timeout(&SocketAddr::new(ip, guest_port), Duration::from_secs(2)).is_ok()
    }

    /// Profile-aware probe used by operational telemetry.  It never guesses a guest's
    /// protocol: an RDP profile is checked on 3389 (or its registered port), not SSH/22.
    pub fn guest_service_is_ready(&self, instance_id: Uuid, profile: HighOsProfile) -> bool {
        self.guest_service_ready(&HighVm::with_profile(
            instance_id,
            PathBuf::new(),
            0,
            profile,
        ))
    }

    fn domain_matches_security_profile(&self, vm: &HighVm) -> anyhow::Result<bool> {
        let name = format!("hf-high-{}", vm.instance_id);
        let output = Command::new("virsh")
            .env("LC_ALL", "C")
            .args(["dumpxml", &name])
            .output()?;
        if !output.status.success() {
            return Ok(false);
        }
        let telemetry_socket = self
            .high_root
            .join(vm.instance_id.to_string())
            .join("telemetry.sock");
        Ok(domain_xml_matches_security_profile(
            &String::from_utf8_lossy(&output.stdout),
            &telemetry_socket,
            vm.profile,
        ))
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

    pub fn service_is_published(&self, vm: &HighVm) -> bool {
        self.has_published_service(vm)
    }

    fn adapter_for(&self, profile: HighOsProfile) -> anyhow::Result<&HighOsAdapter> {
        self.adapters
            .iter()
            .find(|adapter| adapter.profile == profile)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "High OS profile {} is not registered by this agent",
                    profile_recipe_name(profile)
                )
            })
    }

    fn run(&self, profile: HighOsProfile, script: &str, arguments: &[&str]) -> anyhow::Result<()> {
        let adapter = self.adapter_for(profile)?;
        let path = adapter.recipe_dir.join("scripts").join(script);
        let status = Command::new("sh")
            .arg(&path)
            .args(arguments)
            .env("HF_HIGH_ROOT", &self.high_root)
            .env(
                "HF_HIGH_DHCP_ATTEMPTS",
                adapter.dhcp_wait_attempts.to_string(),
            )
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

fn reconcile_action(state: HighDomainState, matches_profile: bool) -> ReconcileAction {
    if state != HighDomainState::Missing && !matches_profile {
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

pub fn profile_recipe_name(profile: HighOsProfile) -> &'static str {
    match profile.guest_os {
        HighGuestOs::Ubuntu => "high-ubuntu-ssh",
        HighGuestOs::ArchLinux => "high-arch-ssh",
        HighGuestOs::Windows => "high-windows-rdp",
    }
}

pub fn profile_manifest_kind(profile: HighOsProfile) -> &'static str {
    match profile.guest_os {
        HighGuestOs::Ubuntu => "high_ubuntu_ssh",
        HighGuestOs::ArchLinux => "high_arch_ssh",
        HighGuestOs::Windows => "high_windows_rdp",
    }
}

pub fn is_supported_profile(profile: HighOsProfile) -> bool {
    profile == HighOsProfile::ubuntu_ssh()
        || profile == HighOsProfile::arch_linux_ssh()
        || profile == HighOsProfile::windows_rdp()
}

fn domain_xml_matches_security_profile(
    xml: &str,
    telemetry_socket: &Path,
    profile: HighOsProfile,
) -> bool {
    let expected_socket = format!("path='{}'", telemetry_socket.display());
    let common = xml.matches("<interface type=").count() == 1
        && xml.contains("<interface type='network'>")
        && xml.contains("<source network='hf-high-isolated'")
        && xml.contains("name='org.honeyforge.telemetry.0'")
        && xml.contains(&expected_socket);
    common
        && match profile.guest_os {
            HighGuestOs::Windows => {
                xml.matches("<graphics ").count() == 1
                    && xml.contains("listen='127.0.0.1'")
                    && !xml.contains("listen='0.0.0.0'")
            }
            HighGuestOs::Ubuntu | HighGuestOs::ArchLinux => xml.matches("<graphics ").count() == 0,
        }
}

fn high_running_health(
    state: HighDomainState,
    matches_security_profile: bool,
    has_dnat: bool,
    ssh_ready: bool,
) -> bool {
    state == HighDomainState::Running && matches_security_profile && has_dnat && ssh_ready
}

pub fn default_recipe_dir() -> &'static Path {
    Path::new("/usr/local/lib/honeyforge/high-ubuntu-ssh")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::{HighImageKind, HighImagePreparation};

    #[test]
    fn high_vm_identity_is_a_real_instance_not_a_shell_simulation() {
        let vm = HighVm::ubuntu_ssh(Uuid::new_v4(), "/images/ubuntu.qcow2".into(), 1488);
        assert!(vm.instance_id.to_string().len() == 36);
        assert_eq!(vm.profile, HighOsProfile::ubuntu_ssh());
        assert_eq!(vm.external_service_port, 1488);
        assert_eq!(
            default_recipe_dir(),
            Path::new("/usr/local/lib/honeyforge/high-ubuntu-ssh")
        );
    }

    #[test]
    fn os_profiles_keep_image_preparation_and_connection_separate_from_vm_state() {
        let ubuntu = HighOsProfile::ubuntu_ssh();
        assert_eq!(ubuntu.guest_os, HighGuestOs::Ubuntu);
        assert_eq!(ubuntu.image_kind, HighImageKind::CloudImage);
        assert_eq!(
            ubuntu.image_preparation,
            HighImagePreparation::CloudInitSeed
        );
        assert_eq!(
            ubuntu.connection,
            HighGuestConnection::Ssh { guest_port: 22 }
        );

        let arch = HighOsProfile::arch_linux_ssh();
        assert_eq!(arch.guest_os, HighGuestOs::ArchLinux);
        assert_eq!(arch.image_kind, HighImageKind::CloudImage);
        assert_eq!(arch.image_preparation, HighImagePreparation::CloudInitSeed);
        assert_eq!(arch.connection, HighGuestConnection::Ssh { guest_port: 22 });

        let windows = HighOsProfile::windows_rdp();
        assert_eq!(windows.guest_os, HighGuestOs::Windows);
        assert_eq!(windows.image_kind, HighImageKind::InstallMediaAndDisk);
        assert_eq!(
            windows.image_preparation,
            HighImagePreparation::UnattendedInstall
        );
        assert_eq!(
            windows.connection,
            HighGuestConnection::Rdp { guest_port: 3389 }
        );
    }

    #[test]
    fn uninstalled_profiles_fail_closed_before_any_lifecycle_script_runs() {
        let manager = LibvirtSandboxManager::with_high_root("/recipes/ubuntu", "/state/high");
        let unsupported = HighOsProfile {
            guest_os: HighGuestOs::Ubuntu,
            image_kind: HighImageKind::PreparedQcow2,
            image_preparation: HighImagePreparation::OfflineGuestPreparation,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        };
        let vm = HighVm::with_profile(
            Uuid::new_v4(),
            "/images/unsupported.qcow2".into(),
            2222,
            unsupported,
        );
        let error = manager.reconcile(&vm, true).unwrap_err();
        assert!(error.to_string().contains("high-ubuntu-ssh"));
        assert!(error.to_string().contains("not registered"));
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
    fn existing_domain_must_keep_isolated_network_and_exact_telemetry_socket() {
        let socket = Path::new("/var/lib/honeyforge/high/id/telemetry.sock");
        let valid = "<domain><devices><interface type='network'><source network='hf-high-isolated'/></interface><channel type='unix'><source mode='bind' path='/var/lib/honeyforge/high/id/telemetry.sock'/><target type='virtio' name='org.honeyforge.telemetry.0'/></channel></devices></domain>";
        assert!(domain_xml_matches_security_profile(
            valid,
            socket,
            HighOsProfile::ubuntu_ssh()
        ));
        assert!(!domain_xml_matches_security_profile(
            &valid.replace("hf-high-isolated", "default"),
            socket,
            HighOsProfile::ubuntu_ssh()
        ));
        assert!(!domain_xml_matches_security_profile(
            &valid.replace("telemetry.sock", "spoof.sock"),
            socket,
            HighOsProfile::ubuntu_ssh()
        ));
        let second_interface =
            valid.replace("</interface>", "</interface><interface type='bridge'/>");
        assert!(!domain_xml_matches_security_profile(
            &second_interface,
            socket,
            HighOsProfile::ubuntu_ssh()
        ));

        let windows = valid.replace(
            "</devices>",
            "<graphics type='spice' listen='127.0.0.1'/></devices>",
        );
        assert!(domain_xml_matches_security_profile(
            &windows,
            socket,
            HighOsProfile::windows_rdp()
        ));
        assert!(!domain_xml_matches_security_profile(
            &windows.replace("127.0.0.1", "0.0.0.0"),
            socket,
            HighOsProfile::windows_rdp()
        ));
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
