use std::{
    io::Read,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use hf_core::{
    HighGuestConnection, HighGuestOs, HighImageKind, HighImagePreparation, HighImageSource,
    HighOsProfile,
};
use uuid::Uuid;

pub const DEFAULT_UBUNTU_24_04_IMAGE: &str =
    "/var/lib/honeyforge/images/noble-server-cloudimg-amd64.img";

const DEFAULT_ARCH_LINUX_IMAGE: &str =
    "/var/lib/honeyforge/images/arch-linux-x86_64-cloudimg.qcow2";
const DEFAULT_DEBIAN_IMAGE: &str = "/var/lib/honeyforge/images/debian-12-genericcloud-amd64.qcow2";
const DEFAULT_WINDOWS_PREPARED_IMAGE: &str =
    "/var/lib/honeyforge/images/windows-server-prepared.qcow2";
const DEFAULT_WINDOWS_SERVER_ISO: &str = "/var/lib/honeyforge/images/windows-server-eval.iso";

pub fn default_image_for(profile: HighOsProfile) -> &'static str {
    if profile == HighOsProfile::windows_rdp_legacy_iso() {
        return DEFAULT_WINDOWS_SERVER_ISO;
    }
    if profile.image_kind == HighImageKind::InstallMediaAndDisk {
        return match profile.guest_os {
            HighGuestOs::Ubuntu => "/var/lib/honeyforge/images/custom-source-required-ubuntu.iso",
            HighGuestOs::Debian => "/var/lib/honeyforge/images/custom-source-required-debian.iso",
            HighGuestOs::ArchLinux => "/var/lib/honeyforge/images/custom-source-required-arch.iso",
            HighGuestOs::CustomLinux => "/var/lib/honeyforge/images/custom-source-required.iso",
            HighGuestOs::Windows => DEFAULT_WINDOWS_SERVER_ISO,
        };
    }
    match profile.guest_os {
        HighGuestOs::Ubuntu => DEFAULT_UBUNTU_24_04_IMAGE,
        HighGuestOs::Debian => DEFAULT_DEBIAN_IMAGE,
        HighGuestOs::ArchLinux => DEFAULT_ARCH_LINUX_IMAGE,
        HighGuestOs::Windows => DEFAULT_WINDOWS_PREPARED_IMAGE,
        HighGuestOs::CustomLinux => match profile.image_preparation {
            HighImagePreparation::BestEffortInstall => {
                "/var/lib/honeyforge/images/custom-source-required.iso"
            }
            _ => "/var/lib/honeyforge/images/custom-source-required.qcow2",
        },
    }
}

/// A concrete libvirt guest independent of its operating system.
#[derive(Debug, Clone)]
pub struct HighVm {
    pub instance_id: Uuid,
    pub base_image: PathBuf,
    pub external_service_port: u16,
    pub profile: HighOsProfile,
    pub image_source: Option<HighImageSource>,
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
            image_source: None,
        }
    }

    pub fn with_source(
        instance_id: Uuid,
        base_image: PathBuf,
        external_service_port: u16,
        profile: HighOsProfile,
        image_source: Option<HighImageSource>,
    ) -> Self {
        Self {
            instance_id,
            base_image,
            external_service_port,
            profile,
            image_source,
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

#[derive(Clone)]
pub struct LibvirtSandboxManager {
    adapters: Vec<HighOsAdapter>,
    high_root: PathBuf,
    network_name: &'static str,
}

#[derive(Clone)]
struct HighOsAdapter {
    profile: HighOsProfile,
    recipe_dir: PathBuf,
    default_image: &'static str,
    readiness_timeout: Duration,
    dhcp_wait_attempts: u16,
    /// Re-run the adapter's verifier before every new VM uses its managed base image.
    /// This is required for immutable QCOW2 backing files: silently trusting an existing
    /// cache entry would let corruption propagate into every new overlay.
    verify_cached_managed_image: bool,
    /// Profiles whose first-boot contract requires a responsive QEMU Guest Agent.
    require_guest_agent: bool,
    publication: HighPublication,
    scripts: HighLifecycleScripts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HighPublication {
    Required,
    Disabled,
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

const WINDOWS_PREPARED_SCRIPTS: HighLifecycleScripts = HighLifecycleScripts {
    download: "ensure-prepared-image.sh",
    launch: "launch-prepared.sh",
    publish: "discover-rdp.sh",
    check_publication: "check-rdp-isolated.sh",
    stop: "stop.sh",
    reset: "reset.sh",
    required: &[
        "launch-prepared.sh",
        "create-prepared-overlay.sh",
        "create-network.sh",
        "firewall-common.sh",
        "discover-rdp.sh",
        "check-rdp-isolated.sh",
        "stop.sh",
        "reset.sh",
        "ensure-prepared-image.sh",
        "verify-prepared-image.sh",
    ],
};

const WINDOWS_ISO_SCRIPTS: HighLifecycleScripts = HighLifecycleScripts {
    download: "download-base-image.sh",
    launch: "launch.sh",
    publish: "discover-rdp.sh",
    check_publication: "check-rdp-isolated.sh",
    stop: "stop.sh",
    reset: "reset.sh",
    required: &[
        "launch.sh",
        "install-windows.sh",
        "verify-windows-media.sh",
        "create-overlay.sh",
        "create-network.sh",
        "firewall-common.sh",
        "discover-rdp.sh",
        "check-rdp-isolated.sh",
        "stop.sh",
        "reset.sh",
        "download-base-image.sh",
    ],
};

const BEST_EFFORT_ISO_SCRIPTS: HighLifecycleScripts = HighLifecycleScripts {
    download: "reject-managed-image.sh",
    launch: "launch-iso.sh",
    publish: "discover-ssh-isolated.sh",
    check_publication: "check-ssh-isolated.sh",
    stop: "stop.sh",
    reset: "reset.sh",
    required: &[
        "launch-iso.sh",
        "create-network.sh",
        "firewall-common.sh",
        "discover-ssh-isolated.sh",
        "check-ssh-isolated.sh",
        "stop.sh",
        "reset.sh",
        "reject-managed-image.sh",
    ],
};

const LINUX_ISO_SCRIPTS: HighLifecycleScripts = HighLifecycleScripts {
    download: "reject-managed-image.sh",
    launch: "launch-iso.sh",
    publish: "discover-ssh-isolated.sh",
    check_publication: "check-ssh-isolated.sh",
    stop: "stop.sh",
    reset: "reset.sh",
    required: &[
        "launch-iso.sh",
        "prepare-unattended-iso.sh",
        "install-arch.sh",
        "arch-console.exp",
        "arch-guest-install.sh",
        "finalize-linux-install.sh",
        "create-network.sh",
        "firewall-common.sh",
        "discover-ssh-isolated.sh",
        "check-ssh-isolated.sh",
        "stop.sh",
        "reset.sh",
        "reject-managed-image.sh",
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
                    verify_cached_managed_image: false,
                    require_guest_agent: false,
                    publication: HighPublication::Disabled,
                    scripts: UBUNTU_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::debian_ssh(),
                    recipe_dir: recipes_root.join("high-debian-ssh"),
                    default_image: default_image_for(HighOsProfile::debian_ssh()),
                    readiness_timeout: Duration::from_secs(90),
                    dhcp_wait_attempts: 18,
                    verify_cached_managed_image: true,
                    require_guest_agent: true,
                    publication: HighPublication::Required,
                    scripts: GENERIC_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::arch_linux_ssh(),
                    recipe_dir: recipes_root.join("high-arch-ssh"),
                    default_image: default_image_for(HighOsProfile::arch_linux_ssh()),
                    readiness_timeout: Duration::from_secs(90),
                    dhcp_wait_attempts: 18,
                    verify_cached_managed_image: true,
                    require_guest_agent: false,
                    publication: HighPublication::Required,
                    scripts: GENERIC_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::windows_rdp(),
                    recipe_dir: recipes_root.join("high-windows-rdp"),
                    default_image: default_image_for(HighOsProfile::windows_rdp()),
                    readiness_timeout: Duration::from_secs(300),
                    dhcp_wait_attempts: 180,
                    verify_cached_managed_image: true,
                    require_guest_agent: false,
                    publication: HighPublication::Disabled,
                    scripts: WINDOWS_PREPARED_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::windows_rdp_legacy_iso(),
                    recipe_dir: recipes_root.join("high-windows-rdp"),
                    default_image: default_image_for(HighOsProfile::windows_rdp_legacy_iso()),
                    readiness_timeout: Duration::from_secs(900),
                    dhcp_wait_attempts: 180,
                    verify_cached_managed_image: false,
                    require_guest_agent: false,
                    publication: HighPublication::Disabled,
                    scripts: WINDOWS_ISO_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::custom_linux_qcow2_ssh(),
                    recipe_dir: recipes_root.join("high-debian-ssh"),
                    default_image: default_image_for(HighOsProfile::custom_linux_qcow2_ssh()),
                    readiness_timeout: Duration::from_secs(120),
                    dhcp_wait_attempts: 24,
                    verify_cached_managed_image: true,
                    require_guest_agent: false,
                    publication: HighPublication::Required,
                    scripts: GENERIC_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::ubuntu_iso_ssh(),
                    recipe_dir: recipes_root.join("high-custom-iso"),
                    default_image: default_image_for(HighOsProfile::ubuntu_iso_ssh()),
                    readiness_timeout: Duration::from_secs(300),
                    dhcp_wait_attempts: 60,
                    verify_cached_managed_image: true,
                    require_guest_agent: true,
                    publication: HighPublication::Disabled,
                    scripts: LINUX_ISO_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::debian_iso_ssh(),
                    recipe_dir: recipes_root.join("high-custom-iso"),
                    default_image: default_image_for(HighOsProfile::debian_iso_ssh()),
                    readiness_timeout: Duration::from_secs(300),
                    dhcp_wait_attempts: 60,
                    verify_cached_managed_image: true,
                    require_guest_agent: true,
                    publication: HighPublication::Disabled,
                    scripts: LINUX_ISO_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::arch_linux_iso_ssh(),
                    recipe_dir: recipes_root.join("high-custom-iso"),
                    default_image: default_image_for(HighOsProfile::arch_linux_iso_ssh()),
                    readiness_timeout: Duration::from_secs(300),
                    dhcp_wait_attempts: 60,
                    verify_cached_managed_image: true,
                    require_guest_agent: true,
                    publication: HighPublication::Disabled,
                    scripts: LINUX_ISO_SCRIPTS,
                },
                HighOsAdapter {
                    profile: HighOsProfile::custom_linux_iso_ssh(),
                    recipe_dir: recipes_root.join("high-custom-iso"),
                    default_image: default_image_for(HighOsProfile::custom_linux_iso_ssh()),
                    readiness_timeout: Duration::from_secs(600),
                    dhcp_wait_attempts: 120,
                    verify_cached_managed_image: true,
                    require_guest_agent: false,
                    publication: HighPublication::Disabled,
                    scripts: BEST_EFFORT_ISO_SCRIPTS,
                },
            ],
            high_root: high_root.into(),
            network_name: high_network_name_from_scope(
                std::env::var_os("HF_HIGH_NETWORK_SCOPE").as_deref(),
            )
            .unwrap_or("invalid-high-network-scope"),
        }
    }

    /// Validate the installed recipe tree before any lifecycle command can mutate libvirt or the
    /// host firewall. Scripts are deliberately required to be regular files, not executable:
    /// lifecycle commands invoke them through `sh`, which also supports read-only recipe trees.
    pub fn validate_recipes(&self) -> anyhow::Result<()> {
        for adapter in &self.adapters {
            if !adapter.recipe_dir.is_dir() {
                anyhow::bail!(
                    "HF_HIGH_ERROR code=RECIPE_DIRECTORY_MISSING stage=configuration: High {} recipe directory does not exist: {}",
                    profile_recipe_name(adapter.profile),
                    adapter.recipe_dir.display()
                );
            }
            let scripts_dir = adapter.recipe_dir.join("scripts");
            if !scripts_dir.is_dir() {
                anyhow::bail!(
                    "HF_HIGH_ERROR code=RECIPE_SCRIPTS_MISSING stage=configuration: High {} scripts directory does not exist: {}",
                    profile_recipe_name(adapter.profile),
                    scripts_dir.display()
                );
            }
            for script in adapter.scripts.required {
                let path = scripts_dir.join(script);
                if !path.is_file() {
                    anyhow::bail!(
                        "HF_HIGH_ERROR code=RECIPE_SCRIPT_MISSING stage=configuration: High {} recipe is missing required script {}",
                        profile_recipe_name(adapter.profile),
                        path.display()
                    );
                }
            }
        }
        Ok(())
    }

    pub fn create_and_start(&self, vm: &HighVm) -> anyhow::Result<()> {
        let adapter = self.adapter_for(vm.profile)?;
        crate::host_inventory::validate_high_vm_host(
            vm.profile,
            vm.image_source.as_ref(),
            &crate::host_inventory::current_static(),
        )?;
        if vm.external_service_port == 0 && adapter.publication == HighPublication::Required {
            anyhow::bail!(
                "High {} VM needs an external service port",
                profile_recipe_name(vm.profile)
            );
        }
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
        if let Some(source) = &vm.image_source {
            crate::high_image::verify_cached_image(source, vm.profile, &vm.base_image)?;
        }
        let managed_image = vm.base_image == Path::new(adapter.default_image);
        if !vm.base_image.is_file() || (managed_image && adapter.verify_cached_managed_image) {
            if managed_image {
                self.run(
                    vm.profile,
                    adapter.scripts.download,
                    &[adapter.default_image],
                )
                .map_err(|failure| lifecycle_error("IMAGE_DOWNLOAD_FAILED", "download", failure))?;
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
        )
        .map_err(|failure| {
            let (code, stage) = match vm.profile.image_preparation {
                HighImagePreparation::UnattendedInstall
                | HighImagePreparation::BestEffortInstall => {
                    ("INSTALLATION_FAILED", "installation")
                }
                _ => ("VM_BOOT_FAILED", "boot"),
            };
            lifecycle_error(code, stage, failure)
        })?;
        if let Err(error) = self.prepare_access_and_wait(vm) {
            if preserve_installation_on_readiness_failure(vm.profile) {
                // Preserve a completed or partially completed installation so an explicit retry
                // or startup reconciliation can resume it.  Resetting here would destroy the
                // installed disk merely because QGA/SSH/telemetry needed more time to start.
                return Err(error);
            }
            let cleanup = self.run(vm.profile, adapter.scripts.reset, &[&instance_id]);
            if let Err(cleanup_error) = cleanup {
                return Err(anyhow::anyhow!(
                    "High VM readiness failed ({error}); cleanup also failed: {cleanup_error}"
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
        if requires_installed_disk_marker(vm.profile) && !self.installed_marker_ready(vm) {
            return self.create_and_start(vm);
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
                self.prepare_access_and_wait(vm)
            }
            ReconcileAction::Resume => {
                self.virsh(&["resume", &format!("hf-high-{}", vm.instance_id)])?;
                self.prepare_access_and_wait(vm)
            }
            ReconcileAction::Verify => self.prepare_access_and_wait(vm),
        }
    }

    pub fn healthy(&self, vm: &HighVm) -> anyhow::Result<bool> {
        let require_guest_agent = self.adapter_for(vm.profile)?.require_guest_agent;
        let guest_ready = self.guest_service_ready(vm)
            && (!require_guest_agent || self.guest_agent_ready(vm.instance_id))
            && required_telemetry_unit(vm.profile).map_or(true, |unit| {
                self.guest_systemd_unit_active(vm.instance_id, unit)
            })
            && self.installed_marker_ready(vm);
        Ok(high_running_health(
            self.domain_state(vm.instance_id)?,
            self.domain_matches_security_profile(vm)?,
            self.has_published_service(vm),
            guest_ready,
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

    fn prepare_access_and_wait(&self, vm: &HighVm) -> anyhow::Result<()> {
        let adapter = self.adapter_for(vm.profile)?;
        let instance_id = vm.instance_id.to_string();
        let port = vm.external_service_port.to_string();
        if !self.installed_marker_ready(vm) {
            return Err(lifecycle_error(
                "INSTALLATION_INCOMPLETE",
                "installation",
                anyhow::anyhow!(
                    "the installed-disk marker is absent; a Live ISO is not a ready High VM"
                ),
            ));
        }
        if let Err(failure) = self.run(vm.profile, adapter.scripts.publish, &[&instance_id, &port])
        {
            let dhcp_timeout = self
                .high_root
                .join(&instance_id)
                .join("dhcp-timeout")
                .is_file();
            let (code, stage) = access_failure_kind(dhcp_timeout);
            let failure = if dhcp_timeout {
                anyhow::anyhow!(
                    "guest did not obtain an IPv4 lease from hf-high-isolated before the DHCP timeout; DNAT publication was not attempted: {failure}"
                )
            } else {
                failure
            };
            return Err(lifecycle_error(code, stage, failure));
        }
        self.wait_until_ready(vm)
    }

    fn wait_until_ready(&self, vm: &HighVm) -> anyhow::Result<()> {
        let adapter = self.adapter_for(vm.profile)?;
        let timeout = adapter.readiness_timeout;
        let deadline = Instant::now() + timeout;
        let mut service_ready = false;
        let mut agent_ready = false;
        let telemetry_ready = required_telemetry_unit(vm.profile).is_none();
        while Instant::now() < deadline {
            if self.access_policy_ready(vm) && self.guest_service_ready(vm) {
                service_ready = true;
                if self.guest_agent_ready(vm.instance_id) {
                    agent_ready = true;
                    if let Some(unit) = required_telemetry_unit(vm.profile) {
                        if self.guest_systemd_unit_active(vm.instance_id, unit) {
                            return Ok(());
                        }
                    } else {
                        return Ok(());
                    }
                }
                if !adapter.require_guest_agent {
                    tracing::warn!(trap_id = %vm.instance_id, "High VM service is ready but qemu-guest-agent is unavailable");
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        if service_ready && adapter.require_guest_agent && !agent_ready {
            return Err(lifecycle_error(
                "GUEST_AGENT_UNAVAILABLE",
                "readiness",
                anyhow::anyhow!(
                    "guest service is reachable but qemu-guest-agent did not answer guest-ping"
                ),
            ));
        }
        if service_ready && agent_ready && !telemetry_ready {
            return Err(lifecycle_error(
                "GUEST_TELEMETRY_UNAVAILABLE",
                "readiness",
                anyhow::anyhow!("guest telemetry systemd service did not become active"),
            ));
        }
        let (code, stage) = match vm.profile.image_preparation {
            HighImagePreparation::UnattendedInstall | HighImagePreparation::BestEffortInstall => {
                ("INSTALLATION_INCOMPLETE", "installation")
            }
            _ => ("GUEST_SERVICE_UNAVAILABLE", "readiness"),
        };
        Err(lifecycle_error(
            code,
            stage,
            anyhow::anyhow!("guest service did not become reachable before the profile timeout"),
        ))
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

    fn access_policy_ready(&self, vm: &HighVm) -> bool {
        self.has_published_service(vm)
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
        let (guest_port, require_ssh_banner) = match vm.profile.connection {
            HighGuestConnection::Ssh { guest_port } => {
                (guest_port, vm.profile == HighOsProfile::ubuntu_iso_ssh())
            }
            HighGuestConnection::Rdp { guest_port } => (guest_port, false),
        };
        let Ok(mut stream) =
            TcpStream::connect_timeout(&SocketAddr::new(ip, guest_port), Duration::from_secs(2))
        else {
            return false;
        };
        if !require_ssh_banner {
            return true;
        }
        if stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .is_err()
        {
            return false;
        }
        let mut banner = [0_u8; 255];
        stream
            .read(&mut banner)
            .is_ok_and(|length| valid_ssh_banner(&banner[..length]))
    }

    fn installed_marker_ready(&self, vm: &HighVm) -> bool {
        !requires_installed_disk_marker(vm.profile)
            || self
                .high_root
                .join(vm.instance_id.to_string())
                .join("installed-disk-verified")
                .is_file()
    }

    fn guest_systemd_unit_active(&self, instance_id: Uuid, unit: &str) -> bool {
        let name = format!("hf-high-{instance_id}");
        let request = serde_json::json!({
            "execute": "guest-exec",
            "arguments": {
                "path": "/bin/systemctl",
                "arg": ["is-active", "--quiet", unit],
                "capture-output": true
            }
        });
        let Ok(output) = Command::new("virsh")
            .env("LC_ALL", "C")
            .args(["qemu-agent-command", &name, &request.to_string()])
            .output()
        else {
            return false;
        };
        let Ok(reply) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
            return false;
        };
        let Some(pid) = reply
            .pointer("/return/pid")
            .and_then(|value| value.as_u64())
        else {
            return false;
        };
        for _ in 0..10 {
            let status_request = serde_json::json!({
                "execute": "guest-exec-status",
                "arguments": { "pid": pid }
            });
            let Ok(status) = Command::new("virsh")
                .env("LC_ALL", "C")
                .args(["qemu-agent-command", &name, &status_request.to_string()])
                .output()
            else {
                return false;
            };
            let Ok(status) = serde_json::from_slice::<serde_json::Value>(&status.stdout) else {
                return false;
            };
            if status
                .pointer("/return/exited")
                .and_then(|value| value.as_bool())
                == Some(true)
            {
                return status
                    .pointer("/return/exitcode")
                    .and_then(|value| value.as_i64())
                    == Some(0);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
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
            self.network_name,
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
        self.adapter_for(vm.profile)
            .is_ok_and(|adapter| adapter.publication == HighPublication::Required)
            && self.has_published_service(vm)
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
        let lifecycle_instance = if script.starts_with("launch") {
            arguments.get(1)
        } else {
            arguments.first()
        }
        .copied()
        .unwrap_or("unknown");
        let mut command = Command::new("sh");
        command
            .arg(&path)
            .args(arguments)
            .env("HF_HIGH_ROOT", &self.high_root)
            .env(
                "HF_HIGH_DHCP_ATTEMPTS",
                adapter.dhcp_wait_attempts.to_string(),
            )
            .env(
                "HF_HIGH_LIFECYCLE_LOG",
                self.high_root
                    .parent()
                    .unwrap_or(Path::new("/var/lib/honeyforge"))
                    .join("traps")
                    .join(lifecycle_instance)
                    .join("lifecycle-events.jsonl"),
            )
            .env("LC_ALL", "C");
        let installer = if profile == HighOsProfile::ubuntu_iso_ssh() {
            Some("ubuntu")
        } else if profile == HighOsProfile::debian_iso_ssh() {
            Some("debian")
        } else if profile == HighOsProfile::arch_linux_iso_ssh() {
            Some("arch")
        } else {
            None
        };
        if let Some(installer) = installer {
            command.env("HF_HIGH_ISO_INSTALLER", installer);
        }
        let output = command.output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let diagnostic = stderr
                .chars()
                .rev()
                .take(4096)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>();
            anyhow::bail!(
                "High VM lifecycle script {} exited with {}: {}",
                path.display(),
                output.status,
                diagnostic.trim()
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
        HighGuestOs::Debian => "high-debian-ssh",
        HighGuestOs::ArchLinux => "high-arch-ssh",
        HighGuestOs::Windows => "high-windows-rdp",
        HighGuestOs::CustomLinux => match profile.image_preparation {
            HighImagePreparation::BestEffortInstall => "high-custom-iso",
            _ => "high-custom-linux",
        },
    }
}

pub fn profile_manifest_kind(profile: HighOsProfile) -> &'static str {
    if profile == HighOsProfile::windows_rdp_legacy_iso() {
        return "high_windows_rdp";
    }
    match profile.guest_os {
        HighGuestOs::Ubuntu if profile.image_kind == HighImageKind::InstallMediaAndDisk => {
            "high_ubuntu_iso_ssh"
        }
        HighGuestOs::Debian if profile.image_kind == HighImageKind::InstallMediaAndDisk => {
            "high_debian_iso_ssh"
        }
        HighGuestOs::ArchLinux if profile.image_kind == HighImageKind::InstallMediaAndDisk => {
            "high_arch_iso_ssh"
        }
        HighGuestOs::Ubuntu => "high_ubuntu_ssh",
        HighGuestOs::Debian => "high_debian_ssh",
        HighGuestOs::ArchLinux => "high_arch_ssh",
        HighGuestOs::Windows => "high_windows_rdp_prepared",
        HighGuestOs::CustomLinux => match profile.image_preparation {
            HighImagePreparation::BestEffortInstall => "high_custom_linux_iso",
            _ => "high_custom_linux_qcow2",
        },
    }
}

pub fn is_supported_profile(profile: HighOsProfile) -> bool {
    profile == HighOsProfile::ubuntu_ssh()
        || profile == HighOsProfile::debian_ssh()
        || profile == HighOsProfile::arch_linux_ssh()
        || profile == HighOsProfile::windows_rdp()
        || profile == HighOsProfile::windows_rdp_legacy_iso()
        || profile == HighOsProfile::ubuntu_iso_ssh()
        || profile == HighOsProfile::debian_iso_ssh()
        || profile == HighOsProfile::arch_linux_iso_ssh()
        || profile == HighOsProfile::custom_linux_qcow2_ssh()
        || profile == HighOsProfile::custom_linux_iso_ssh()
}

fn domain_xml_matches_security_profile(
    xml: &str,
    telemetry_socket: &Path,
    profile: HighOsProfile,
    network_name: &str,
) -> bool {
    let expected_socket = format!("path='{}'", telemetry_socket.display());
    let expected_network = format!("<source network='{network_name}'");
    let common = xml.matches("<interface type=").count() == 1
        && xml.contains("<interface type='network'>")
        && xml.contains(&expected_network)
        && xml.contains("name='org.honeyforge.telemetry.0'")
        && xml.contains(&expected_socket);
    common
        && match profile.guest_os {
            HighGuestOs::Windows => {
                xml.matches("<graphics ").count() == 1
                    && xml.contains("listen='127.0.0.1'")
                    && !xml.contains("listen='0.0.0.0'")
            }
            HighGuestOs::CustomLinux
                if profile.image_preparation == HighImagePreparation::BestEffortInstall =>
            {
                xml.matches("<graphics ").count() == 1
                    && xml.contains("listen='127.0.0.1'")
                    && !xml.contains("listen='0.0.0.0'")
            }
            HighGuestOs::Ubuntu | HighGuestOs::Debian | HighGuestOs::ArchLinux
                if profile.image_kind == HighImageKind::InstallMediaAndDisk =>
            {
                xml.matches("<graphics ").count() == 1
                    && xml.contains("listen='127.0.0.1'")
                    && !xml.contains("listen='0.0.0.0'")
            }
            HighGuestOs::Ubuntu
            | HighGuestOs::Debian
            | HighGuestOs::ArchLinux
            | HighGuestOs::CustomLinux => xml.matches("<graphics ").count() == 0,
        }
}

fn requires_installed_disk_marker(profile: HighOsProfile) -> bool {
    profile.image_kind == HighImageKind::InstallMediaAndDisk
        && profile.image_preparation == HighImagePreparation::UnattendedInstall
}

fn preserve_installation_on_readiness_failure(profile: HighOsProfile) -> bool {
    profile == HighOsProfile::ubuntu_iso_ssh()
}

fn required_telemetry_unit(profile: HighOsProfile) -> Option<&'static str> {
    if !requires_installed_disk_marker(profile) || profile.guest_os == HighGuestOs::Windows {
        return None;
    }
    Some("high-telemetry.service")
}

fn valid_ssh_banner(banner: &[u8]) -> bool {
    banner.starts_with(b"SSH-2.0-") || banner.starts_with(b"SSH-1.99-")
}

fn lifecycle_error(
    code: &'static str,
    stage: &'static str,
    failure: anyhow::Error,
) -> anyhow::Error {
    anyhow::anyhow!("HF_HIGH_ERROR code={code} stage={stage}: {failure}")
}

fn access_failure_kind(dhcp_timeout: bool) -> (&'static str, &'static str) {
    if dhcp_timeout {
        ("DHCP_LEASE_TIMEOUT", "dhcp")
    } else {
        ("ACCESS_POLICY_FAILED", "network")
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

pub const DEFAULT_HIGH_RECIPES_ROOT: &str = "/usr/local/lib/honeyforge";
pub const HIGH_RECIPES_ROOT_ENV: &str = "HF_HIGH_RECIPES_ROOT";

fn high_network_name_from_scope(scope: Option<&std::ffi::OsStr>) -> anyhow::Result<&'static str> {
    match scope
        .and_then(|value| value.to_str())
        .unwrap_or("production")
    {
        "production" => Ok("hf-high-isolated"),
        "e2e" => Ok("hf-high-iso-e2e"),
        value => anyhow::bail!(
            "HF_HIGH_ERROR code=NETWORK_SCOPE_INVALID stage=configuration: HF_HIGH_NETWORK_SCOPE must be production or e2e, got {value}"
        ),
    }
}

pub fn validate_high_network_scope(standalone_high: bool) -> anyhow::Result<()> {
    let scope = std::env::var_os("HF_HIGH_NETWORK_SCOPE");
    let network = high_network_name_from_scope(scope.as_deref())?;
    anyhow::ensure!(
        network != "hf-high-iso-e2e" || standalone_high,
        "HF_HIGH_ERROR code=NETWORK_SCOPE_FORBIDDEN stage=configuration: e2e network scope is allowed only with --standalone-high"
    );
    Ok(())
}

fn recipe_dir_from_override(root: Option<std::ffi::OsString>) -> anyhow::Result<PathBuf> {
    let root = match root {
        Some(root) if root.is_empty() => {
            anyhow::bail!(
                "HF_HIGH_ERROR code=RECIPE_ROOT_INVALID stage=configuration: {HIGH_RECIPES_ROOT_ENV} must not be empty"
            )
        }
        Some(root) => PathBuf::from(root),
        None => PathBuf::from(DEFAULT_HIGH_RECIPES_ROOT),
    };
    if !root.is_absolute() {
        anyhow::bail!(
            "HF_HIGH_ERROR code=RECIPE_ROOT_INVALID stage=configuration: {HIGH_RECIPES_ROOT_ENV} must be an absolute path, got {}",
            root.display()
        );
    }
    Ok(root.join("high-ubuntu-ssh"))
}

pub fn default_recipe_dir() -> anyhow::Result<PathBuf> {
    recipe_dir_from_override(std::env::var_os(HIGH_RECIPES_ROOT_ENV))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::{HighImageKind, HighImagePreparation};
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn high_vm_identity_is_a_real_instance_not_a_shell_simulation() {
        let vm = HighVm::ubuntu_ssh(Uuid::new_v4(), "/images/ubuntu.qcow2".into(), 1488);
        assert!(vm.instance_id.to_string().len() == 36);
        assert_eq!(vm.profile, HighOsProfile::ubuntu_ssh());
        assert_eq!(vm.external_service_port, 1488);
    }

    #[test]
    fn recipe_root_override_selects_the_ubuntu_recipe_beneath_the_shared_root() {
        assert_eq!(
            recipe_dir_from_override(Some("/home/tima/MellCore-iso-e2e/honeypots".into())).unwrap(),
            Path::new("/home/tima/MellCore-iso-e2e/honeypots/high-ubuntu-ssh")
        );
        assert_eq!(
            recipe_dir_from_override(None).unwrap(),
            Path::new("/usr/local/lib/honeyforge/high-ubuntu-ssh")
        );
        assert!(recipe_dir_from_override(Some("".into())).is_err());
        assert!(recipe_dir_from_override(Some("relative/recipes".into())).is_err());
    }

    #[test]
    fn validates_all_recipe_scripts_and_runs_non_executable_scripts_through_sh() {
        let temporary = std::env::temp_dir().join(format!("hf-recipes-{}", Uuid::new_v4()));
        let ubuntu = temporary.join("high-ubuntu-ssh");
        let manager = LibvirtSandboxManager::with_high_root(&ubuntu, temporary.join("state"));
        for adapter in &manager.adapters {
            let scripts = adapter.recipe_dir.join("scripts");
            fs::create_dir_all(&scripts).unwrap();
            for script in adapter.scripts.required {
                let path = scripts.join(script);
                if !path.exists() {
                    fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
        }
        manager.validate_recipes().unwrap();

        let probe = ubuntu.join("scripts/non-executable-probe.sh");
        fs::write(&probe, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o600)).unwrap();
        manager
            .run(HighOsProfile::ubuntu_ssh(), "non-executable-probe.sh", &[])
            .unwrap();

        let missing = ubuntu.join("scripts/launch.sh");
        fs::remove_file(&missing).unwrap();
        let error = manager.validate_recipes().unwrap_err().to_string();
        assert!(error.contains("RECIPE_SCRIPT_MISSING"));
        assert!(error.contains(&missing.display().to_string()));

        fs::remove_dir_all(&temporary).unwrap();
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
        assert_eq!(windows.image_kind, HighImageKind::PreparedQcow2);
        assert_eq!(windows.image_preparation, HighImagePreparation::Sysprep);
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
    fn dhcp_timeout_is_not_reported_as_a_firewall_or_dnat_failure() {
        assert_eq!(access_failure_kind(true), ("DHCP_LEASE_TIMEOUT", "dhcp"));
        assert_eq!(
            access_failure_kind(false),
            ("ACCESS_POLICY_FAILED", "network")
        );
    }

    #[test]
    fn immutable_backing_images_are_revalidated_before_new_overlays() {
        let manager = LibvirtSandboxManager::with_high_root("/recipes/ubuntu", "/state/high");
        let arch = manager
            .adapter_for(HighOsProfile::arch_linux_ssh())
            .unwrap();
        let ubuntu = manager.adapter_for(HighOsProfile::ubuntu_ssh()).unwrap();
        let windows = manager.adapter_for(HighOsProfile::windows_rdp()).unwrap();
        let debian = manager.adapter_for(HighOsProfile::debian_ssh()).unwrap();
        let custom_qcow2 = manager
            .adapter_for(HighOsProfile::custom_linux_qcow2_ssh())
            .unwrap();
        let custom_iso = manager
            .adapter_for(HighOsProfile::custom_linux_iso_ssh())
            .unwrap();
        let legacy = manager
            .adapter_for(HighOsProfile::windows_rdp_legacy_iso())
            .unwrap();
        assert!(arch.verify_cached_managed_image);
        assert!(debian.verify_cached_managed_image);
        assert!(debian.require_guest_agent);
        assert!(!ubuntu.verify_cached_managed_image);
        assert!(!ubuntu.require_guest_agent);
        assert!(windows.verify_cached_managed_image);
        assert_eq!(windows.publication, HighPublication::Disabled);
        assert!(!legacy.verify_cached_managed_image);
        assert_eq!(legacy.publication, HighPublication::Disabled);
        assert_eq!(legacy.scripts.publish, "discover-rdp.sh");
        assert_eq!(custom_qcow2.publication, HighPublication::Required);
        assert_eq!(custom_iso.publication, HighPublication::Disabled);
        assert_ne!(custom_iso.scripts.publish, "publish-service.sh");
    }

    #[test]
    fn prepared_windows_uses_local_qcow2_and_no_publication_script() {
        let manager = LibvirtSandboxManager::with_high_root("/recipes/ubuntu", "/state/high");
        let adapter = manager.adapter_for(HighOsProfile::windows_rdp()).unwrap();
        assert_eq!(
            adapter.default_image,
            "/var/lib/honeyforge/images/windows-server-prepared.qcow2"
        );
        assert_eq!(adapter.scripts.publish, "discover-rdp.sh");
        assert_eq!(adapter.scripts.check_publication, "check-rdp-isolated.sh");
        assert_ne!(adapter.scripts.publish, "publish-service.sh");
        assert_eq!(
            profile_manifest_kind(HighOsProfile::windows_rdp()),
            "high_windows_rdp_prepared"
        );
        assert_eq!(
            profile_manifest_kind(HighOsProfile::windows_rdp_legacy_iso()),
            "high_windows_rdp"
        );
    }

    #[test]
    fn unattended_iso_profiles_require_disk_boot_and_linux_telemetry() {
        for profile in [
            HighOsProfile::ubuntu_iso_ssh(),
            HighOsProfile::debian_iso_ssh(),
            HighOsProfile::arch_linux_iso_ssh(),
            HighOsProfile::windows_rdp_legacy_iso(),
        ] {
            assert!(requires_installed_disk_marker(profile));
        }
        assert_eq!(
            required_telemetry_unit(HighOsProfile::ubuntu_iso_ssh()),
            Some("high-telemetry.service")
        );
        assert_eq!(
            required_telemetry_unit(HighOsProfile::debian_iso_ssh()),
            Some("high-telemetry.service")
        );
        assert_eq!(
            required_telemetry_unit(HighOsProfile::arch_linux_iso_ssh()),
            Some("high-telemetry.service")
        );
        assert_eq!(
            required_telemetry_unit(HighOsProfile::windows_rdp_legacy_iso()),
            None
        );
        assert!(!requires_installed_disk_marker(HighOsProfile::ubuntu_ssh()));
        assert!(preserve_installation_on_readiness_failure(
            HighOsProfile::ubuntu_iso_ssh()
        ));
        assert!(!preserve_installation_on_readiness_failure(
            HighOsProfile::ubuntu_ssh()
        ));
    }

    #[test]
    fn ssh_readiness_requires_an_openssh_protocol_banner() {
        assert!(valid_ssh_banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"));
        assert!(valid_ssh_banner(b"SSH-1.99-compatible\r\n"));
        assert!(!valid_ssh_banner(b"HTTP/1.1 200 OK\r\n"));
        assert!(!valid_ssh_banner(b""));
    }

    #[test]
    fn existing_domain_must_keep_isolated_network_and_exact_telemetry_socket() {
        let socket = Path::new("/var/lib/honeyforge/high/id/telemetry.sock");
        let valid = "<domain><devices><interface type='network'><source network='hf-high-isolated'/></interface><channel type='unix'><source mode='bind' path='/var/lib/honeyforge/high/id/telemetry.sock'/><target type='virtio' name='org.honeyforge.telemetry.0'/></channel></devices></domain>";
        assert!(domain_xml_matches_security_profile(
            valid,
            socket,
            HighOsProfile::ubuntu_ssh(),
            "hf-high-isolated"
        ));
        assert!(!domain_xml_matches_security_profile(
            &valid.replace("hf-high-isolated", "default"),
            socket,
            HighOsProfile::ubuntu_ssh(),
            "hf-high-isolated"
        ));
        assert!(!domain_xml_matches_security_profile(
            &valid.replace("telemetry.sock", "spoof.sock"),
            socket,
            HighOsProfile::ubuntu_ssh(),
            "hf-high-isolated"
        ));
        let second_interface =
            valid.replace("</interface>", "</interface><interface type='bridge'/>");
        assert!(!domain_xml_matches_security_profile(
            &second_interface,
            socket,
            HighOsProfile::ubuntu_ssh(),
            "hf-high-isolated"
        ));

        let windows = valid.replace(
            "</devices>",
            "<graphics type='spice' listen='127.0.0.1'/></devices>",
        );
        assert!(domain_xml_matches_security_profile(
            &windows,
            socket,
            HighOsProfile::windows_rdp(),
            "hf-high-isolated"
        ));
        assert!(!domain_xml_matches_security_profile(
            &windows.replace("127.0.0.1", "0.0.0.0"),
            socket,
            HighOsProfile::windows_rdp(),
            "hf-high-isolated"
        ));
        let e2e = valid
            .replace("hf-high-isolated", "hf-high-iso-e2e")
            .replace(
                "</devices>",
                "<graphics type='spice' listen='127.0.0.1'/></devices>",
            );
        assert!(domain_xml_matches_security_profile(
            &e2e,
            socket,
            HighOsProfile::ubuntu_iso_ssh(),
            "hf-high-iso-e2e"
        ));
        assert_eq!(
            high_network_name_from_scope(Some(std::ffi::OsStr::new("e2e"))).unwrap(),
            "hf-high-iso-e2e"
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
