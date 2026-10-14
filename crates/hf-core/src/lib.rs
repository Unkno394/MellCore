//! Stable domain contracts. Network transports and infrastructure live outside this crate.

pub mod host_inventory;
pub mod math;
pub mod security;

pub use host_inventory::*;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistration {
    pub enrollment_token: String,
    pub hostname: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredAgent {
    pub agent_id: Uuid,
    /// Credentials for the selected transport. Never use `agent_id` as authentication.
    pub transport_credential: String,
    /// Settings issued after enrollment for the optional Hysteria transport service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hysteria: Option<HysteriaConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HysteriaConnection {
    /// Public Hysteria endpoint in `host:port` form (IPv6 is bracketed).
    pub server: String,
    /// TLS server name the agent verifies; certificate verification is not disabled.
    pub sni: String,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("agent is not authorized")]
    Unauthorized,
}

/// The agent core depends on this port, not on Hysteria, HTTP, or a radio implementation.
#[async_trait]
pub trait RegistrationTransport: Send + Sync {
    async fn register(&self, registration: AgentRegistration)
    -> Result<RegisteredAgent, CoreError>;
}

#[derive(Debug, Clone)]
pub struct BootstrapScript {
    pub contents: String,
    /// A root-owned initial command copied to the agent inbox during the one SSH bootstrap.
    /// This is deliberately data, never interpolated into the shell installer.
    pub initial_command_json: Option<Vec<u8>>,
}

/// Ephemeral SSH credentials used only during first installation. Do not persist or log this type.
pub struct SshBootstrapTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuthentication,
}

/// Ephemeral SSH authentication material. Never derive Debug/Serialize for this type.
pub enum SshAuthentication {
    Password(String),
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
}

/// Desired honeypot instance. Recipes are supplied by the infrastructure layer, not the core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapSpec {
    pub trap_id: Uuid,
    pub tier: TrapTier,
    pub protocol: String,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrapTier {
    Low,
    Medium,
    High,
}

/// A command is idempotent by `command_id`; the agent persists completed IDs before ACKing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentCommand {
    DeployKozyavka(KozyavkaDeployment),
    DeployPritvoryashka(PritvoryashkaDeployment),
    /// Generic High VM deployment. `DeployHighUbuntu` remains for wire compatibility.
    DeployHighVm(HighVmDeployment),
    DeployHighUbuntu(HighUbuntuDeployment),
    ResetHighVm { command_id: Uuid, trap_id: Uuid },
    ResetHighUbuntu { command_id: Uuid, trap_id: Uuid },
    ReconcileTcpPortGroup(TcpPortGroup),
    StopTrap { command_id: Uuid, trap_id: Uuid },
    RemoveTrap { command_id: Uuid, trap_id: Uuid },
}

impl AgentCommand {
    pub fn command_id(&self) -> Uuid {
        match self {
            Self::DeployKozyavka(command) => command.command_id,
            Self::DeployPritvoryashka(command) => command.command_id,
            Self::DeployHighVm(command) => command.command_id,
            Self::DeployHighUbuntu(command) => command.command_id,
            Self::ResetHighVm { command_id, .. } => *command_id,
            Self::ResetHighUbuntu { command_id, .. } => *command_id,
            Self::ReconcileTcpPortGroup(command) => command.command_id,
            Self::StopTrap { command_id, .. } | Self::RemoveTrap { command_id, .. } => *command_id,
        }
    }
}

/// Exact deployment data for the existing Low SSH banner honeypot. The central backend builds
/// this from its validated profile snapshot; the agent never accepts arbitrary compose YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KozyavkaDeployment {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub host_port: u16,
    pub container_port: u16,
    pub banner: String,
    #[serde(default)]
    pub resources: ContainerResourceLimits,
    /// External direct listener is 0.0.0.0; Dispatcher members are loopback-only.
    pub publish_address: String,
}

/// Exact deployment data for the Middle-interaction SSH trap. The agent fills its own agent ID
/// into the generated runtime configuration rather than trusting it from the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PritvoryashkaDeployment {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub server_id: Uuid,
    pub host_port: u16,
    /// External direct listener is 0.0.0.0; Dispatcher members are loopback-only.
    pub publish_address: String,
    pub hostname: String,
    #[serde(default = "ContainerResourceLimits::middle_default")]
    pub resources: ContainerResourceLimits,
    #[serde(default = "default_pritvoryashka_connections")]
    pub max_connections: u16,
}

fn default_pritvoryashka_connections() -> u16 {
    128
}

/// Bounded Docker resource budget passed as typed deployment data. The agent still enforces
/// tier-specific ceilings and renders its own Compose file; callers never supply YAML.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContainerResourceLimits {
    pub cpu_cores: f64,
    pub memory_mb: u32,
    pub pids: u32,
}

impl Default for ContainerResourceLimits {
    fn default() -> Self {
        Self { cpu_cores: 0.5, memory_mb: 128, pids: 64 }
    }
}

impl ContainerResourceLimits {
    pub fn middle_default() -> Self {
        Self { cpu_cores: 1.0, memory_mb: 512, pids: 256 }
    }

    pub fn within(&self, max_cpu: f64, max_memory_mb: u32, max_pids: u32) -> bool {
        self.cpu_cores.is_finite() && self.cpu_cores >= 0.05 && self.cpu_cores <= max_cpu
            && (32..=max_memory_mb).contains(&self.memory_mb)
            && (16..=max_pids).contains(&self.pids)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighUbuntuDeployment {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub base_image: String,
    pub external_ssh_port: u16,
}

/// Guest operating systems supported by the High VM lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighGuestOs {
    Ubuntu,
    Debian,
    ArchLinux,
    Windows,
    CustomLinux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighImageFormat {
    Qcow2,
    Iso,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighImageArchitecture {
    X86_64,
    Aarch64,
    #[serde(other)]
    Unknown,
}

/// An operator-supplied immutable image. A trusted digest is mandatory: transport TLS alone does
/// not prove that a mutable third-party URL still contains the reviewed artefact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighImageSource {
    pub url: String,
    pub sha256: String,
    pub format: HighImageFormat,
    pub architecture: HighImageArchitecture,
}

/// The immutable artefact expected before an OS adapter starts a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighImageKind {
    CloudImage,
    PreparedQcow2,
    InstallMediaAndDisk,
}

/// Per-instance preparation performed by the OS adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighImagePreparation {
    CloudInitSeed,
    OfflineGuestPreparation,
    UnattendedInstall,
    Sysprep,
    /// Boots isolated installation media and probes the declared guest service. Success depends
    /// on the media providing its own unattended mechanism; arbitrary installers are not claimed
    /// to be universally automatable.
    BestEffortInstall,
}

/// The service published externally by a High guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HighGuestConnection {
    Ssh { guest_port: u16 },
    Rdp { guest_port: u16 },
}

/// A typed OS profile carried across the control plane and persisted by the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighOsProfile {
    pub guest_os: HighGuestOs,
    pub image_kind: HighImageKind,
    pub image_preparation: HighImagePreparation,
    pub connection: HighGuestConnection,
}

impl HighOsProfile {
    pub const fn ubuntu_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::Ubuntu,
            image_kind: HighImageKind::CloudImage,
            image_preparation: HighImagePreparation::CloudInitSeed,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn arch_linux_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::ArchLinux,
            image_kind: HighImageKind::CloudImage,
            image_preparation: HighImagePreparation::CloudInitSeed,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn debian_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::Debian,
            image_kind: HighImageKind::CloudImage,
            image_preparation: HighImagePreparation::CloudInitSeed,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn windows_rdp() -> Self {
        Self {
            guest_os: HighGuestOs::Windows,
            image_kind: HighImageKind::PreparedQcow2,
            image_preparation: HighImagePreparation::Sysprep,
            connection: HighGuestConnection::Rdp { guest_port: 3389 },
        }
    }

    /// Compatibility profile for manifests created by the original ISO installer adapter.
    pub const fn windows_rdp_legacy_iso() -> Self {
        Self {
            guest_os: HighGuestOs::Windows,
            image_kind: HighImageKind::InstallMediaAndDisk,
            image_preparation: HighImagePreparation::UnattendedInstall,
            connection: HighGuestConnection::Rdp { guest_port: 3389 },
        }
    }

    pub const fn custom_linux_qcow2_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::CustomLinux,
            image_kind: HighImageKind::CloudImage,
            image_preparation: HighImagePreparation::CloudInitSeed,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }

    pub const fn custom_linux_iso_ssh() -> Self {
        Self {
            guest_os: HighGuestOs::CustomLinux,
            image_kind: HighImageKind::InstallMediaAndDisk,
            image_preparation: HighImagePreparation::BestEffortInstall,
            connection: HighGuestConnection::Ssh { guest_port: 22 },
        }
    }
}

/// Common High deployment contract used by all OS adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighVmDeployment {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub base_image: String,
    #[serde(alias = "external_ssh_port")]
    pub external_service_port: u16,
    #[serde(default = "HighOsProfile::ubuntu_ssh")]
    pub profile: HighOsProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_source: Option<HighImageSource>,
}

impl From<HighUbuntuDeployment> for HighVmDeployment {
    fn from(value: HighUbuntuDeployment) -> Self {
        Self {
            command_id: value.command_id,
            trap_id: value.trap_id,
            base_image: value.base_image,
            external_service_port: value.external_ssh_port,
            profile: HighOsProfile::ubuntu_ssh(),
            image_source: None,
        }
    }
}

/// Agent-side transition from one direct trap to a shared external TCP listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpPortGroup {
    pub command_id: Uuid,
    pub listener_port: u16,
    pub members: Vec<TcpPortGroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpPortGroupMember {
    pub trap_id: Uuid,
    pub backend_port: u16,
    pub weight: u8,
    #[serde(default)]
    pub trap_kind: SharedTcpTrapKind,
}

/// The Dispatcher only sees TCP targets; the agent needs this to recreate the correct recipe on
/// a loopback backend port during a direct-listener → shared-listener transition.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SharedTcpTrapKind {
    #[default]
    Kozyavka,
    Pritvoryashka,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command_id: Uuid,
    pub trap_id: Uuid,
    pub success: bool,
    pub detail: String,
}

#[async_trait]
pub trait RemoteBootstrap: Send + Sync {
    /// Execute a prepared, non-interactive installation script on a VPS exactly once.
    async fn install_agent(
        &self,
        target: SshBootstrapTarget,
        script: BootstrapScript,
    ) -> Result<(), CoreError>;
}

/// HFSP stays identical regardless of whether packets travel through Hysteria, TCP, HTTPS or LoRa.
pub const HFSP_MAGIC: [u8; 4] = *b"HFSP";
pub const HFSP_VERSION: u8 = 1;
pub const HFSP_HEADER_LEN: usize = 28;
pub const HFSP_MAX_PAYLOAD_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HfspMessageKind {
    Register = 1,
    Command = 2,
    Telemetry = 3,
    Ack = 4,
    Heartbeat = 5,
    Error = 6,
}

impl TryFrom<u8> for HfspMessageKind {
    type Error = HfspCodecError;

    fn try_from(value: u8) -> Result<Self, HfspCodecError> {
        match value {
            1 => Ok(Self::Register),
            2 => Ok(Self::Command),
            3 => Ok(Self::Telemetry),
            4 => Ok(Self::Ack),
            5 => Ok(Self::Heartbeat),
            6 => Ok(Self::Error),
            _ => Err(HfspCodecError::UnknownMessageKind(value)),
        }
    }
}

/// Wire frame: fixed header followed by an opaque serialized payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfspFrame {
    pub kind: HfspMessageKind,
    pub flags: u16,
    pub sequence: u64,
    pub acknowledgement: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum HfspCodecError {
    #[error("HFSP frame is truncated")]
    Truncated,
    #[error("invalid HFSP magic")]
    InvalidMagic,
    #[error("unsupported HFSP version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown HFSP message kind {0}")]
    UnknownMessageKind(u8),
    #[error("HFSP payload length is invalid")]
    InvalidLength,
    #[error("HFSP payload exceeds the maximum size")]
    PayloadTooLarge,
    #[error("payload serialization failed: {0}")]
    Serialization(String),
}

impl HfspFrame {
    pub fn from_json<T: Serialize>(
        kind: HfspMessageKind,
        sequence: u64,
        acknowledgement: u64,
        payload: &T,
    ) -> Result<Self, HfspCodecError> {
        let payload = serde_json::to_vec(payload)
            .map_err(|error| HfspCodecError::Serialization(error.to_string()))?;
        Ok(Self {
            kind,
            flags: 0,
            sequence,
            acknowledgement,
            payload,
        })
    }

    pub fn payload_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, HfspCodecError> {
        serde_json::from_slice(&self.payload)
            .map_err(|error| HfspCodecError::Serialization(error.to_string()))
    }

    pub fn encode(&self) -> Result<Vec<u8>, HfspCodecError> {
        if self.payload.len() > HFSP_MAX_PAYLOAD_LEN {
            return Err(HfspCodecError::PayloadTooLarge);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| HfspCodecError::PayloadTooLarge)?;
        let mut bytes = Vec::with_capacity(HFSP_HEADER_LEN + self.payload.len());
        bytes.extend_from_slice(&HFSP_MAGIC);
        bytes.push(HFSP_VERSION);
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.acknowledgement.to_be_bytes());
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HfspCodecError> {
        if bytes.len() < HFSP_HEADER_LEN {
            return Err(HfspCodecError::Truncated);
        }
        if bytes[0..4] != HFSP_MAGIC {
            return Err(HfspCodecError::InvalidMagic);
        }
        if bytes[4] != HFSP_VERSION {
            return Err(HfspCodecError::UnsupportedVersion(bytes[4]));
        }
        let kind = HfspMessageKind::try_from(bytes[5])?;
        let flags = u16::from_be_bytes(bytes[6..8].try_into().expect("fixed slice"));
        let sequence = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed slice"));
        let acknowledgement = u64::from_be_bytes(bytes[16..24].try_into().expect("fixed slice"));
        let payload_len =
            u32::from_be_bytes(bytes[24..28].try_into().expect("fixed slice")) as usize;
        if payload_len > HFSP_MAX_PAYLOAD_LEN {
            return Err(HfspCodecError::PayloadTooLarge);
        }
        if bytes.len() != HFSP_HEADER_LEN + payload_len {
            return Err(HfspCodecError::InvalidLength);
        }
        Ok(Self {
            kind,
            flags,
            sequence,
            acknowledgement,
            payload: bytes[HFSP_HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Debug, Error)]
#[error("{transport}: {message}")]
pub struct TransportError {
    pub transport: &'static str,
    pub message: String,
}

/// Replaceable boundary beneath HFSP. Implementations carry complete encoded HFSP packets.
#[async_trait]
pub trait PacketTransport: Send + Sync + fmt::Debug {
    fn name(&self) -> &'static str;
    async fn send(&self, packet: &[u8]) -> Result<(), TransportError>;
    async fn receive(&self) -> Result<Vec<u8>, TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hfsp_round_trip_preserves_header_and_json_payload() {
        let frame = HfspFrame::from_json(
            HfspMessageKind::Telemetry,
            7,
            4,
            &serde_json::json!({"event": "hit"}),
        )
        .unwrap();
        let decoded = HfspFrame::decode(&frame.encode().unwrap()).unwrap();
        assert_eq!(decoded.kind, HfspMessageKind::Telemetry);
        assert_eq!(decoded.sequence, 7);
        assert_eq!(
            decoded.payload_json::<serde_json::Value>().unwrap()["event"],
            "hit"
        );
    }

    #[test]
    fn high_profiles_round_trip_without_losing_adapter_contract() {
        for profile in [
            HighOsProfile::ubuntu_ssh(),
            HighOsProfile::debian_ssh(),
            HighOsProfile::arch_linux_ssh(),
            HighOsProfile::windows_rdp(),
            HighOsProfile::windows_rdp_legacy_iso(),
            HighOsProfile::custom_linux_qcow2_ssh(),
            HighOsProfile::custom_linux_iso_ssh(),
        ] {
            let encoded = serde_json::to_vec(&profile).unwrap();
            assert_eq!(
                serde_json::from_slice::<HighOsProfile>(&encoded).unwrap(),
                profile
            );
        }
    }

    #[test]
    fn legacy_ubuntu_deployment_converts_to_the_generic_contract() {
        let legacy = HighUbuntuDeployment {
            command_id: Uuid::new_v4(),
            trap_id: Uuid::new_v4(),
            base_image: "/images/ubuntu.qcow2".into(),
            external_ssh_port: 2222,
        };
        let generic: HighVmDeployment = legacy.clone().into();
        assert_eq!(generic.command_id, legacy.command_id);
        assert_eq!(generic.trap_id, legacy.trap_id);
        assert_eq!(generic.base_image, legacy.base_image);
        assert_eq!(generic.external_service_port, legacy.external_ssh_port);
        assert_eq!(generic.profile, HighOsProfile::ubuntu_ssh());
        assert!(generic.image_source.is_none());
    }

    #[test]
    fn custom_image_source_round_trip_preserves_integrity_contract() {
        let deployment = HighVmDeployment {
            command_id: Uuid::new_v4(),
            trap_id: Uuid::new_v4(),
            base_image: String::new(),
            external_service_port: 2222,
            profile: HighOsProfile::debian_ssh(),
            image_source: Some(HighImageSource {
                url: "https://images.example.invalid/debian.qcow2".into(),
                sha256: "a".repeat(64),
                format: HighImageFormat::Qcow2,
                architecture: HighImageArchitecture::X86_64,
            }),
        };
        let encoded = serde_json::to_vec(&deployment).unwrap();
        let decoded: HighVmDeployment = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.image_source, deployment.image_source);
        assert_eq!(decoded.profile, HighOsProfile::debian_ssh());

        let unsupported: HighImageArchitecture =
            serde_json::from_str("\"sparc64\"").unwrap();
        assert_eq!(unsupported, HighImageArchitecture::Unknown);
    }
}
