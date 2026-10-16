//! Transport-neutral host inventory reported by `hf-agent`.
//!
//! Identifiers such as disk serial numbers, filesystem UUIDs and interface MAC addresses are
//! intentionally absent from this contract.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostInventory {
    pub schema_version: u16,
    pub collected_at_unix_ms: i64,
    pub static_info: HostStaticInventory,
    pub dynamic: HostDynamicMetrics,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostStaticInventory {
    pub cpu: CpuInventory,
    pub memory: MemoryInventory,
    pub disks: Vec<DiskInventory>,
    pub gpus: Vec<GpuInventory>,
    pub network: Vec<NetworkInterfaceInventory>,
    pub operating_system: OperatingSystemInventory,
    pub virtualization: VirtualizationInventory,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CpuInventory {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub architecture: String,
    pub physical_cores: Option<u32>,
    pub logical_threads: Option<u32>,
    pub frequency_mhz: Option<u64>,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemoryInventory {
    pub ram_total_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DiskInventory {
    pub name: String,
    pub model: Option<String>,
    pub size_bytes: Option<u64>,
    pub rotational: Option<bool>,
    pub removable: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GpuInventory {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub pci_address: Option<String>,
    pub driver: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceInventory {
    pub name: String,
    pub state: Option<String>,
    pub mtu: Option<u32>,
    pub speed_mbps: Option<u64>,
    pub duplex: Option<String>,
    pub addresses: Vec<String>,
    pub virtual_interface: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OperatingSystemInventory {
    pub name: Option<String>,
    pub version: Option<String>,
    pub distribution_id: Option<String>,
    pub kernel_release: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VirtualizationInventory {
    pub cpu_virtualization: Option<CpuVirtualization>,
    pub kvm: ComponentCapability,
    pub qemu: ComponentCapability,
    pub libvirt: ComponentCapability,
    pub nested_virtualization: Option<bool>,
    pub guest_architectures: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CpuVirtualization {
    IntelVtx,
    AmdV,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComponentCapability {
    pub installed: Option<bool>,
    pub usable: Option<bool>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostDynamicMetrics {
    pub uptime_seconds: Option<u64>,
    pub load_average_1m: Option<f64>,
    pub load_average_5m: Option<f64>,
    pub load_average_15m: Option<f64>,
    pub cpu_utilization_percent: Option<f64>,
    pub ram_used_bytes: Option<u64>,
    pub ram_available_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub filesystems: Vec<FilesystemMetric>,
    pub network: Vec<NetworkInterfaceMetric>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FilesystemMetric {
    pub mount_point: String,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceMetric {
    pub name: String,
    pub received_bytes: Option<u64>,
    pub transmitted_bytes: Option<u64>,
}
