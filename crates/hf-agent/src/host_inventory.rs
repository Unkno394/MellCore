use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use hf_core::{
    ComponentCapability, CpuInventory, CpuVirtualization, DiskInventory, FilesystemMetric,
    GpuInventory, HighGuestOs, HighImageArchitecture, HighImageKind, HighImageSource,
    HighOsProfile, HostDynamicMetrics, HostInventory, HostStaticInventory, MemoryInventory,
    NetworkInterfaceInventory, NetworkInterfaceMetric, OperatingSystemInventory,
    VirtualizationInventory,
};

const MAX_ITEMS: usize = 64;
const MAX_CPU_FLAGS: usize = 256;
const MAX_TEXT: usize = 256;
// Keep the complete heartbeat, including its HFSP envelope, below Hysteria's UDP limit.
const MAX_TRANSPORT_BYTES: usize = 2 * 1024;

pub struct HostInventoryCollector {
    static_info: HostStaticInventory,
    previous_cpu: Option<(u64, u64)>,
    last_static_refresh: Instant,
}

impl HostInventoryCollector {
    pub fn new() -> Self {
        Self {
            static_info: collect_static(Path::new("/")),
            previous_cpu: None,
            last_static_refresh: Instant::now(),
        }
    }

    pub fn collect(&mut self) -> HostInventory {
        if self.last_static_refresh.elapsed().as_secs() >= 300 {
            self.static_info = collect_static(Path::new("/"));
            self.last_static_refresh = Instant::now();
        }
        let (dynamic, sample) = collect_dynamic(Path::new("/"), self.previous_cpu);
        self.previous_cpu = sample;
        HostInventory {
            schema_version: 1,
            collected_at_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis() as i64)
                .unwrap_or_default(),
            static_info: self.static_info.clone(),
            dynamic,
        }
    }

    /// Keep a heartbeat below a practical UDP datagram without changing the local CLI output.
    /// Only repeated low-priority details are reduced; scalar capability results are retained.
    pub fn collect_for_transport(&mut self) -> Option<HostInventory> {
        let mut inventory = self.collect();
        if serialized_size(&inventory) <= MAX_TRANSPORT_BYTES {
            return Some(inventory);
        }
        inventory.static_info.cpu.flags.truncate(128);
        for interface in &mut inventory.static_info.network {
            interface.addresses.truncate(4);
        }
        inventory.static_info.gpus.truncate(16);
        inventory.static_info.disks.truncate(32);
        inventory.static_info.network.truncate(32);
        inventory.dynamic.network.truncate(32);
        (serialized_size(&inventory) <= MAX_TRANSPORT_BYTES).then_some(inventory)
    }
}

fn serialized_size(inventory: &HostInventory) -> usize {
    serde_json::to_vec(inventory).map_or(usize::MAX, |json| json.len())
}

pub fn render_human(inventory: &HostInventory) -> String {
    let cpu = &inventory.static_info.cpu;
    let memory = &inventory.static_info.memory;
    let virtualization = &inventory.static_info.virtualization;
    let os = &inventory.static_info.operating_system;
    let bytes = |value: Option<u64>| {
        value
            .map(|bytes| format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0))
            .unwrap_or_else(|| "unknown".into())
    };
    let metric = |value: Option<f64>| {
        value
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "unknown".into())
    };
    let capability = |item: &ComponentCapability| match (item.installed, item.usable) {
        (Some(true), Some(true)) => format!("available ({})", known(item.version.as_deref())),
        (Some(true), _) => format!("installed, not usable ({})", known(item.version.as_deref())),
        (Some(false), _) => "not installed".into(),
        _ => "unknown".into(),
    };
    format!(
        concat!(
            "OS: {} {} (kernel {})\n",
            "CPU: {} {} [{}], cores {}, threads {}, reported {} MHz\n",
            "RAM: {} total, {} available; swap: {} total, {} used\n",
            "Load: {}/{}/{}; CPU: {}%; uptime: {} s\n",
            "Storage: {} block devices, {} mounted filesystems\n",
            "GPU: {} device(s); network: {} interface(s)\n",
            "Virtualization: CPU {:?}; KVM {}; QEMU {}; libvirt {}; nested {}; guests: {}"
        ),
        known(os.name.as_deref()),
        known(os.version.as_deref()),
        known(os.kernel_release.as_deref()),
        known(cpu.vendor.as_deref()),
        known(cpu.model.as_deref()),
        cpu.architecture,
        cpu.physical_cores
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        cpu.logical_threads
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        cpu.frequency_mhz
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        bytes(memory.ram_total_bytes),
        bytes(inventory.dynamic.ram_available_bytes),
        bytes(memory.swap_total_bytes),
        bytes(inventory.dynamic.swap_used_bytes),
        metric(inventory.dynamic.load_average_1m),
        metric(inventory.dynamic.load_average_5m),
        metric(inventory.dynamic.load_average_15m),
        inventory
            .dynamic
            .cpu_utilization_percent
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "unknown".into()),
        inventory
            .dynamic
            .uptime_seconds
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        inventory.static_info.disks.len(),
        inventory.dynamic.filesystems.len(),
        inventory.static_info.gpus.len(),
        inventory.static_info.network.len(),
        virtualization.cpu_virtualization,
        capability(&virtualization.kvm),
        capability(&virtualization.qemu),
        capability(&virtualization.libvirt),
        virtualization
            .nested_virtualization
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        if virtualization.guest_architectures.is_empty() {
            "unknown".into()
        } else {
            virtualization.guest_architectures.join(", ")
        }
    )
}

fn known(value: Option<&str>) -> &str {
    value.unwrap_or("unknown")
}

pub fn validate_high_vm_host(
    profile: HighOsProfile,
    source: Option<&HighImageSource>,
    inventory: &HostStaticInventory,
) -> anyhow::Result<()> {
    let requested = source
        .map(|source| source.architecture)
        .unwrap_or(HighImageArchitecture::X86_64);
    let architecture = match requested {
        HighImageArchitecture::X86_64 => "x86_64",
        HighImageArchitecture::Aarch64 => "aarch64",
        HighImageArchitecture::Unknown => {
            anyhow::bail!(
                "HF_HIGH_ERROR code=IMAGE_ARCHITECTURE_UNKNOWN stage=compatibility: image architecture was not established"
            )
        }
    };
    let host_architecture = match inventory.cpu.architecture.as_str() {
        "x86_64" | "amd64" => Some("x86_64"),
        "aarch64" | "arm64" => Some("aarch64"),
        _ => None,
    };
    if host_architecture.is_some_and(|host| host != architecture) {
        anyhow::bail!(
            "HF_HIGH_ERROR code=HOST_ARCHITECTURE_UNSUPPORTED stage=compatibility: KVM host architecture {} cannot run {architecture} guests for {:?}",
            inventory.cpu.architecture,
            profile.guest_os
        );
    }
    if !inventory.virtualization.guest_architectures.is_empty()
        && !inventory
            .virtualization
            .guest_architectures
            .iter()
            .any(|candidate| candidate == architecture)
    {
        anyhow::bail!(
            "HF_HIGH_ERROR code=HOST_ARCHITECTURE_UNSUPPORTED stage=compatibility: host cannot run {architecture} guests for {:?}",
            profile.guest_os
        );
    }
    if inventory.virtualization.kvm.usable == Some(false) {
        anyhow::bail!(
            "HF_HIGH_ERROR code=KVM_UNAVAILABLE stage=compatibility: /dev/kvm is unavailable or not accessible to hf-agent"
        );
    }
    if inventory.virtualization.qemu.installed == Some(false) {
        anyhow::bail!(
            "HF_HIGH_ERROR code=QEMU_UNAVAILABLE stage=compatibility: a compatible QEMU system emulator is not installed"
        );
    }
    if inventory.virtualization.libvirt.installed == Some(false) {
        anyhow::bail!(
            "HF_HIGH_ERROR code=LIBVIRT_UNAVAILABLE stage=compatibility: virsh/libvirt is not installed"
        );
    }
    if profile.image_kind == HighImageKind::InstallMediaAndDisk {
        let minimum_ram = if profile.guest_os == HighGuestOs::Windows {
            5 * 1024 * 1024 * 1024_u64
        } else {
            3 * 1024 * 1024 * 1024_u64
        };
        if inventory
            .memory
            .ram_total_bytes
            .is_some_and(|total| total < minimum_ram)
        {
            anyhow::bail!(
                "HF_HIGH_ERROR code=HOST_MEMORY_INSUFFICIENT stage=compatibility: unattended {:?} installation requires at least {} GiB host RAM",
                profile.guest_os,
                minimum_ram / 1024 / 1024 / 1024
            );
        }
        if inventory
            .cpu
            .logical_threads
            .is_some_and(|threads| threads < 2)
        {
            anyhow::bail!(
                "HF_HIGH_ERROR code=HOST_CPU_INSUFFICIENT stage=compatibility: unattended installation requires at least two logical CPU threads"
            );
        }
    }
    Ok(())
}

pub fn current_static() -> HostStaticInventory {
    collect_static(Path::new("/"))
}

fn collect_static(root: &Path) -> HostStaticInventory {
    let cpuinfo = read(root, "proc/cpuinfo");
    let flags = cpu_flags(cpuinfo.as_deref().unwrap_or_default());
    HostStaticInventory {
        cpu: parse_cpu(cpuinfo.as_deref().unwrap_or_default(), &flags),
        memory: parse_memory(cpuinfo_path(root, "proc/meminfo").as_deref()),
        disks: collect_disks(root),
        gpus: collect_gpus(root),
        network: collect_network(root),
        operating_system: collect_os(root),
        virtualization: collect_virtualization(root, &flags),
    }
}

fn collect_dynamic(
    root: &Path,
    previous_cpu: Option<(u64, u64)>,
) -> (HostDynamicMetrics, Option<(u64, u64)>) {
    let meminfo = parse_meminfo(read(root, "proc/meminfo").as_deref().unwrap_or_default());
    let load = read(root, "proc/loadavg").and_then(|line| parse_three_f64(&line));
    let current_cpu = read(root, "proc/stat").and_then(|stat| parse_cpu_times(&stat));
    let utilization = current_cpu.and_then(|current| {
        let base = previous_cpu.unwrap_or((0, 0));
        let idle = current.0.saturating_sub(base.0);
        let total = current.1.saturating_sub(base.1);
        (total > 0).then(|| ((total - idle) as f64 * 100.0 / total as f64).clamp(0.0, 100.0))
    });
    let total_ram = meminfo.get("MemTotal").copied();
    let available_ram = meminfo.get("MemAvailable").copied();
    let swap_total = meminfo.get("SwapTotal").copied();
    let swap_free = meminfo.get("SwapFree").copied();
    (
        HostDynamicMetrics {
            uptime_seconds: read(root, "proc/uptime")
                .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
                .map(|value| value.max(0.0) as u64),
            load_average_1m: load.map(|item| item.0),
            load_average_5m: load.map(|item| item.1),
            load_average_15m: load.map(|item| item.2),
            cpu_utilization_percent: utilization,
            ram_used_bytes: total_ram
                .zip(available_ram)
                .map(|(total, available)| total.saturating_sub(available)),
            ram_available_bytes: available_ram,
            swap_used_bytes: swap_total
                .zip(swap_free)
                .map(|(total, free)| total.saturating_sub(free)),
            filesystems: if root == Path::new("/") {
                collect_filesystems()
            } else {
                Vec::new()
            },
            network: collect_network_metrics(root),
        },
        current_cpu,
    )
}

fn parse_cpu(cpuinfo: &str, flags: &[String]) -> CpuInventory {
    let fields = parse_first_cpu_fields(cpuinfo);
    let logical_threads = cpuinfo
        .lines()
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(key, _)| key.trim() == "processor")
        })
        .count();
    let physical = cpuinfo
        .split("\n\n")
        .filter_map(|section| {
            let values = parse_key_values(section);
            Some((
                values.get("physical id")?.clone(),
                values.get("core id")?.clone(),
            ))
        })
        .collect::<BTreeSet<_>>();
    CpuInventory {
        vendor: fields
            .get("vendor_id")
            .or_else(|| fields.get("CPU implementer"))
            .cloned(),
        model: fields
            .get("model name")
            .or_else(|| fields.get("Processor"))
            .cloned(),
        architecture: std::env::consts::ARCH.to_string(),
        physical_cores: (!physical.is_empty()).then_some(physical.len() as u32),
        logical_threads: (logical_threads > 0).then_some(logical_threads as u32),
        frequency_mhz: fields
            .get("cpu MHz")
            .and_then(|value| value.parse::<f64>().ok())
            .map(|value| value.round() as u64),
        flags: flags.to_vec(),
    }
}

fn cpu_flags(cpuinfo: &str) -> Vec<String> {
    let mut flags = cpuinfo
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            matches!(key.trim(), "flags" | "Features").then_some(value)
        })
        .flat_map(str::split_whitespace)
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let virtualization_flags = ["svm", "vmx"]
        .into_iter()
        .filter_map(|flag| {
            flags
                .iter()
                .any(|candidate| candidate == flag)
                .then_some(flag.to_owned())
        })
        .collect::<Vec<_>>();
    flags.truncate(MAX_CPU_FLAGS);
    let missing_virtualization_flags = virtualization_flags
        .into_iter()
        .filter(|flag| !flags.contains(flag))
        .collect::<Vec<_>>();
    flags.truncate(MAX_CPU_FLAGS.saturating_sub(missing_virtualization_flags.len()));
    flags.extend(missing_virtualization_flags);
    flags.sort();
    flags
}

fn parse_memory(meminfo: Option<&str>) -> MemoryInventory {
    let values = parse_meminfo(meminfo.unwrap_or_default());
    MemoryInventory {
        ram_total_bytes: values.get("MemTotal").copied(),
        swap_total_bytes: values.get("SwapTotal").copied(),
    }
}

fn parse_meminfo(input: &str) -> BTreeMap<String, u64> {
    input
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
            Some((key.to_string(), kib.saturating_mul(1024)))
        })
        .collect()
}

fn collect_disks(root: &Path) -> Vec<DiskInventory> {
    let directory = root.join("sys/block");
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut result = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("fd") {
                return None;
            }
            let path = entry.path();
            let size_bytes = read_path(path.join("size"))
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(|sectors| sectors.saturating_mul(512));
            if name.starts_with("nbd") && size_bytes == Some(0) {
                return None;
            }
            Some(DiskInventory {
                name,
                model: read_path(path.join("device/model")).map(|value| clean(&value)),
                size_bytes,
                rotational: read_bool(path.join("queue/rotational")),
                removable: read_bool(path.join("removable")),
            })
        })
        .collect::<Vec<_>>();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result.truncate(MAX_ITEMS);
    result
}

fn collect_gpus(root: &Path) -> Vec<GpuInventory> {
    let mut result = Vec::new();
    let drm = root.join("sys/class/drm");
    if let Ok(entries) = fs::read_dir(drm) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("card") || name.contains('-') || result.len() >= MAX_ITEMS {
                continue;
            }
            let device = entry.path().join("device");
            let pci_address = fs::canonicalize(&device)
                .ok()
                .and_then(|path| path.file_name()?.to_str().map(str::to_owned));
            let driver = fs::canonicalize(device.join("driver"))
                .ok()
                .and_then(|path| path.file_name()?.to_str().map(str::to_owned));
            result.push(GpuInventory {
                vendor: read_path(device.join("vendor")).map(|value| clean(&value)),
                model: read_path(device.join("device")).map(|value| clean(&value)),
                pci_address,
                driver,
            });
        }
    }
    if root == Path::new("/") {
        enrich_gpu_models(&mut result);
    }
    result
}

fn enrich_gpu_models(gpus: &mut [GpuInventory]) {
    let Some(output) = command_output("lspci", &["-D", "-nn"]) else {
        return;
    };
    for line in output.lines().filter(|line| {
        line.contains("VGA compatible controller")
            || line.contains("3D controller")
            || line.contains("Display controller")
    }) {
        let Some((address, description)) = line.split_once(' ') else {
            continue;
        };
        if let Some(gpu) = gpus
            .iter_mut()
            .find(|gpu| gpu.pci_address.as_deref() == Some(address))
        {
            gpu.model = Some(clean(description));
        }
    }
}

fn collect_network(root: &Path) -> Vec<NetworkInterfaceInventory> {
    let addresses = if root == Path::new("/") {
        ip_addresses()
    } else {
        BTreeMap::new()
    };
    let directory = root.join("sys/class/net");
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut result = entries
        .flatten()
        .take(MAX_ITEMS)
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            NetworkInterfaceInventory {
                name: name.clone(),
                state: read_path(path.join("operstate")).map(|value| clean(&value)),
                mtu: read_path(path.join("mtu")).and_then(|value| value.trim().parse().ok()),
                speed_mbps: read_path(path.join("speed"))
                    .and_then(|value| value.trim().parse().ok()),
                duplex: read_path(path.join("duplex"))
                    .map(|value| clean(&value).to_ascii_lowercase()),
                addresses: addresses.get(&name).cloned().unwrap_or_default(),
                virtual_interface: fs::canonicalize(&path)
                    .ok()
                    .map(|resolved| resolved.to_string_lossy().contains("/devices/virtual/")),
            }
        })
        .collect::<Vec<_>>();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

fn ip_addresses() -> BTreeMap<String, Vec<String>> {
    let Some(output) = command_output("ip", &["-j", "address", "show"]) else {
        return BTreeMap::new();
    };
    let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(&output) else {
        return BTreeMap::new();
    };
    items
        .into_iter()
        .filter_map(|item| {
            let name = item.get("ifname")?.as_str()?.to_owned();
            let mut values = item
                .get("addr_info")?
                .as_array()?
                .iter()
                .filter_map(|address| {
                    let local = address.get("local")?.as_str()?;
                    let prefix = address.get("prefixlen")?.as_u64()?;
                    Some(format!("{local}/{prefix}"))
                })
                .take(16)
                .collect::<Vec<_>>();
            values.sort();
            Some((name, values))
        })
        .collect()
}

fn collect_network_metrics(root: &Path) -> Vec<NetworkInterfaceMetric> {
    let directory = root.join("sys/class/net");
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut result = entries
        .flatten()
        .take(MAX_ITEMS)
        .map(|entry| {
            let path = entry.path().join("statistics");
            NetworkInterfaceMetric {
                name: entry.file_name().to_string_lossy().into_owned(),
                received_bytes: read_path(path.join("rx_bytes"))
                    .and_then(|value| value.trim().parse().ok()),
                transmitted_bytes: read_path(path.join("tx_bytes"))
                    .and_then(|value| value.trim().parse().ok()),
            }
        })
        .collect::<Vec<_>>();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

fn collect_os(root: &Path) -> OperatingSystemInventory {
    let release = parse_os_release(read(root, "etc/os-release").as_deref().unwrap_or_default());
    OperatingSystemInventory {
        name: release
            .get("PRETTY_NAME")
            .or_else(|| release.get("NAME"))
            .cloned(),
        version: release.get("VERSION_ID").cloned(),
        distribution_id: release.get("ID").cloned(),
        kernel_release: read(root, "proc/sys/kernel/osrelease").map(|value| clean(&value)),
    }
}

fn collect_virtualization(root: &Path, flags: &[String]) -> VirtualizationInventory {
    let cpu_virtualization = cpu_virtualization(flags);
    let kvm_path = root.join("dev/kvm");
    let kvm_installed = kvm_path.exists();
    let kvm_usable = if root == Path::new("/") && kvm_installed {
        Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&kvm_path)
                .is_ok(),
        )
    } else if root == Path::new("/") {
        Some(false)
    } else {
        None
    };
    let qemu_arches = if root == Path::new("/") {
        ["x86_64", "aarch64", "riscv64"]
            .into_iter()
            .filter(|arch| command_exists(&format!("qemu-system-{arch}")))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let qemu_version = qemu_arches
        .first()
        .and_then(|architecture| {
            command_output(&format!("qemu-system-{architecture}"), &["--version"])
        })
        .and_then(|value| value.lines().next().map(clean));
    let virsh_version = (root == Path::new("/"))
        .then(|| command_output("virsh", &["--version"]))
        .flatten()
        .and_then(|value| value.lines().next().map(clean));
    let nested_virtualization = [
        "sys/module/kvm_intel/parameters/nested",
        "sys/module/kvm_amd/parameters/nested",
    ]
    .into_iter()
    .find_map(|path| read(root, path).and_then(|value| parse_enabled(value.trim())));
    VirtualizationInventory {
        cpu_virtualization,
        kvm: ComponentCapability {
            installed: Some(kvm_installed),
            usable: kvm_usable,
            version: read(root, "sys/module/kvm/version").map(|value| clean(&value)),
        },
        qemu: ComponentCapability {
            installed: (root == Path::new("/")).then_some(!qemu_arches.is_empty()),
            usable: (root == Path::new("/")).then_some(!qemu_arches.is_empty()),
            version: qemu_version,
        },
        libvirt: ComponentCapability {
            installed: (root == Path::new("/")).then_some(virsh_version.is_some()),
            usable: if root == Path::new("/") && virsh_version.is_some() {
                Some(
                    Command::new("virsh")
                        .args(["-c", "qemu:///system", "uri"])
                        .output()
                        .is_ok_and(|output| output.status.success()),
                )
            } else if root == Path::new("/") {
                Some(false)
            } else {
                None
            },
            version: virsh_version,
        },
        nested_virtualization,
        guest_architectures: qemu_arches,
    }
}

fn cpu_virtualization(flags: &[String]) -> Option<CpuVirtualization> {
    if flags.iter().any(|flag| flag == "vmx") {
        Some(CpuVirtualization::IntelVtx)
    } else if flags.iter().any(|flag| flag == "svm") {
        Some(CpuVirtualization::AmdV)
    } else {
        None
    }
}

fn collect_filesystems() -> Vec<FilesystemMetric> {
    let Some(output) = command_output("df", &["-B1", "-P", "/"]) else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    output
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 6 {
                return None;
            }
            let mount_point = fields[5].to_owned();
            if !seen.insert(mount_point.clone()) {
                return None;
            }
            Some(FilesystemMetric {
                mount_point,
                total_bytes: fields[1].parse().ok(),
                available_bytes: fields[3].parse().ok(),
            })
        })
        .take(MAX_ITEMS)
        .collect()
}

fn parse_cpu_times(stat: &str) -> Option<(u64, u64)> {
    let fields = stat.lines().next()?.split_whitespace().collect::<Vec<_>>();
    if fields.first().copied() != Some("cpu") {
        return None;
    }
    let values = fields
        .iter()
        .skip(1)
        .filter_map(|value| value.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if values.len() < 4 {
        return None;
    }
    let idle = values[3].saturating_add(values.get(4).copied().unwrap_or_default());
    Some((idle, values.into_iter().fold(0u64, u64::saturating_add)))
}

fn parse_three_f64(input: &str) -> Option<(f64, f64, f64)> {
    let mut values = input.split_whitespace().take(3).map(str::parse::<f64>);
    Some((
        values.next()?.ok()?,
        values.next()?.ok()?,
        values.next()?.ok()?,
    ))
}

fn parse_first_cpu_fields(input: &str) -> BTreeMap<String, String> {
    parse_key_values(input.split("\n\n").next().unwrap_or_default())
}

fn parse_key_values(input: &str) -> BTreeMap<String, String> {
    input
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_owned(), clean(value)))
        })
        .collect()
}

fn parse_os_release(input: &str) -> BTreeMap<String, String> {
    input
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            if key.is_empty() || key.starts_with('#') {
                return None;
            }
            Some((key.to_owned(), clean(value.trim_matches('"'))))
        })
        .collect()
}

fn parse_enabled(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "y" | "yes" | "on" => Some(true),
        "0" | "n" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn read_bool(path: PathBuf) -> Option<bool> {
    read_path(path).and_then(|value| parse_enabled(value.trim()))
}

fn read(root: &Path, relative: &str) -> Option<String> {
    read_path(root.join(relative))
}

fn read_path(path: PathBuf) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn cpuinfo_path(root: &Path, relative: &str) -> Option<String> {
    read(root, relative)
}

fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_TEXT)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn command_exists(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn collect_once() -> anyhow::Result<HostInventory> {
    let mut collector = HostInventoryCollector::new();
    let inventory = collector.collect();
    serde_json::to_vec(&inventory).context("host inventory is not JSON serializable")?;
    Ok(inventory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use uuid::Uuid;

    fn fixture() -> PathBuf {
        let root = std::env::temp_dir().join(format!("hf-host-inventory-{}", Uuid::new_v4()));
        for directory in [
            "proc/sys/kernel",
            "etc",
            "sys/class/net/eth0/statistics",
            "sys/block/nbd0",
            "sys/block/nbd1",
            "sys/block/vda/queue",
            "sys/block/vda/device",
            "sys/module/kvm_intel/parameters",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        let write = |path: &str, value: &str| {
            let path = root.join(path);
            let mut file = fs::File::create(path).unwrap();
            file.write_all(value.as_bytes()).unwrap();
        };
        write(
            "proc/cpuinfo",
            "processor: 0\nvendor_id: GenuineIntel\nmodel name: Test CPU\nphysical id: 0\ncore id: 0\ncpu MHz: 2400.0\nflags: fpu vmx sse\n\nprocessor: 1\nphysical id: 0\ncore id: 0\n",
        );
        write(
            "proc/meminfo",
            "MemTotal: 8192 kB\nMemAvailable: 4096 kB\nSwapTotal: 2048 kB\nSwapFree: 1024 kB\n",
        );
        write("proc/stat", "cpu 10 0 10 80 0 0 0 0\n");
        write("proc/loadavg", "0.10 0.20 0.30 1/2 3\n");
        write("proc/uptime", "42.9 1.0\n");
        write("proc/sys/kernel/osrelease", "6.8.0-test\n");
        write(
            "etc/os-release",
            "ID=debian\nPRETTY_NAME=\"Debian Test\"\nVERSION_ID=12\n",
        );
        write("sys/class/net/eth0/operstate", "up\n");
        write("sys/class/net/eth0/mtu", "1500\n");
        write("sys/class/net/eth0/statistics/rx_bytes", "100\n");
        write("sys/class/net/eth0/statistics/tx_bytes", "200\n");
        write("sys/block/nbd0/size", "0\n");
        write("sys/block/nbd1/size", "4096\n");
        write("sys/block/vda/size", "2048\n");
        write("sys/block/vda/queue/rotational", "0\n");
        write("sys/block/vda/removable", "0\n");
        write("sys/block/vda/device/model", "Virtual Disk\n");
        write("sys/module/kvm_intel/parameters/nested", "Y\n");
        root
    }

    #[test]
    fn collects_linux_fixture_without_sensitive_identifiers() {
        let root = fixture();
        let static_info = collect_static(&root);
        let (dynamic, _) = collect_dynamic(&root, None);
        assert_eq!(static_info.cpu.vendor.as_deref(), Some("GenuineIntel"));
        assert_eq!(static_info.cpu.logical_threads, Some(2));
        assert_eq!(static_info.memory.ram_total_bytes, Some(8 * 1024 * 1024));
        assert_eq!(
            static_info
                .disks
                .iter()
                .find(|disk| disk.name == "vda")
                .and_then(|disk| disk.size_bytes),
            Some(2048 * 512)
        );
        assert_eq!(
            static_info.virtualization.cpu_virtualization,
            Some(CpuVirtualization::IntelVtx)
        );
        assert_eq!(static_info.virtualization.nested_virtualization, Some(true));
        assert_eq!(dynamic.uptime_seconds, Some(42));
        assert_eq!(dynamic.ram_used_bytes, Some(4 * 1024 * 1024));
        assert_eq!(dynamic.network[0].received_bytes, Some(100));
        let json = serde_json::to_string(&(static_info, dynamic)).unwrap();
        assert!(!json.contains("serial"));
        assert!(!json.contains("mac"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detects_amd_v_from_svm_across_cpu_records() {
        let flags = cpu_flags(
            "processor: 0\nvendor_id: AuthenticAMD\n\nprocessor: 1\nflags: fpu sse svm\n",
        );

        assert!(flags.iter().any(|flag| flag == "svm"));
        assert_eq!(cpu_virtualization(&flags), Some(CpuVirtualization::AmdV));
    }

    #[test]
    fn detects_intel_vt_x_from_vmx_across_cpu_records() {
        let flags = cpu_flags(
            "processor: 0\nvendor_id: GenuineIntel\n\nprocessor: 1\nflags: fpu sse VMX\n",
        );

        assert!(flags.iter().any(|flag| flag == "vmx"));
        assert_eq!(
            cpu_virtualization(&flags),
            Some(CpuVirtualization::IntelVtx)
        );
    }

    #[test]
    fn filters_empty_nbd_but_keeps_an_in_use_nbd() {
        let root = fixture();
        let disks = collect_disks(&root);

        assert!(!disks.iter().any(|disk| disk.name == "nbd0"));
        assert_eq!(
            disks
                .iter()
                .find(|disk| disk.name == "nbd1")
                .and_then(|disk| disk.size_bytes),
            Some(4096 * 512)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_known_incompatible_high_host() {
        let mut inventory = HostStaticInventory::default();
        inventory.cpu.architecture = "x86_64".into();
        inventory.virtualization.kvm.usable = Some(true);
        inventory.virtualization.qemu.installed = Some(true);
        inventory.virtualization.libvirt.installed = Some(true);
        inventory.virtualization.guest_architectures = vec!["aarch64".into()];
        let error =
            validate_high_vm_host(HighOsProfile::debian_ssh(), None, &inventory).unwrap_err();
        assert!(error.to_string().contains("HOST_ARCHITECTURE_UNSUPPORTED"));
    }

    #[test]
    fn unattended_iso_install_checks_host_resources() {
        let mut inventory = HostStaticInventory::default();
        inventory.cpu.architecture = "x86_64".into();
        inventory.cpu.logical_threads = Some(2);
        inventory.memory.ram_total_bytes = Some(2 * 1024 * 1024 * 1024);
        inventory.virtualization.kvm.usable = Some(true);
        inventory.virtualization.qemu.installed = Some(true);
        inventory.virtualization.libvirt.installed = Some(true);
        let error =
            validate_high_vm_host(HighOsProfile::ubuntu_iso_ssh(), None, &inventory).unwrap_err();
        assert!(error.to_string().contains("HOST_MEMORY_INSUFFICIENT"));
    }

    #[test]
    fn heartbeat_inventory_is_bounded_for_udp_transport() {
        let mut collector = HostInventoryCollector::new();
        collector.static_info.disks = (0..64)
            .map(|index| DiskInventory {
                name: format!("disk{index}"),
                model: Some("x".repeat(MAX_TEXT)),
                ..DiskInventory::default()
            })
            .collect();
        collector.static_info.network = (0..64)
            .map(|index| NetworkInterfaceInventory {
                name: format!("eth{index}"),
                addresses: (0..16)
                    .map(|address| format!("2001:db8:{index:x}:{address:x}::1/64"))
                    .collect(),
                ..NetworkInterfaceInventory::default()
            })
            .collect();
        collector.static_info.gpus = (0..64)
            .map(|_| GpuInventory {
                vendor: Some("v".repeat(MAX_TEXT)),
                model: Some("m".repeat(MAX_TEXT)),
                driver: Some("d".repeat(MAX_TEXT)),
                ..GpuInventory::default()
            })
            .collect();
        let inventory = collector.collect_for_transport().unwrap();
        assert!(serialized_size(&inventory) <= MAX_TRANSPORT_BYTES);
        assert!(inventory.static_info.disks.len() <= 32);
        assert!(inventory.static_info.network.len() <= 32);
    }
}
