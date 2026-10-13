packer {
  required_version = ">= 1.14.0, < 2.0.0"

  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "= 1.1.7"
    }
  }
}

variable "windows_iso_path" {
  type = string
}

variable "windows_iso_sha256" {
  type = string
}

variable "payload_directory" {
  type = string
}

variable "output_directory" {
  type = string
}

variable "build_password" {
  type      = string
  sensitive = true
}

source "qemu" "windows_server_2022" {
  accelerator      = "kvm"
  machine_type     = "pc"
  cpus             = 2
  memory           = 4096
  disk_size        = "48G"
  disk_interface   = "virtio"
  cdrom_interface  = "ide"
  net_device       = "e1000"
  format           = "qcow2"
  disk_compression = true
  disk_discard     = "unmap"
  disk_detect_zeroes = "unmap"

  iso_url      = var.windows_iso_path
  iso_checksum = "sha256:${var.windows_iso_sha256}"

  output_directory = var.output_directory
  vm_name           = "windows-server-prepared.qcow2"
  headless          = true
  vnc_bind_address  = "127.0.0.1"

  cd_files = ["${var.payload_directory}/*"]
  cd_label = "HFBUILDER"
  # Windows Setup reads Autounattend and the small boot-critical viostor
  # driver from A:. All other drivers and installers stay on the payload CD.
  floppy_files = [
    "${var.payload_directory}/Autounattend.xml",
    "${var.payload_directory}/winpe/*",
  ]

  communicator          = "winrm"
  winrm_username        = "hfbuild"
  winrm_password        = var.build_password
  winrm_use_ntlm        = true
  winrm_no_proxy        = true
  winrm_timeout         = "2h"
  pause_before_connecting = "30s"
  host_port_min         = 22980
  host_port_max         = 22999

  # The temporary management listener is reachable only through a loopback-bound
  # QEMU user-mode forward. There is deliberately no RDP forward.
  qemuargs = [
    ["-netdev", "user,id=user.0,restrict=on,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:5985"],
  ]

  boot_wait    = "5s"
  boot_command = ["<spacebar>"]

  shutdown_command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\hf-finalize.ps1"
  shutdown_timeout = "30m"
}

build {
  sources = ["source.qemu.windows_server_2022"]

  provisioner "file" {
    source      = "${var.payload_directory}/finalize.ps1"
    destination = "C:\\Windows\\Temp\\hf-finalize.ps1"
  }

  provisioner "powershell" {
    scripts = [
      "${var.payload_directory}/configure.ps1",
      "${var.payload_directory}/verify.ps1",
    ]
  }
}
