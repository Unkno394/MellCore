use std::{
    path::{Path, PathBuf},
    process::Command,
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
}

impl LibvirtSandboxManager {
    pub fn new(recipe_dir: impl Into<PathBuf>) -> Self {
        Self {
            recipe_dir: recipe_dir.into(),
        }
    }

    pub fn create_and_start(&self, vm: &UbuntuSshVm) -> anyhow::Result<()> {
        if vm.external_ssh_port == 0 {
            anyhow::bail!("High Ubuntu VM needs an external SSH port");
        }
        for script in [
            "launch.sh",
            "publish-ssh.sh",
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
        if let Err(error) = self.run("publish-ssh.sh", &[&instance_id, &port]) {
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

    pub fn is_running(&self, instance_id: Uuid) -> anyhow::Result<bool> {
        let name = format!("hf-high-{instance_id}");
        let output = Command::new("virsh").args(["domstate", &name]).output()?;
        Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "running")
    }

    fn run(&self, script: &str, arguments: &[&str]) -> anyhow::Result<()> {
        let path = self.recipe_dir.join("scripts").join(script);
        let status = Command::new("sh").arg(&path).args(arguments).status()?;
        if !status.success() {
            anyhow::bail!(
                "High VM lifecycle script {} exited with {status}",
                path.display()
            );
        }
        Ok(())
    }
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
}
