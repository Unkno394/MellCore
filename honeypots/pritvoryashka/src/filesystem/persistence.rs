use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use super::VirtualFileSystem;

const SNAPSHOT_VERSION: u32 = 1;
const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(serde::Deserialize, serde::Serialize)]
struct Snapshot {
    version: u32,
    filesystem: VirtualFileSystem,
}

pub struct PersistentVirtualFileSystem {
    path: PathBuf,
    filesystem: VirtualFileSystem,
}

impl PersistentVirtualFileSystem {
    pub fn open(path: impl AsRef<Path>, initial: VirtualFileSystem) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let (filesystem, migrated) = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.len() > MAX_SNAPSHOT_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "virtual filesystem snapshot is not a regular file or exceeds its size limit",
                    ));
                }
                let bytes = fs::read(&path)?;
                let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid virtual filesystem snapshot: {error}"),
                    )
                })?;
                if snapshot.version != SNAPSHOT_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported virtual filesystem snapshot version",
                    ));
                }
                if snapshot.filesystem.distribution() != initial.distribution() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "virtual filesystem snapshot belongs to a different Linux distribution",
                    ));
                }
                let mut filesystem = snapshot.filesystem;
                let repaired_directories = filesystem.repair_missing_parent_directories();
                if repaired_directories > 0 {
                    tracing::warn!(
                        repaired_directories,
                        "repaired missing virtual filesystem parent directories from an older snapshot"
                    );
                }
                filesystem
                    .validate_snapshot()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                (filesystem, repaired_directories > 0)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                initial
                    .validate_snapshot()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                (initial, false)
            }
            Err(error) => return Err(error),
        };
        let store = Self { path, filesystem };
        if migrated || !store.path.exists() {
            store.persist()?;
        }
        Ok(store)
    }

    pub fn filesystem(&self) -> &VirtualFileSystem {
        &self.filesystem
    }

    pub fn replace(&mut self, filesystem: VirtualFileSystem) -> io::Result<()> {
        filesystem
            .validate_snapshot()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.persist_filesystem(&filesystem)?;
        self.filesystem = filesystem;
        Ok(())
    }

    fn persist(&self) -> io::Result<()> {
        self.persist_filesystem(&self.filesystem)
    }

    fn persist_filesystem(&self, filesystem: &VirtualFileSystem) -> io::Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot path has no parent directory",
            )
        })?;
        fs::create_dir_all(parent)?;
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if !metadata.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "virtual filesystem snapshot path is not a regular file",
                ));
            }
        }
        let bytes = serde_json::to_vec(&Snapshot {
            version: SNAPSHOT_VERSION,
            filesystem: filesystem.clone(),
        })
        .map_err(|error| {
            io::Error::other(format!(
                "cannot encode virtual filesystem snapshot: {error}"
            ))
        })?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "virtual filesystem snapshot exceeds its size limit",
            ));
        }
        let temporary = parent.join(format!(".vfs-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn open_repairs_missing_parent_directories_in_older_snapshots() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("virtual-filesystem.json");
        let filesystem = VirtualFileSystem::linux("matrix-host", Utc::now());
        let mut serialized = serde_json::to_value(Snapshot {
            version: SNAPSHOT_VERSION,
            filesystem,
        })
        .unwrap();
        serialized["filesystem"]["nodes"]
            .as_object_mut()
            .unwrap()
            .remove("/etc/apt");
        fs::write(&path, serde_json::to_vec(&serialized).unwrap()).unwrap();

        let loaded = PersistentVirtualFileSystem::open(
            &path,
            VirtualFileSystem::linux("matrix-host", Utc::now()),
        )
        .unwrap();
        assert!(loaded.filesystem().is_dir("/etc/apt"));
        assert!(loaded.filesystem().is_dir("/etc/apt/apt.conf.d"));

        let reopened = PersistentVirtualFileSystem::open(
            &path,
            VirtualFileSystem::linux("matrix-host", Utc::now()),
        )
        .unwrap();
        assert!(reopened.filesystem().is_dir("/etc/apt"));
    }
}
