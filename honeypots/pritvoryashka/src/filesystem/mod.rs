pub mod node;
pub mod permissions;

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use node::{Node, NodeKind};
use thiserror::Error;

#[derive(Clone)]
pub struct VirtualFileSystem {
    nodes: BTreeMap<String, Node>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FsError {
    #[error("No such file or directory")]
    NotFound,
    #[error("Not a directory")]
    NotDirectory,
    #[error("Is a directory")]
    IsDirectory,
    #[error("File exists")]
    Exists,
    #[error("Directory not empty")]
    NotEmpty,
    #[error("Operation not permitted")]
    Forbidden,
    #[error("Invalid path")]
    InvalidPath,
    #[error("No space left on device")]
    NoSpace,
}

const MAX_NODES: usize = 4096;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: usize = 4 * 1024 * 1024;

impl VirtualFileSystem {
    pub fn linux(hostname: &str, now: DateTime<Utc>) -> Self {
        let mut fs = Self {
            nodes: BTreeMap::new(),
        };
        for path in [
            "/",
            "/bin",
            "/dev",
            "/etc",
            "/home",
            "/home/admin",
            "/root",
            "/tmp",
            "/usr",
            "/var",
            "/var/log",
            "/var/backups",
        ] {
            fs.nodes.insert(path.into(), Node::directory(now));
        }
        fs.put_file("/etc/hostname", format!("{hostname}\n"), now);
        fs.put_file(
            "/etc/os-release",
            "NAME=\"Ubuntu\"\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\nID=ubuntu\n",
            now,
        );
        fs.put_file(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Administrator:/home/admin:/bin/bash\n",
            now,
        );
        fs.put_file(
            "/home/admin/README.txt",
            "Internal application server.\n",
            now,
        );
        fs
    }

    pub fn normalize(cwd: &str, path: &str) -> Result<String, FsError> {
        if path.as_bytes().contains(&0) || path.len() > 4096 {
            return Err(FsError::InvalidPath);
        }
        let joined = if path.starts_with('/') {
            path.to_owned()
        } else if cwd == "/" {
            format!("/{path}")
        } else {
            format!("{cwd}/{path}")
        };
        let mut parts = Vec::new();
        for part in joined.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                value if value.len() <= 255 => parts.push(value),
                _ => return Err(FsError::InvalidPath),
            }
        }
        Ok(if parts.is_empty() {
            "/".into()
        } else {
            format!("/{}", parts.join("/"))
        })
    }

    pub fn exists(&self, path: &str) -> bool {
        self.nodes.contains_key(path)
    }

    pub fn is_dir(&self, path: &str) -> bool {
        self.nodes.get(path).is_some_and(Node::is_dir)
    }

    pub fn node(&self, path: &str) -> Result<&Node, FsError> {
        self.nodes.get(path).ok_or(FsError::NotFound)
    }

    pub fn read(&self, path: &str) -> Result<&[u8], FsError> {
        match &self.node(path)?.kind {
            NodeKind::File(data) => Ok(data),
            NodeKind::Directory => Err(FsError::IsDirectory),
        }
    }

    pub fn list(&self, path: &str) -> Result<Vec<(String, &Node)>, FsError> {
        if !self.node(path)?.is_dir() {
            return Err(FsError::NotDirectory);
        }
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        Ok(self
            .nodes
            .iter()
            .filter_map(|(candidate, node)| {
                let rest = candidate.strip_prefix(&prefix)?;
                (!rest.is_empty() && !rest.contains('/')).then(|| (rest.to_owned(), node))
            })
            .collect())
    }

    pub fn put_file(&mut self, path: &str, content: impl Into<Vec<u8>>, now: DateTime<Utc>) {
        self.nodes.insert(path.into(), Node::file(content, now));
    }

    fn require_parent(&self, path: &str) -> Result<(), FsError> {
        let parent = path
            .rsplit_once('/')
            .map(|(p, _)| if p.is_empty() { "/" } else { p });
        match parent.and_then(|p| self.nodes.get(p)) {
            Some(node) if node.is_dir() => Ok(()),
            Some(_) => Err(FsError::NotDirectory),
            None => Err(FsError::NotFound),
        }
    }

    pub fn touch(&mut self, path: &str, now: DateTime<Utc>) -> Result<(), FsError> {
        if let Some(node) = self.nodes.get_mut(path) {
            if node.is_dir() {
                return Err(FsError::IsDirectory);
            }
            node.modified_at = now;
            return Ok(());
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(FsError::NoSpace);
        }
        self.require_parent(path)?;
        self.put_file(path, Vec::new(), now);
        Ok(())
    }

    pub fn mkdir(&mut self, path: &str, now: DateTime<Utc>) -> Result<(), FsError> {
        if self.exists(path) {
            return Err(FsError::Exists);
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(FsError::NoSpace);
        }
        self.require_parent(path)?;
        self.nodes.insert(path.into(), Node::directory(now));
        Ok(())
    }

    pub fn write(&mut self, path: &str, data: Vec<u8>, now: DateTime<Utc>) -> Result<(), FsError> {
        if data.len() > MAX_FILE_BYTES {
            return Err(FsError::NoSpace);
        }
        self.require_parent(path)?;
        if self.is_dir(path) {
            return Err(FsError::IsDirectory);
        }
        if !self.exists(path) && self.nodes.len() >= MAX_NODES {
            return Err(FsError::NoSpace);
        }
        let previous = self.nodes.get(path).map_or(0, Node::len);
        let total: usize = self
            .nodes
            .values()
            .filter(|node| !node.is_dir())
            .map(Node::len)
            .sum();
        if total.saturating_sub(previous).saturating_add(data.len()) > MAX_TOTAL_FILE_BYTES {
            return Err(FsError::NoSpace);
        }
        self.put_file(path, data, now);
        Ok(())
    }

    pub fn remove(&mut self, path: &str, recursive: bool) -> Result<(), FsError> {
        if path == "/" || path == "/etc" || path == "/bin" {
            return Err(FsError::Forbidden);
        }
        let node = self.node(path)?;
        if node.is_dir() {
            let prefix = format!("{path}/");
            let has_children = self.nodes.keys().any(|p| p.starts_with(&prefix));
            if has_children && !recursive {
                return Err(FsError::NotEmpty);
            }
            if recursive {
                self.nodes.retain(|p, _| !p.starts_with(&prefix));
            }
        }
        self.nodes.remove(path);
        Ok(())
    }

    pub fn copy(&mut self, source: &str, target: &str, now: DateTime<Utc>) -> Result<(), FsError> {
        let data = self.read(source)?.to_vec();
        self.write(target, data, now)
    }

    pub fn rename(
        &mut self,
        source: &str,
        target: &str,
        now: DateTime<Utc>,
    ) -> Result<(), FsError> {
        self.copy(source, target, now)?;
        self.remove(source, false)
    }

    pub fn all_paths(&self) -> impl Iterator<Item = &str> {
        self.nodes.keys().map(String::as_str)
    }
}
