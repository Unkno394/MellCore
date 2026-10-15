use chrono::{DateTime, Utc};

use super::permissions::Permissions;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Node {
    pub kind: NodeKind,
    pub permissions: Permissions,
    pub owner: String,
    #[serde(default = "default_group")]
    pub group: String,
    #[serde(default)]
    pub reported_size: Option<usize>,
    pub modified_at: DateTime<Utc>,
}

fn default_group() -> String {
    "root".into()
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum NodeKind {
    Directory,
    File(Vec<u8>),
    Symlink(String),
}

impl Node {
    pub fn directory(now: DateTime<Utc>) -> Self {
        Self {
            kind: NodeKind::Directory,
            permissions: Permissions::dir(),
            owner: "root".into(),
            group: "root".into(),
            reported_size: None,
            modified_at: now,
        }
    }
    pub fn file(content: impl Into<Vec<u8>>, now: DateTime<Utc>) -> Self {
        Self {
            kind: NodeKind::File(content.into()),
            permissions: Permissions::file(),
            owner: "root".into(),
            group: "root".into(),
            reported_size: None,
            modified_at: now,
        }
    }
    pub fn symlink(target: impl Into<String>, now: DateTime<Utc>) -> Self {
        Self {
            kind: NodeKind::Symlink(target.into()),
            permissions: Permissions(0o777),
            owner: "root".into(),
            group: "root".into(),
            reported_size: None,
            modified_at: now,
        }
    }
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, NodeKind::Directory)
    }
    pub fn len(&self) -> usize {
        if let Some(size) = self.reported_size {
            return size;
        }
        match &self.kind {
            NodeKind::Directory => 4096,
            NodeKind::File(data) => data.len(),
            NodeKind::Symlink(target) => target.len(),
        }
    }

    /// Bytes physically stored in the snapshot, excluding virtual metadata
    /// sizes used to make `ls` and `du` look realistic.
    pub fn stored_len(&self) -> usize {
        match &self.kind {
            NodeKind::Directory => 0,
            NodeKind::File(data) => data.len(),
            NodeKind::Symlink(target) => target.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(&self.kind, NodeKind::File(data) if data.is_empty())
    }
}
