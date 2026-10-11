use chrono::{DateTime, Utc};

use super::permissions::Permissions;

#[derive(Clone, Debug)]
pub struct Node {
    pub kind: NodeKind,
    pub permissions: Permissions,
    pub owner: String,
    pub modified_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum NodeKind {
    Directory,
    File(Vec<u8>),
}

impl Node {
    pub fn directory(now: DateTime<Utc>) -> Self {
        Self {
            kind: NodeKind::Directory,
            permissions: Permissions::dir(),
            owner: "root".into(),
            modified_at: now,
        }
    }
    pub fn file(content: impl Into<Vec<u8>>, now: DateTime<Utc>) -> Self {
        Self {
            kind: NodeKind::File(content.into()),
            permissions: Permissions::file(),
            owner: "root".into(),
            modified_at: now,
        }
    }
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, NodeKind::Directory)
    }
    pub fn len(&self) -> usize {
        match &self.kind {
            NodeKind::Directory => 4096,
            NodeKind::File(data) => data.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(&self.kind, NodeKind::File(data) if data.is_empty())
    }
}
