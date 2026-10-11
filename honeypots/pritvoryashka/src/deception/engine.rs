use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use crate::filesystem::VirtualFileSystem;

use super::scenarios::{AUTH_LOG, BACKUP_ENV, SSH_CONFIG};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeceptionMetrics {
    pub stages_reached: u32,
    pub unique_objects: usize,
    pub transitions: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub from: u8,
    pub to: u8,
    pub trigger: &'static str,
    pub artifact: &'static str,
}

#[derive(Clone, Default)]
pub struct DeceptionEngine {
    stage: u8,
    explored: BTreeSet<String>,
    transitions: u32,
}

impl DeceptionEngine {
    pub fn record_object(&mut self, path: &str) {
        self.explored.insert(path.to_owned());
    }

    pub fn observe(
        &mut self,
        command: &str,
        args: &[String],
        fs: &mut VirtualFileSystem,
        now: DateTime<Utc>,
    ) -> Option<Transition> {
        for arg in args {
            if arg.starts_with('/') {
                self.explored.insert(arg.clone());
            }
        }
        let joined = args.join(" ");
        let transition = match self.stage {
            0 if matches!(command, "ls" | "find") && joined.contains("/var/log") => {
                fs.put_file("/var/log/auth.log", AUTH_LOG, now);
                Some(Transition {
                    from: 0,
                    to: 1,
                    trigger: "log_discovery",
                    artifact: "/var/log/auth.log",
                })
            }
            1 if matches!(command, "cat" | "head" | "tail" | "grep")
                && joined.contains("auth.log") =>
            {
                fs.put_file("/var/backups/app.env.bak", BACKUP_ENV, now);
                Some(Transition {
                    from: 1,
                    to: 2,
                    trigger: "auth_log_read",
                    artifact: "/var/backups/app.env.bak",
                })
            }
            2 if matches!(command, "cat" | "head" | "tail" | "grep" | "find")
                && (joined.contains("app.env.bak") || joined.contains("/var/backups")) =>
            {
                if !fs.exists("/home/admin/.ssh") {
                    let _ = fs.mkdir("/home/admin/.ssh", now);
                }
                fs.put_file("/home/admin/.ssh/config", SSH_CONFIG, now);
                Some(Transition {
                    from: 2,
                    to: 3,
                    trigger: "backup_read",
                    artifact: "/home/admin/.ssh/config",
                })
            }
            _ => None,
        };
        if let Some(change) = &transition {
            self.stage = change.to;
            self.transitions = self.transitions.saturating_add(1);
            self.explored.insert(change.artifact.into());
        }
        transition
    }

    pub fn metrics(&self) -> DeceptionMetrics {
        DeceptionMetrics {
            stages_reached: u32::from(self.stage),
            unique_objects: self.explored.len(),
            transitions: self.transitions,
        }
    }
}
