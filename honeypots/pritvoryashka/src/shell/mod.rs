pub mod commands;
pub mod executor;
pub mod model;
pub mod packages;
pub mod parser;
pub mod windows;

pub use executor::{BaitOpen, FsAction, FsActionKind, Shell, ShellOutput};
pub use model::VirtualInteraction;

use crate::{config::Distribution, deception::DeceptionMetrics, filesystem::VirtualFileSystem};
use chrono::{DateTime, Utc};
use hf_core::{BaitFile, VirtualProcess};

pub enum SessionShell {
    Linux(Shell),
    Windows(windows::WindowsShell),
}

impl SessionShell {
    pub fn new(
        hostname: &str,
        username: &str,
        distribution: Distribution,
        max_input_bytes: usize,
        baits: &[BaitFile],
        processes: &[VirtualProcess],
    ) -> Self {
        Self::new_with_scenarios(
            hostname,
            username,
            distribution,
            max_input_bytes,
            baits,
            processes,
            &[],
        )
    }

    pub fn new_with_scenarios(
        hostname: &str,
        username: &str,
        distribution: Distribution,
        max_input_bytes: usize,
        baits: &[BaitFile],
        processes: &[VirtualProcess],
        vulnerability_profiles: &[String],
    ) -> Self {
        if distribution == Distribution::Windows {
            Self::Windows(windows::WindowsShell::new_with_scenarios(
                hostname,
                username,
                max_input_bytes,
                baits,
                processes,
                vulnerability_profiles,
                Utc::now(),
            ))
        } else {
            Self::Linux(Shell::with_profile_and_scenarios(
                hostname,
                username,
                distribution,
                max_input_bytes,
                Utc::now(),
                baits,
                processes,
                vulnerability_profiles,
            ))
        }
    }
    pub fn execute(&mut self, line: &str, now: DateTime<Utc>) -> ShellOutput {
        match self {
            Self::Linux(shell) => shell.execute(line, now),
            Self::Windows(shell) => shell.execute(line, now),
        }
    }
    pub fn prompt(&self) -> String {
        match self {
            Self::Linux(shell) => shell.prompt(),
            Self::Windows(shell) => shell.prompt(),
        }
    }
    pub fn metrics(&self) -> DeceptionMetrics {
        match self {
            Self::Linux(shell) => shell.metrics(),
            Self::Windows(shell) => shell.metrics(),
        }
    }
    pub fn filesystem(&self) -> &VirtualFileSystem {
        match self {
            Self::Linux(shell) => shell.filesystem(),
            Self::Windows(shell) => shell.filesystem(),
        }
    }
    pub fn replace_filesystem(&mut self, fs: VirtualFileSystem) {
        match self {
            Self::Linux(shell) => shell.replace_filesystem(fs),
            Self::Windows(shell) => shell.replace_filesystem(fs),
        }
    }
    pub fn replace_filesystem_preserving_history(&mut self, fs: VirtualFileSystem) {
        match self {
            Self::Linux(shell) => shell.replace_filesystem_preserving_history(fs),
            Self::Windows(shell) => shell.replace_filesystem(fs),
        }
    }
}
