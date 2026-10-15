use crate::config::Distribution;
use chrono::Utc;
use hf_core::{BaitFile, VirtualProcess};
use std::sync::{Arc, Mutex};

use crate::filesystem::persistence::PersistentVirtualFileSystem;
use crate::shell::{FsActionKind, SessionShell, ShellOutput};

pub struct SessionState {
    pub shell: SessionShell,
    pub input: String,
    pub shell_started: bool,
    pub session_ended: bool,
    pub terminal_columns: u32,
    pub terminal_rows: u32,
    pub last_was_cr: bool,
    persistent_filesystem: Option<Arc<Mutex<PersistentVirtualFileSystem>>>,
    hostname: String,
    username: String,
    distribution: Distribution,
    max_input_bytes: usize,
    baits: Vec<BaitFile>,
    virtual_processes: Vec<VirtualProcess>,
    vulnerability_profiles: Vec<String>,
}

impl SessionState {
    pub fn new(hostname: &str, max_input_bytes: usize) -> Self {
        Self::with_baits(hostname, max_input_bytes, &[])
    }

    pub fn with_baits(hostname: &str, max_input_bytes: usize, baits: &[BaitFile]) -> Self {
        Self::with_environment(hostname, max_input_bytes, baits, &[])
    }

    pub fn with_environment(
        hostname: &str,
        max_input_bytes: usize,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
    ) -> Self {
        Self::with_identity(hostname, "admin", max_input_bytes, baits, virtual_processes)
    }

    pub fn with_identity(
        hostname: &str,
        username: &str,
        max_input_bytes: usize,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
    ) -> Self {
        Self::with_profile(
            hostname,
            username,
            Distribution::Ubuntu,
            max_input_bytes,
            baits,
            virtual_processes,
        )
    }

    pub fn with_profile(
        hostname: &str,
        username: &str,
        distribution: Distribution,
        max_input_bytes: usize,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
    ) -> Self {
        Self::with_profile_and_scenarios(
            hostname,
            username,
            distribution,
            max_input_bytes,
            baits,
            virtual_processes,
            &[],
        )
    }

    pub fn with_profile_and_scenarios(
        hostname: &str,
        username: &str,
        distribution: Distribution,
        max_input_bytes: usize,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
        vulnerability_profiles: &[String],
    ) -> Self {
        Self {
            shell: SessionShell::new_with_scenarios(
                hostname,
                username,
                distribution,
                max_input_bytes,
                baits,
                virtual_processes,
                vulnerability_profiles,
            ),
            input: String::new(),
            shell_started: false,
            session_ended: false,
            terminal_columns: 80,
            terminal_rows: 24,
            last_was_cr: false,
            persistent_filesystem: None,
            hostname: hostname.to_owned(),
            username: username.to_owned(),
            distribution,
            max_input_bytes,
            baits: baits.to_vec(),
            virtual_processes: virtual_processes.to_vec(),
            vulnerability_profiles: vulnerability_profiles.to_vec(),
        }
    }

    pub fn with_persistent_environment(
        hostname: &str,
        max_input_bytes: usize,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
        persistent_filesystem: Arc<Mutex<PersistentVirtualFileSystem>>,
        username: &str,
        distribution: Distribution,
    ) -> Self {
        Self::with_persistent_environment_and_scenarios(
            hostname,
            max_input_bytes,
            baits,
            virtual_processes,
            persistent_filesystem,
            username,
            distribution,
            &[],
        )
    }

    pub fn with_persistent_environment_and_scenarios(
        hostname: &str,
        max_input_bytes: usize,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
        persistent_filesystem: Arc<Mutex<PersistentVirtualFileSystem>>,
        username: &str,
        distribution: Distribution,
        vulnerability_profiles: &[String],
    ) -> Self {
        let mut state = Self::with_profile_and_scenarios(
            hostname,
            username,
            distribution,
            max_input_bytes,
            baits,
            virtual_processes,
            vulnerability_profiles,
        );
        if let Ok(filesystem) = persistent_filesystem.lock() {
            state
                .shell
                .replace_filesystem(filesystem.filesystem().clone());
        }
        state.persistent_filesystem = Some(persistent_filesystem);
        state
    }

    pub fn switch_username(&mut self, username: &str) {
        if self.username == username {
            return;
        }
        let filesystem = self.shell.filesystem().clone();
        self.username = username.to_owned();
        self.shell = SessionShell::new_with_scenarios(
            &self.hostname,
            &self.username,
            self.distribution,
            self.max_input_bytes,
            &self.baits,
            &self.virtual_processes,
            &self.vulnerability_profiles,
        );
        self.shell.replace_filesystem(filesystem);
    }

    pub fn execute_line(&mut self) -> ShellOutput {
        let line = std::mem::take(&mut self.input);
        self.execute_command(&line)
    }

    pub fn execute_command(&mut self, line: &str) -> ShellOutput {
        let Some(persistent_filesystem) = self.persistent_filesystem.as_ref() else {
            return self.shell.execute(line, Utc::now());
        };
        let mut filesystem = match persistent_filesystem.lock() {
            Ok(filesystem) => filesystem,
            Err(error) => {
                tracing::error!(%error, "virtual filesystem persistence lock was poisoned");
                return ShellOutput {
                    output: "bash: virtual filesystem is temporarily unavailable\n".into(),
                    exit_status: 1,
                    ..ShellOutput::default()
                };
            }
        };
        self.shell
            .replace_filesystem_preserving_history(filesystem.filesystem().clone());
        let mut output = self.shell.execute(line, Utc::now());
        let should_persist = output
            .fs_actions
            .iter()
            .any(|action| action.kind == FsActionKind::Modified);
        if should_persist {
            if let Err(error) = filesystem.replace(self.shell.filesystem().clone()) {
                tracing::error!(%error, "could not persist virtual filesystem changes");
                output.output = "bash: Input/output error\n".into();
                output.exit_status = 1;
            }
        }
        output
    }

    /// Flush session-local shell history when the SSH channel ends.
    pub fn finish_session(&mut self) {
        let Some(persistent_filesystem) = self.persistent_filesystem.as_ref() else {
            return;
        };
        let mut filesystem = match persistent_filesystem.lock() {
            Ok(filesystem) => filesystem,
            Err(error) => {
                tracing::error!(%error, "virtual filesystem persistence lock was poisoned at session end");
                return;
            }
        };
        self.shell
            .replace_filesystem_preserving_history(filesystem.filesystem().clone());
        if let Err(error) = filesystem.replace(self.shell.filesystem().clone()) {
            tracing::error!(%error, "could not persist shell history at session end");
        }
    }
}
