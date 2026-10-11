use chrono::Utc;

use crate::shell::{Shell, ShellOutput};

pub struct SessionState {
    pub shell: Shell,
    pub input: String,
    pub shell_started: bool,
    pub session_ended: bool,
    pub terminal_columns: u32,
    pub terminal_rows: u32,
    pub last_was_cr: bool,
}

impl SessionState {
    pub fn new(hostname: &str, max_input_bytes: usize) -> Self {
        Self {
            shell: Shell::new(hostname, max_input_bytes, Utc::now()),
            input: String::new(),
            shell_started: false,
            session_ended: false,
            terminal_columns: 80,
            terminal_rows: 24,
            last_was_cr: false,
        }
    }

    pub fn execute_line(&mut self) -> ShellOutput {
        let line = std::mem::take(&mut self.input);
        self.shell.execute(&line, Utc::now())
    }
}
