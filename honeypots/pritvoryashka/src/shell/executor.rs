use chrono::{DateTime, Utc};
use hf_core::{BaitFile, BaitImplementation, BaitKind, VirtualProcess};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use crate::{
    config::Distribution,
    deception::{DeceptionEngine, DeceptionMetrics, Transition},
    filesystem::{
        FsError, VirtualFileSystem,
        node::{Node, NodeKind},
    },
};

use super::model::{VirtualCommand, VirtualInteraction, VirtualServer};
use super::packages;
use super::parser;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsActionKind {
    Accessed,
    Modified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsAction {
    pub kind: FsActionKind,
    pub operation: &'static str,
    pub path: String,
}

#[derive(Clone, Debug, Default)]
pub struct ShellOutput {
    pub output: String,
    pub exit_status: u32,
    pub stream_output: bool,
    pub close: bool,
    pub fs_actions: Vec<FsAction>,
    pub deception: Option<Transition>,
    pub virtual_interactions: Vec<VirtualInteraction>,
    pub bait_opens: Vec<BaitOpen>,
    pub vulnerability_attempts: Vec<VulnerabilityAttempt>,
}

#[derive(Clone, Debug)]
pub struct VulnerabilityAttempt {
    pub profile_id: String,
    pub details: Value,
}

#[derive(Clone, Debug)]
pub struct BaitOpen {
    pub id: Uuid,
    pub name: String,
    pub path: String,
    pub operation: String,
    pub kind: BaitKind,
}

#[derive(Clone)]
pub struct Shell {
    cwd: String,
    user: String,
    home: String,
    variables: BTreeMap<String, String>,
    exported_variables: BTreeSet<String>,
    pipe_input: Option<String>,
    hostname: String,
    history: Vec<String>,
    fs: VirtualFileSystem,
    deception: DeceptionEngine,
    virtual_server: VirtualServer,
    max_input_bytes: usize,
    started_at: DateTime<Utc>,
    last_exit_status: u32,
    baits: Vec<BaitFile>,
    virtual_processes: Vec<VirtualProcess>,
    vulnerability_profiles: std::collections::BTreeSet<String>,
}

impl Shell {
    pub fn new(hostname: &str, max_input_bytes: usize, now: DateTime<Utc>) -> Self {
        Self::with_baits(hostname, max_input_bytes, now, &[])
    }

    pub fn with_baits(
        hostname: &str,
        max_input_bytes: usize,
        now: DateTime<Utc>,
        baits: &[BaitFile],
    ) -> Self {
        Self::with_environment(hostname, max_input_bytes, now, baits, &[])
    }

    pub fn with_environment(
        hostname: &str,
        max_input_bytes: usize,
        now: DateTime<Utc>,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
    ) -> Self {
        Self::with_identity(
            hostname,
            "admin",
            max_input_bytes,
            now,
            baits,
            virtual_processes,
        )
    }

    pub fn with_identity(
        hostname: &str,
        username: &str,
        max_input_bytes: usize,
        now: DateTime<Utc>,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
    ) -> Self {
        Self::with_profile(
            hostname,
            username,
            Distribution::Ubuntu,
            max_input_bytes,
            now,
            baits,
            virtual_processes,
        )
    }

    pub fn with_profile(
        hostname: &str,
        username: &str,
        distribution: Distribution,
        max_input_bytes: usize,
        now: DateTime<Utc>,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
    ) -> Self {
        Self::with_profile_and_scenarios(
            hostname,
            username,
            distribution,
            max_input_bytes,
            now,
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
        now: DateTime<Utc>,
        baits: &[BaitFile],
        virtual_processes: &[VirtualProcess],
        vulnerability_profiles: &[String],
    ) -> Self {
        let home = format!("/home/{username}");
        let mut fs = VirtualFileSystem::linux_with_profile(hostname, username, distribution, now);
        let mut virtual_server =
            VirtualServer::new_with_identity(&mut fs, now, virtual_processes, username);
        let vulnerability_profiles = vulnerability_profiles
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        VirtualServer::initialize_vulnerability_scenarios(&vulnerability_profiles, &mut fs, now);
        virtual_server.refresh_packages(&mut fs, now);
        virtual_server.sync_vulnerability_scenarios(&vulnerability_profiles, &mut fs, now);
        configure_virtual_sshd(&mut fs, &vulnerability_profiles, now);
        let mut passwd = fs.read("/etc/passwd").unwrap_or_default().to_vec();
        let mut group = fs.read("/etc/group").unwrap_or_default().to_vec();
        let mut uid = 2000_u32;
        let mut added_users = std::collections::BTreeSet::new();
        let mut users = std::collections::BTreeMap::new();
        for bait in baits.iter().filter(|bait| {
            bait.kind == BaitKind::Account
                && bait.effective_implementation() == BaitImplementation::VirtualAccount
        }) {
            let account = bait.config.account.as_ref();
            let login = account.map_or(bait.name.as_str(), |account| account.login.as_str());
            users.insert(login.to_owned(), Some(bait));
        }
        for username in virtual_processes
            .iter()
            .map(|process| process.user.as_str())
        {
            users.entry(username.to_owned()).or_insert(None);
        }
        for (username, account_bait) in users {
            if !added_users.insert(username.to_ascii_lowercase()) {
                continue;
            }
            let prefix = format!("{username}:");
            if !passwd
                .split(|byte| *byte == b'\n')
                .any(|line| line.starts_with(prefix.as_bytes()))
            {
                let account = account_bait.and_then(|bait| bait.config.account.as_ref());
                let user_uid = account.and_then(|account| account.uid).unwrap_or(uid);
                let home = account
                    .and_then(|account| account.home_directory.as_deref())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("/home/{username}"));
                let shell = account
                    .and_then(|account| account.shell)
                    .unwrap_or_default()
                    .as_str();
                passwd.extend_from_slice(
                    format!("{username}:x:{user_uid}:{user_uid}:Service account:{home}:{shell}\n")
                        .as_bytes(),
                );
                let has_gid = String::from_utf8_lossy(&group).lines().any(|line| {
                    line.split(':')
                        .nth(2)
                        .and_then(|gid| gid.parse::<u32>().ok())
                        == Some(user_uid)
                });
                if !has_gid {
                    group.extend_from_slice(format!("{username}:x:{user_uid}:\n").as_bytes());
                }
                ensure_virtual_directory(&mut fs, &home, now);
                uid = uid.max(user_uid.saturating_add(1));
            }
        }
        if !passwd.is_empty() {
            fs.write("/etc/passwd", passwd, now)
                .expect("the virtual passwd file has a valid parent");
        }
        if !group.is_empty() {
            fs.write("/etc/group", group, now)
                .expect("the virtual group file has a valid parent");
        }
        let started_at = virtual_server.booted_at();
        let history = VirtualServer::initial_history();
        virtual_server.sync_history(&mut fs, &history, now);
        for bait in baits {
            if let Some(path) = bait.path.as_deref() {
                fs.install_bait(bait, path, now)
                    .expect("bait file was validated at startup");
            }
        }
        Self {
            cwd: home.clone(),
            user: username.into(),
            home,
            variables: BTreeMap::new(),
            exported_variables: BTreeSet::new(),
            pipe_input: None,
            hostname: hostname.into(),
            history,
            fs,
            deception: DeceptionEngine::default(),
            virtual_server,
            max_input_bytes,
            started_at,
            last_exit_status: 0,
            baits: baits.to_vec(),
            virtual_processes: virtual_processes.to_vec(),
            vulnerability_profiles,
        }
    }

    pub fn prompt(&self) -> String {
        let shown = self.cwd.strip_prefix(&self.home).map_or_else(
            || self.cwd.clone(),
            |rest| {
                if rest.is_empty() {
                    "~".into()
                } else {
                    format!("~{rest}")
                }
            },
        );
        format!("{}@{}:{}$ ", self.user, self.hostname, shown)
    }

    pub fn metrics(&self) -> DeceptionMetrics {
        self.deception.metrics()
    }

    pub fn filesystem(&self) -> &VirtualFileSystem {
        &self.fs
    }

    pub fn replace_filesystem(&mut self, filesystem: VirtualFileSystem) {
        let now = Utc::now();
        self.fs = filesystem;
        let baseline = VirtualFileSystem::linux_with_profile(
            &self.hostname,
            &self.user,
            self.fs.distribution(),
            now,
        );
        self.fs.upgrade_linux_layout(&baseline, now);
        if self.fs.distribution().is_apt() && !self.fs.exists("/var/lib/dpkg/status") {
            if !self.fs.exists("/var/lib/dpkg") {
                let _ = self.fs.mkdir("/var/lib/dpkg", now);
            }
            if !self.fs.exists("/usr/bin") {
                let _ = self.fs.mkdir("/usr/bin", now);
            }
            self.fs.put_file("/var/lib/dpkg/status", "Package: postgresql\nStatus: install ok installed\nVersion: 14+238\nArchitecture: amd64\nDescription: object-relational SQL database\n\n", now);
            self.fs
                .put_file("/usr/bin/psql", "ELF virtual PostgreSQL client\n", now);
        }
        if self
            .fs
            .distribution()
            .linux_profile()
            .is_some_and(|profile| profile.package_manager == crate::config::PackageManager::Pacman)
        {
            let result = if packages::arch_local_packages(&self.fs).is_empty() {
                packages::seed_arch_base(&mut self.fs, now)
            } else {
                packages::migrate_arch_base(&mut self.fs, now)
            };
            if let Err(error) = result {
                tracing::warn!(%error, "could not migrate persisted Arch package image");
            }
        }
        self.virtual_server.refresh_packages(&mut self.fs, now);
        self.virtual_server.sync_vulnerability_scenarios(
            &self.vulnerability_profiles,
            &mut self.fs,
            now,
        );
        configure_virtual_sshd(&mut self.fs, &self.vulnerability_profiles, now);
        self.virtual_server.sync_proc(&mut self.fs, now);
        if let Ok(contents) = self.fs.read(&format!("{}/.bash_history", self.home)) {
            let history: Vec<String> = String::from_utf8_lossy(contents)
                .lines()
                .map(str::to_owned)
                .collect();
            if !history.is_empty() {
                self.history = history.into_iter().rev().take(1000).collect();
                self.history.reverse();
            }
        }
    }

    pub fn replace_filesystem_preserving_history(&mut self, filesystem: VirtualFileSystem) {
        let history = self.history.clone();
        self.replace_filesystem(filesystem);
        self.history = history;
        self.virtual_server
            .sync_history(&mut self.fs, &self.history, Utc::now());
    }

    fn path(&self, raw: &str) -> Result<String, FsError> {
        let expanded = if raw == "~" {
            self.home.clone()
        } else if let Some(rest) = raw.strip_prefix("~/") {
            format!("{}/{rest}", self.home)
        } else {
            raw.to_owned()
        };
        VirtualFileSystem::normalize(&self.cwd, &expanded)
    }

    pub fn execute(&mut self, line: &str, now: DateTime<Utc>) -> ShellOutput {
        let line = line.trim_end_matches(['\r', '\n']);
        // procfs counters and uptime are live kernel views. Refresh the
        // synthetic snapshot before a command can read those paths.
        self.virtual_server.sync_proc(&mut self.fs, now);
        if !line.trim().is_empty() {
            self.history.push(line.to_owned());
            if self.history.len() > 1000 {
                self.history.remove(0);
            }
            self.virtual_server
                .sync_history(&mut self.fs, &self.history, now);
        }
        let result = self.execute_script(line, now);
        self.last_exit_status = result.exit_status;
        result
    }

    fn execute_script(&mut self, line: &str, now: DateTime<Utc>) -> ShellOutput {
        let words = match parser::parse_shell(line, self.max_input_bytes) {
            Ok(words) => words,
            Err(error) => return failure(format!("bash: {error}\n")),
        };
        self.execute_tokens(words, now)
    }

    fn execute_tokens(&mut self, words: Vec<String>, now: DateTime<Utc>) -> ShellOutput {
        let result = self.execute_tokens_inner(words, now);
        self.last_exit_status = result.exit_status;
        result
    }

    fn execute_tokens_inner(&mut self, words: Vec<String>, now: DateTime<Utc>) -> ShellOutput {
        if let Some(kind) = words.first().map(String::as_str)
            && matches!(kind, "for" | "if")
        {
            let Some(end) = find_control_end(&words, 0) else {
                return failure(format!(
                    "bash: syntax error: expected '{}'\n",
                    if kind == "for" { "done" } else { "fi" }
                ));
            };
            let block = words[..=end].to_vec();
            let mut combined = if kind == "for" {
                self.execute_for(&block, now)
            } else {
                self.execute_if(&block, now)
            };
            let suffix = words[end + 1..]
                .iter()
                .skip_while(|word| word.as_str() == ";")
                .cloned()
                .collect::<Vec<_>>();
            if !suffix.is_empty() {
                append_shell_output(&mut combined, self.execute_tokens(suffix, now));
            }
            return combined;
        }
        if let Some(start) = (1..words.len()).find(|index| {
            words[*index - 1] == ";" && matches!(words[*index].as_str(), "for" | "if")
        }) {
            let Some(end) = find_control_end(&words, start) else {
                return failure("bash: syntax error: expected a matching control keyword\n");
            };
            let mut combined = ShellOutput::default();
            let prefix = words[..start - 1].to_vec();
            if !prefix.is_empty() {
                append_shell_output(&mut combined, self.execute_tokens(prefix, now));
            }
            let control = words[start..=end].to_vec();
            append_shell_output(&mut combined, self.execute_tokens(control, now));
            let suffix = words[end + 1..]
                .iter()
                .skip_while(|word| word.as_str() == ";")
                .cloned()
                .collect::<Vec<_>>();
            if !suffix.is_empty() {
                append_shell_output(&mut combined, self.execute_tokens(suffix, now));
            }
            return combined;
        }
        if words
            .iter()
            .any(|word| matches!(word.as_str(), "|" | "&&" | "||" | ";"))
        {
            return self.execute_compound(words, now);
        }
        self.execute_words(words, now)
    }

    fn execute_for(&mut self, words: &[String], now: DateTime<Utc>) -> ShellOutput {
        if words.len() < 7 || !valid_variable_name(&words[1]) || words[2] != "in" {
            return failure("bash: syntax error near unexpected token `for'\n");
        }
        let Some(do_index) = words.iter().position(|word| word == "do") else {
            return failure("bash: syntax error: expected 'do'\n");
        };
        let Some(done_index) = words.iter().rposition(|word| word == "done") else {
            return failure("bash: syntax error: expected 'done'\n");
        };
        if done_index <= do_index {
            return failure("bash: syntax error: expected 'done'\n");
        }
        let values = words[3..do_index]
            .iter()
            .filter(|word| word.as_str() != ";")
            .flat_map(|word| {
                let value = self.expand_value(word.strip_prefix("\u{001f}").unwrap_or(word));
                expand_brace_sequence(&value).unwrap_or_else(|| vec![value])
            })
            .collect::<Vec<_>>();
        if values.len() > 256 {
            return failure("bash: loop has too many iterations\n");
        }
        let mut body = words[do_index + 1..done_index].to_vec();
        while body.first().is_some_and(|word| word == ";") {
            body.remove(0);
        }
        while body.last().is_some_and(|word| word == ";") {
            body.pop();
        }
        let mut combined = ShellOutput::default();
        for value in values {
            self.variables.insert(words[1].clone(), value);
            let result = self.execute_tokens(body.clone(), now);
            append_shell_output(&mut combined, result);
            if combined.close {
                break;
            }
        }
        combined
    }

    fn execute_if(&mut self, words: &[String], now: DateTime<Utc>) -> ShellOutput {
        let Some(then_index) = words.iter().position(|word| word == "then") else {
            return failure("bash: syntax error: expected 'then'\n");
        };
        let Some(fi_index) = words.iter().rposition(|word| word == "fi") else {
            return failure("bash: syntax error: expected 'fi'\n");
        };
        if then_index <= 1 || fi_index <= then_index {
            return failure("bash: syntax error near unexpected token `if'\n");
        }
        let condition = words[1..then_index]
            .iter()
            .filter(|word| word.as_str() != ";")
            .cloned()
            .collect::<Vec<_>>();
        let condition_result = self.evaluate_test(&condition);
        let else_index = find_top_level_else(words, then_index + 1, fi_index);
        let (start, end) = match (condition_result, else_index) {
            (true, _) => (then_index + 1, else_index.unwrap_or(fi_index)),
            (false, Some(index)) => (index + 1, fi_index),
            (false, None) => return ShellOutput::default(),
        };
        let mut body = words[start..end].to_vec();
        while body.first().is_some_and(|word| word == ";") {
            body.remove(0);
        }
        while body.last().is_some_and(|word| word == ";") {
            body.pop();
        }
        self.execute_tokens(body, now)
    }

    fn evaluate_test(&self, words: &[String]) -> bool {
        let mut values = words
            .iter()
            .map(|word| self.expand_value(word.strip_prefix("\u{001f}").unwrap_or(word)))
            .collect::<Vec<_>>();
        if values.first().is_some_and(|word| word == "[") {
            values.remove(0);
        } else if values.first().is_some_and(|word| word == "test") {
            values.remove(0);
        }
        if values.last().is_some_and(|word| word == "]") {
            values.pop();
        }
        match values.as_slice() {
            [value] if value == "true" => true,
            [value] if value == "false" => false,
            [flag, path] if flag == "-d" => self.path(path).is_ok_and(|path| self.fs.is_dir(&path)),
            [flag, path] if flag == "-e" || flag == "-a" => {
                self.path(path).is_ok_and(|path| self.fs.exists(&path))
            }
            [flag, path] if flag == "-f" => self
                .path(path)
                .is_ok_and(|path| self.fs.node(&path).is_ok_and(|node| !node.is_dir())),
            [flag, path] if flag == "-r" => self
                .path(path)
                .is_ok_and(|path| self.fs.authorize_read(&path, &self.user).is_ok()),
            [flag, path] if flag == "-w" => self
                .path(path)
                .is_ok_and(|path| self.fs.authorize_write(&path, &self.user).is_ok()),
            [left, operator, right] => match operator.as_str() {
                "=" | "==" => left == right,
                "!=" => left != right,
                "-eq" => numeric_test(left, right, |a, b| a == b),
                "-ne" => numeric_test(left, right, |a, b| a != b),
                "-lt" => numeric_test(left, right, |a, b| a < b),
                "-le" => numeric_test(left, right, |a, b| a <= b),
                "-gt" => numeric_test(left, right, |a, b| a > b),
                "-ge" => numeric_test(left, right, |a, b| a >= b),
                _ => false,
            },
            [flag, value] if flag == "-n" => !value.is_empty(),
            [flag, value] if flag == "-z" => value.is_empty(),
            [negation, rest @ ..] if negation == "!" => !self.evaluate_test(rest),
            [value] => !value.is_empty(),
            [] => false,
            _ => false,
        }
    }

    fn test_command(&self, command: &str, args: &[String]) -> ShellOutput {
        let mut values = args.to_vec();
        if command == "[" {
            if values.last().is_none_or(|word| word != "]") {
                return failure("bash: [: missing `]'\n");
            }
            values.pop();
        }
        if self.evaluate_test(&values) {
            success("")
        } else {
            failure("")
        }
    }

    fn execute_compound(&mut self, words: Vec<String>, now: DateTime<Utc>) -> ShellOutput {
        let mut chains: Vec<(Vec<Vec<String>>, String)> = Vec::new();
        let mut pipeline = Vec::new();
        let mut command = Vec::new();
        for word in words {
            if word == "|" {
                if command.is_empty() {
                    return failure("bash: syntax error near unexpected token\n");
                }
                pipeline.push(std::mem::take(&mut command));
            } else if matches!(word.as_str(), "&&" | "||" | ";") {
                if command.is_empty() {
                    return failure("bash: syntax error near unexpected token\n");
                }
                pipeline.push(std::mem::take(&mut command));
                chains.push((std::mem::take(&mut pipeline), word));
            } else {
                command.push(word);
            }
        }
        if command.is_empty() {
            return failure("bash: syntax error near unexpected token `newline'\n");
        }
        pipeline.push(command);
        chains.push((pipeline, String::new()));
        let mut combined = ShellOutput::default();
        let mut previous_op = String::new();
        let mut last_status = 0;
        for (pipeline, next_op) in chains {
            let should_execute = match previous_op.as_str() {
                "&&" => last_status == 0,
                "||" => last_status != 0,
                _ => true,
            };
            if should_execute {
                let mut pipe_output = String::new();
                let pipeline_status = self.last_exit_status;
                for (index, words) in pipeline.into_iter().enumerate() {
                    // Bash expands parameters in every pipeline command before execution.
                    self.last_exit_status = pipeline_status;
                    if index > 0 {
                        self.pipe_input = Some(pipe_output);
                    }
                    let mut result = self.execute_words(words, now);
                    pipe_output = result.output.clone();
                    last_status = result.exit_status;
                    combined.close |= result.close;
                    combined.stream_output |= result.stream_output;
                    combined.fs_actions.append(&mut result.fs_actions);
                    combined
                        .virtual_interactions
                        .append(&mut result.virtual_interactions);
                    combined.bait_opens.append(&mut result.bait_opens);
                    combined
                        .vulnerability_attempts
                        .append(&mut result.vulnerability_attempts);
                    if result.deception.is_some() {
                        combined.deception = result.deception;
                    }
                    if combined.close {
                        break;
                    }
                }
                self.pipe_input = None;
                self.last_exit_status = last_status;
                combined.output.push_str(&pipe_output);
                combined.exit_status = last_status;
            }
            previous_op = next_op;
            if combined.close {
                break;
            }
        }
        combined
    }

    fn execute_words(&mut self, words: Vec<String>, now: DateTime<Utc>) -> ShellOutput {
        let result = self.execute_words_inner(words, now);
        self.last_exit_status = result.exit_status;
        result
    }

    fn execute_words_inner(&mut self, mut words: Vec<String>, now: DateTime<Utc>) -> ShellOutput {
        let redirect = match words.iter().position(|word| word == ">" || word == ">>") {
            Some(index) if index + 2 == words.len() && index > 0 => {
                let append = words[index] == ">>";
                let target = words.pop().expect("validated redirect target");
                words.pop();
                Some((append, target))
            }
            Some(_) => return failure("bash: syntax error near unexpected token `newline'\n"),
            None => None,
        };
        for word in &mut words {
            if word.starts_with('\u{001f}') {
                word.remove(0);
            }
        }
        let redirect = redirect.map(|(append, target)| (append, self.expand_value(&target)));
        words = self.expand_environment(&words);
        let mut assignment_count = 0;
        while let Some(word) = words.get(assignment_count) {
            let Some((name, value)) = word.split_once('=') else {
                break;
            };
            if !valid_variable_name(name) {
                break;
            }
            let value = self.expand_value(value);
            self.variables.insert(name.to_owned(), value);
            assignment_count += 1;
        }
        if assignment_count == words.len() {
            return ShellOutput::default();
        }
        if assignment_count > 0 {
            words.drain(..assignment_count);
        }
        let Some((command, args)) = words.split_first() else {
            return ShellOutput::default();
        };
        let executable = if command.starts_with('/') && self.fs.is_executable(command) {
            command.rsplit('/').next().unwrap_or(command)
        } else {
            command.as_str()
        };
        if !is_shell_builtin(executable) && self.executable_path(executable).is_none() {
            return failure(format!("bash: {command}: command not found\n"));
        }
        if executable == "psql"
            && (!packages::installed(&self.fs, "postgresql") || !self.fs.exists("/usr/bin/psql"))
        {
            return failure("bash: psql: command not found\n");
        }
        let deception = self.deception.observe(executable, args, &mut self.fs, now);
        let virtual_command =
            self.virtual_server
                .execute(executable, args, &self.cwd, &mut self.fs, now);
        let mut result = if let Some(result) = virtual_command {
            shell_output(result)
        } else {
            match executable {
                "pwd" => success(format!("{}\n", self.cwd)),
                "cd" => self.cd(args),
                "ls" => self.ls(args),
                "cat" => self.cat(args),
                "echo" => self.echo(args),
                "whoami" => success(format!("{}\n", self.user)),
                "id" => self.id(args),
                "true" => success(""),
                "false" => failure(""),
                "test" | "[" => self.test_command(executable, args),
                "printf" => self.printf(args),
                "export" => self.export(args),
                "unset" => self.unset(args),
                "command" => self.command_builtin(args, now),
                "type" => self.type_command(args),
                "umask" => self.umask(args),
                "bash" | "sh" | "dash" | "rbash" => self.shell_interpreter(executable, args, now),
                "sudo" => self.sudo(args, now),
                "su" => self.su(args, now),
                "apt" | "apt-get" if self.fs.distribution().is_apt() => {
                    self.apt(args, self.user == "root", now)
                }
                "pacman" if !self.fs.distribution().is_apt() => {
                    self.pacman(args, self.user == "root", now)
                }
                "dpkg" | "dpkg-query" if self.fs.distribution().is_apt() => self.dpkg(args),
                "which" => self.which(args),
                "run-parts" if self.fs.distribution().is_apt() => {
                    if args.iter().any(|arg| arg == "--version") {
                        success("run-parts (debianutils) 5.23.2\n")
                    } else if args.iter().any(|arg| arg == "--help" || arg == "-h") {
                        success("Usage: run-parts [OPTION]... DIRECTORY\n")
                    } else if let Some(directory) = args.iter().find(|arg| !arg.starts_with('-')) {
                        match self.path(directory).and_then(|path| self.fs.list(&path)) {
                            Ok(entries) => {
                                let scripts = entries
                                    .into_iter()
                                    .filter(|(name, node)| {
                                        !node.is_dir()
                                            && !name.starts_with('.')
                                            && name.chars().all(|ch| {
                                                ch.is_ascii_alphanumeric()
                                                    || matches!(ch, '_' | '-')
                                            })
                                    })
                                    .map(|(name, _)| name)
                                    .collect::<Vec<_>>();
                                success(format!(
                                    "{}",
                                    if args.iter().any(|arg| arg == "--test") {
                                        scripts
                                            .into_iter()
                                            .map(|name| format!("{directory}/{name}\n"))
                                            .collect::<Vec<_>>()
                                            .concat()
                                    } else {
                                        String::new()
                                    }
                                ))
                            }
                            Err(_) => failure(format!(
                                "run-parts: cannot open directory {directory}: No such file or directory\n"
                            )),
                        }
                    } else {
                        failure("run-parts: missing operand\n")
                    }
                }
                "nologin" if self.fs.distribution().is_apt() => {
                    failure("This account is currently not available.\n")
                }
                "containerd"
                    if self
                        .fs
                        .distribution()
                        .linux_profile()
                        .is_some_and(|profile| !profile.containerd_version_output.is_empty()) =>
                {
                    if args.iter().any(|arg| arg == "--version" || arg == "-v") {
                        success(
                            self.fs
                                .distribution()
                                .linux_profile()
                                .unwrap()
                                .containerd_version_output,
                        )
                    } else {
                        failure(
                            "containerd: unable to access containerd socket /run/containerd/containerd.sock\n",
                        )
                    }
                }
                "dockerd"
                    if self
                        .fs
                        .distribution()
                        .linux_profile()
                        .is_some_and(|profile| !profile.dockerd_version_output.is_empty()) =>
                {
                    if args.iter().any(|arg| arg == "--version" || arg == "-v") {
                        success(
                            self.fs
                                .distribution()
                                .linux_profile()
                                .unwrap()
                                .dockerd_version_output,
                        )
                    } else {
                        failure("failed to start daemon: permission denied\n")
                    }
                }
                "dbus-daemon"
                    if self
                        .fs
                        .distribution()
                        .linux_profile()
                        .is_some_and(|profile| !profile.dbus_version_output.is_empty()) =>
                {
                    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
                        success(
                            self.fs
                                .distribution()
                                .linux_profile()
                                .unwrap()
                                .dbus_version_output,
                        )
                    } else {
                        failure("Failed to start message bus: Operation not permitted\n")
                    }
                }
                "ssh" if self.fs.distribution().is_apt() => {
                    if args.iter().any(|arg| arg == "-V" || arg == "-version") {
                        success("OpenSSH_10.0p1 Debian-7+deb13u4, OpenSSL 3.5.4 30 Sep 2025\n")
                    } else {
                        failure("ssh: connect to host: Network is unreachable\n")
                    }
                }
                "ssh-add" if self.fs.distribution().is_apt() => {
                    failure("Could not open a connection to your authentication agent.\n")
                }
                "ssh-agent" if self.fs.distribution().is_apt() => {
                    if args.iter().any(|arg| arg == "-V" || arg == "--version") {
                        success("ssh-agent: OpenSSH_10.0p1\n")
                    } else {
                        success(
                            "SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.1312; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=1313; export SSH_AGENT_PID;\necho Agent pid 1313;\n",
                        )
                    }
                }
                "ssh-keygen" if self.fs.distribution().is_apt() => {
                    if args.iter().any(|arg| arg == "-V" || arg == "--version") {
                        success("ssh-keygen: OpenSSH_10.0p1\n")
                    } else {
                        failure(
                            "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-t dsa | ecdsa | ed25519 | rsa] [-f output_keyfile]\n",
                        )
                    }
                }
                "ssh-keyscan" if self.fs.distribution().is_apt() => {
                    failure("ssh-keyscan: no host specified\n")
                }
                "scp" | "sftp" if self.fs.distribution().is_apt() => {
                    failure(format!("{executable}: Connection closed\n"))
                }
                "apt-cache" if self.fs.distribution().is_apt() => self.apt_cache(args),
                "hostnamectl" => self.hostnamectl(args, now),
                "update-alternatives" if self.fs.distribution().is_apt() => {
                    self.update_alternatives(args)
                }
                "getent" => self.getent(args),
                "groups" => self.groups(args),
                "stat" => self.stat(args),
                "readlink" => self.readlink(args),
                "chmod" => self.chmod(args, now),
                "nginx" => self.nginx(args),
                "sshd" => self.sshd(args),
                "redis-server" => self.redis_server(args),
                "valkey-server" => self.valkey_server(args),
                "redis-cli" | "valkey-cli" => self.redis_cli(executable, args, now),
                "mysql" | "mariadb" => self.mysql_cli(args),
                "ftp" => self.ftp_client(args),
                "curl" => self.curl(args),
                "vim" => self.vim(args),
                "nano" => self.nano(args),
                "uname" => self.uname(args),
                "hostname" => self.hostname_command(args),
                "date" => success(format!("{}\n", now.format("%a %b %e %T UTC %Y"))),
                "uptime" => self.uptime(now),
                "nproc" => self.nproc(args),
                "lsblk" => self.lsblk(args),
                "service" => self.service(args, now),
                "who" | "w" | "users" => self.login_users(executable, args, now),
                "ping" => self.ping(args),
                "lsb_release" => self.lsb_release(args),
                "df" => self.df(args),
                "du" => self.du(args),
                "free" => self.free(args),
                "file" => self.file(args),
                "env" => self.env(args),
                "printenv" => self.printenv(args),
                "lscpu" => self.lscpu(args),
                "tr" => self.tr(args),
                "seq" => self.seq(args),
                "wc" => self.wc(args),
                "sort" => self.sort(args),
                "rmdir" => self.rmdir(args),
                "mount" => self.mount(args),
                "findmnt" => self.findmnt(args),
                "history" => self.history(),
                "mkdir" => self.mkdir(args, now),
                "touch" => self.touch(args, now),
                "rm" => self.rm(args),
                "cp" => self.copy_move(args, now, false),
                "mv" => self.copy_move(args, now, true),
                "head" => self.head_tail(args, true),
                "tail" => self.head_tail(args, false),
                "grep" => self.grep(args),
                "find" => self.find(args),
                "clear" => success("\u{1b}[2J\u{1b}[H"),
                "exit" | "logout" => ShellOutput {
                    output: "logout\n".into(),
                    close: true,
                    ..ShellOutput::default()
                },
                _ => {
                    let path = self
                        .executable_path(executable)
                        .unwrap_or_else(|| command.to_owned());
                    failure(format!(
                        "bash: {command}: {path} is present but this command is not emulated\n"
                    ))
                }
            }
        };
        if executable == "psql"
            && self
                .vulnerability_profiles
                .contains("sql_database_weak_credentials")
            && (args
                .windows(2)
                .any(|pair| matches!(pair[0].as_str(), "-p" | "--port") && pair[1] == "15432")
                || args
                    .iter()
                    .any(|arg| arg == "-p15432" || arg == "--port=15432")
                || args.iter().any(|arg| {
                    (arg.starts_with("postgres://") || arg.starts_with("postgresql://"))
                        && arg.contains(":15432/")
                }))
        {
            result.vulnerability_attempts.push(VulnerabilityAttempt {
                profile_id: "sql_database_weak_credentials".into(),
                details: serde_json::json!({"source":"ssh_terminal","database":"postgres","port":15432,"arguments":args,"accepted":result.exit_status == 0}),
            });
        }
        if executable == "docker"
            && self.vulnerability_profiles.contains("docker_api_exposed")
            && docker_tcp_api_target(args)
        {
            result.vulnerability_attempts.push(VulnerabilityAttempt {
                profile_id: "docker_api_exposed".into(),
                details: serde_json::json!({"source":"ssh_terminal","command":format!("docker {}", args.join(" "))}),
            });
        }
        if let Some((append, raw_path)) = redirect {
            let path = match self.path(&raw_path) {
                Ok(path) => path,
                Err(error) => return fs_failure("bash", &raw_path, error),
            };
            let created = !self.fs.exists(&path);
            let mut contents = if append {
                if self.fs.exists(&path) {
                    if let Err(error) = self.fs.authorize_read(&path, &self.user) {
                        return fs_failure("bash", &raw_path, error);
                    }
                }
                match self.fs.read(&path) {
                    Ok(previous) => previous.to_vec(),
                    Err(FsError::NotFound) => Vec::new(),
                    Err(error) => return fs_failure("bash", &raw_path, error),
                }
            } else {
                Vec::new()
            };
            contents.extend_from_slice(result.output.as_bytes());
            if let Err(error) = self
                .fs
                .authorize_write(&path, &self.user)
                .and_then(|_| self.fs.write(&path, contents, now))
            {
                return fs_failure("bash", &raw_path, error);
            }
            if created {
                let group = self.fs.primary_group(&self.user);
                if let Ok(node) = self.fs.node_mut(&path) {
                    node.owner = self.user.clone();
                    node.group = group;
                }
            }
            result.output.clear();
            result.fs_actions.push(FsAction {
                kind: FsActionKind::Modified,
                operation: if append { "append" } else { "redirect" },
                path,
            });
        }
        for action in &result.fs_actions {
            self.deception.record_object(&action.path);
            if action.kind == FsActionKind::Accessed
                && matches!(action.operation, "read" | "head" | "tail" | "grep")
            {
                for bait in self.baits.iter().filter(|bait| {
                    bait.path.as_deref() == Some(action.path.as_str())
                        || (bait.kind == BaitKind::Account
                            && bait.effective_implementation()
                                == BaitImplementation::VirtualAccount
                            && action.path == "/etc/passwd")
                }) {
                    result.bait_opens.push(BaitOpen {
                        id: bait.id,
                        name: bait.name.clone(),
                        path: bait.path.clone().unwrap_or_else(|| action.path.clone()),
                        operation: action.operation.into(),
                        kind: bait.kind,
                    });
                }
            }
        }
        let inferred_interactions = result
            .fs_actions
            .iter()
            .filter_map(|action| {
                bait_for_path(&action.path).map(|bait| VirtualInteraction {
                    bait,
                    action: action.operation.into(),
                    target: Some(action.path.clone()),
                    success: result.exit_status == 0,
                })
            })
            .collect::<Vec<_>>();
        for interaction in inferred_interactions {
            if !result
                .virtual_interactions
                .iter()
                .any(|existing| existing.bait == interaction.bait)
            {
                result.virtual_interactions.push(interaction);
            }
        }
        if command == "history" {
            result.virtual_interactions.push(VirtualInteraction {
                bait: "history",
                action: "list".into(),
                target: Some(format!("{}/.bash_history", self.home)),
                success: result.exit_status == 0,
            });
        }
        let process_targets = if command == "top"
            || (command == "ps"
                && args
                    .iter()
                    .any(|arg| arg.contains('a') || arg.contains('e') || arg.contains('f')))
        {
            self.virtual_processes.iter().collect::<Vec<_>>()
        } else if matches!(command.as_str(), "ss" | "netstat") {
            self.virtual_processes
                .iter()
                .filter(|process| process.running && process.listen_port.is_some())
                .collect::<Vec<_>>()
        } else if command == "systemctl" {
            if args
                .first()
                .is_some_and(|action| action == "list-units" || action == "list-unit-files")
            {
                self.virtual_processes.iter().collect::<Vec<_>>()
            } else if let Some(target) = args.get(1).map(|name| name.trim_end_matches(".service")) {
                self.virtual_processes
                    .iter()
                    .filter(|process| process.name == target)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        } else if command == "kill" {
            args.last()
                .and_then(|raw_pid| raw_pid.parse::<u32>().ok())
                .filter(|pid| *pid >= 4000)
                .and_then(|pid| self.virtual_processes.get((pid - 4000) as usize))
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for process in process_targets {
            result.bait_opens.push(BaitOpen {
                id: process.id,
                name: process.name.clone(),
                path: format!("process://{}", process.name),
                operation: command.clone(),
                kind: process.kind,
            });
        }
        result.deception = deception;
        result
    }

    fn expand_environment(&self, args: &[String]) -> Vec<String> {
        args.iter().map(|value| self.expand_value(value)).collect()
    }

    fn expand_value(&self, value: &str) -> String {
        let mut result = String::with_capacity(value.len());
        let mut chars = value.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\u{001e}' && chars.peek() == Some(&'$') {
                chars.next();
                result.push('$');
                continue;
            }
            if ch != '$' {
                result.push(ch);
                continue;
            }
            if chars.peek() == Some(&'(') {
                chars.next();
                if chars.next_if_eq(&'(').is_none() {
                    result.push_str("$(");
                    continue;
                }
                let mut expression = String::new();
                let mut nested_parentheses = 0_usize;
                let mut closed = false;
                while let Some(next) = chars.next() {
                    match next {
                        '(' => {
                            nested_parentheses += 1;
                            expression.push(next);
                        }
                        ')' if nested_parentheses > 0 => {
                            nested_parentheses -= 1;
                            expression.push(next);
                        }
                        ')' if chars.peek() == Some(&')') => {
                            chars.next();
                            closed = true;
                            break;
                        }
                        _ => expression.push(next),
                    }
                }
                if closed {
                    result.push_str(
                        &evaluate_arithmetic(&expression, &self.variables)
                            .unwrap_or_default()
                            .to_string(),
                    );
                }
                continue;
            }
            if chars.peek() == Some(&'?') {
                chars.next();
                result.push_str(&self.last_exit_status.to_string());
                continue;
            }
            let mut name = String::new();
            let braced = chars.peek() == Some(&'{');
            if braced {
                chars.next();
                while let Some(next) = chars.next() {
                    if next == '}' {
                        break;
                    }
                    name.push(next);
                }
            } else {
                while chars
                    .peek()
                    .is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_')
                {
                    name.push(chars.next().expect("peeked environment variable character"));
                }
            }
            if name.is_empty() {
                result.push('$');
                if braced {
                    result.push('{');
                }
                continue;
            }
            if name == "?" {
                result.push_str(&self.last_exit_status.to_string());
                continue;
            }
            result.push_str(&self.variable_value(&name).unwrap_or_default());
        }
        result
    }

    fn variable_value(&self, name: &str) -> Option<String> {
        match name {
            _ if self.variables.contains_key(name) => self.variables.get(name).cloned(),
            "HOME" => Some(self.home.clone()),
            "USER" | "LOGNAME" => Some(self.user.clone()),
            "HOSTNAME" => Some(self.hostname.clone()),
            "SHELL" => Some("/bin/bash".into()),
            "PWD" => Some(self.cwd.clone()),
            "OLDPWD" => None,
            "PATH" => Some("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()),
            "SHLVL" => Some("1".into()),
            _ => None,
        }
    }

    fn echo(&self, args: &[String]) -> ShellOutput {
        let mut index = 0;
        let mut newline = true;
        let mut escapes = false;
        while let Some(option) = args.get(index).map(String::as_str) {
            match option {
                "-n" => newline = false,
                "-e" => escapes = true,
                "-E" => escapes = false,
                _ => break,
            }
            index += 1;
        }
        let value = args[index..].join(" ");
        let mut output = if escapes {
            decode_escapes(&value)
        } else {
            value
        };
        if newline {
            output.push('\n');
        }
        success(output)
    }

    fn printf(&self, args: &[String]) -> ShellOutput {
        let Some(format) = args.first() else {
            return success("");
        };
        let format = decode_escapes(format);
        let mut output = String::new();
        let mut value_index = 1;
        loop {
            let start = value_index;
            let mut chars = format.chars().peekable();
            while let Some(ch) = chars.next() {
                if ch == '%' {
                    match chars.next() {
                        Some('%') => output.push('%'),
                        Some('s') => {
                            output.push_str(args.get(value_index).map_or("", String::as_str));
                            if value_index < args.len() {
                                value_index += 1;
                            }
                        }
                        Some('d') | Some('i') => {
                            let value = args.get(value_index).map_or("", String::as_str);
                            output.push_str(
                                &value
                                    .parse::<i64>()
                                    .map_or_else(|_| "0".to_owned(), |value| value.to_string()),
                            );
                            if value_index < args.len() {
                                value_index += 1;
                            }
                        }
                        Some(other) => {
                            output.push('%');
                            output.push(other);
                        }
                        None => output.push('%'),
                    }
                } else {
                    output.push(ch);
                }
            }
            if value_index >= args.len() || value_index == start {
                break;
            }
        }
        success(output)
    }

    fn export(&mut self, args: &[String]) -> ShellOutput {
        if args.is_empty() {
            let mut entries = self.environment();
            for name in &self.exported_variables {
                if let Some(value) = self.variables.get(name) {
                    entries.insert(name.clone(), value.clone());
                }
            }
            return success(
                entries
                    .into_iter()
                    .map(|(name, value)| {
                        format!("declare -x {name}=\"{}\"", value.replace('"', "\\\""))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n",
            );
        }
        for arg in args {
            let Some((name, value)) = arg.split_once('=') else {
                if !valid_variable_name(arg) {
                    return failure(format!("bash: export: `{arg}': not a valid identifier\n"));
                }
                self.exported_variables.insert(arg.clone());
                continue;
            };
            if !valid_variable_name(name) {
                return failure(format!("bash: export: `{arg}': not a valid identifier\n"));
            }
            let value = self.expand_value(value);
            self.variables.insert(name.to_owned(), value);
            self.exported_variables.insert(name.to_owned());
        }
        success("")
    }

    fn unset(&mut self, args: &[String]) -> ShellOutput {
        for name in args {
            if !valid_variable_name(name) {
                return failure(format!("bash: unset: `{name}': not a valid identifier\n"));
            }
            self.variables.remove(name);
            self.exported_variables.remove(name);
        }
        success("")
    }

    fn command_builtin(&mut self, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        match args.first().map(String::as_str) {
            Some("-v" | "-V") if args.len() > 1 => {
                let verbose = args[0] == "-V";
                let mut output = String::new();
                let mut status = 0;
                for name in &args[1..] {
                    if let Some(path) = self.command_path(name) {
                        if verbose {
                            output.push_str(&format!("{name} is {path}\n"));
                        } else {
                            output.push_str(&format!("{path}\n"));
                        }
                    } else {
                        status = 1;
                    }
                }
                ShellOutput {
                    output,
                    exit_status: status,
                    ..ShellOutput::default()
                }
            }
            Some("-v" | "-V") => {
                failure("bash: command: usage: command [-pVv] command [arg ...]\n")
            }
            Some("--") => self.execute_words(args[1..].to_vec(), now),
            Some(_) => self.execute_words(args.to_vec(), now),
            None => failure("bash: command: usage: command [-pVv] command [arg ...]\n"),
        }
    }

    fn command_path(&self, name: &str) -> Option<String> {
        if is_shell_builtin(name) {
            return Some(name.to_owned());
        }
        self.executable_path(name)
    }

    fn type_command(&self, args: &[String]) -> ShellOutput {
        if args.is_empty() {
            return failure("type: usage: type [-afptP] name [name ...]\n");
        }
        let mut output = String::new();
        let mut status = 0;
        for name in args {
            if is_shell_builtin(name) {
                output.push_str(&format!("{name} is a shell builtin\n"));
            } else if let Some(path) = self.executable_path(name) {
                output.push_str(&format!("{name} is {path}\n"));
            } else {
                output.push_str(&format!("bash: type: {name}: not found\n"));
                status = 1;
            }
        }
        ShellOutput {
            output,
            exit_status: status,
            ..ShellOutput::default()
        }
    }

    fn umask(&self, args: &[String]) -> ShellOutput {
        if args.first().is_some_and(|arg| arg == "-S") {
            return success("u=rwx,g=rx,o=rx\n");
        }
        if args.is_empty() {
            return success("0022\n");
        }
        failure("umask: changing the virtual process mask is not supported\n")
    }

    fn executable_path(&self, name: &str) -> Option<String> {
        if name.starts_with('/') {
            return self.fs.is_executable(name).then(|| name.to_owned());
        }
        for directory in [
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
        ] {
            let path = format!("{directory}/{name}");
            if self.fs.is_executable(&path) {
                return Some(path);
            }
        }
        None
    }

    fn id(&self, args: &[String]) -> ShellOutput {
        if args.len() > 1 {
            return failure("id: extra operand\n");
        }
        let user = args.first().map_or(self.user.as_str(), String::as_str);
        let Some(account) = self.account(user) else {
            return failure(format!("id: ‘{user}’: no such user\n"));
        };
        let uid = account
            .get(2)
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(65534);
        let gid = account
            .get(3)
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(65534);
        let group_name = self.group_name(gid).unwrap_or_else(|| gid.to_string());
        let mut groups = vec![(gid, group_name.clone())];
        if let Ok(contents) = self.fs.read("/etc/group") {
            for line in String::from_utf8_lossy(contents).lines() {
                let fields: Vec<_> = line.split(':').collect();
                if fields.len() >= 4 && fields[3].split(',').any(|member| member == user) {
                    if let Ok(group_id) = fields[2].parse::<u32>() {
                        if !groups.iter().any(|(existing, _)| *existing == group_id) {
                            groups.push((group_id, fields[0].to_owned()));
                        }
                    }
                }
            }
        }
        let group_list = groups
            .iter()
            .map(|(id, name)| format!("{id}({name})"))
            .collect::<Vec<_>>()
            .join(",");
        success(format!(
            "uid={uid}({user}) gid={gid}({group_name}) groups={group_list}\n"
        ))
    }

    fn account(&self, username: &str) -> Option<Vec<String>> {
        let contents = self.fs.read("/etc/passwd").ok()?;
        String::from_utf8_lossy(contents)
            .lines()
            .find(|line| line.split(':').next() == Some(username))
            .map(|line| line.split(':').map(str::to_owned).collect())
    }

    fn group_name(&self, gid: u32) -> Option<String> {
        let contents = self.fs.read("/etc/group").ok()?;
        String::from_utf8_lossy(contents).lines().find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _password = fields.next()?;
            (fields.next()?.parse::<u32>().ok() == Some(gid)).then(|| name.to_owned())
        })
    }

    fn getent(&self, args: &[String]) -> ShellOutput {
        if args.is_empty() {
            return failure("getent: database name required\n");
        }
        let database = args[0].as_str();
        if database == "hosts" {
            if args.len() > 2 {
                return failure("getent: too many arguments\n");
            }
            let Ok(contents) = self.fs.read("/etc/hosts") else {
                return failure("");
            };
            let key = args.get(1).map(String::as_str);
            let hosts = String::from_utf8_lossy(contents);
            let lines = hosts
                .lines()
                .filter(|line| {
                    let mut fields = line.split_whitespace();
                    let _address = fields.next();
                    key.is_none_or(|key| fields.any(|field| field == key))
                })
                .collect::<Vec<_>>();
            return if lines.is_empty() {
                failure("")
            } else {
                success(format!("{}\n", lines.join("\n")))
            };
        }
        let file = match database {
            "passwd" => "/etc/passwd",
            "group" => "/etc/group",
            "shadow" => "/etc/shadow",
            _ => return failure(format!("getent: unknown database ‘{database}’\n")),
        };
        if args.len() > 2 {
            return failure("getent: too many arguments\n");
        }
        if database == "shadow" && self.user != "root" {
            return failure("getent: Permission denied\n");
        }
        let Ok(data) = self.fs.read(file) else {
            return failure("");
        };
        let lines = String::from_utf8_lossy(data);
        let output = lines
            .lines()
            .filter(|line| {
                args.get(1)
                    .is_none_or(|key| line.split(':').next() == Some(key.as_str()))
            })
            .collect::<Vec<_>>()
            .join("\n");
        if output.is_empty() {
            failure("")
        } else {
            success(format!("{output}\n"))
        }
    }

    fn groups(&self, args: &[String]) -> ShellOutput {
        if args.len() > 1 {
            return failure("groups: extra operand\n");
        }
        let user = args.first().map_or(self.user.as_str(), String::as_str);
        if self.account(user).is_none() {
            return failure(format!("groups: ‘{user}’: no such user\n"));
        }
        let account = self.account(user).unwrap_or_default();
        let gid = account
            .get(3)
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(65534);
        let mut names = self.group_name(gid).into_iter().collect::<Vec<_>>();
        if let Ok(contents) = self.fs.read("/etc/group") {
            for line in String::from_utf8_lossy(contents).lines() {
                let fields: Vec<_> = line.split(':').collect();
                if fields.len() >= 4
                    && fields[3].split(',').any(|member| member == user)
                    && !names.iter().any(|name| name == fields[0])
                {
                    names.push(fields[0].to_owned());
                }
            }
        }
        success(format!("{}\n", names.join(" ")))
    }

    fn stat(&self, args: &[String]) -> ShellOutput {
        let paths = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return failure("stat: missing file operand\n");
        }
        let mut output = String::new();
        for raw in paths {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure("stat", raw, error),
            };
            let node = match self.fs.node(&path) {
                Ok(node) => node,
                Err(error) => return fs_failure("stat", raw, error),
            };
            let kind = if node.is_dir() {
                "directory"
            } else {
                "regular file"
            };
            let permissions = node.permissions.display(node.is_dir());
            let uid = self
                .account(&node.owner)
                .and_then(|entry| entry.get(2).and_then(|value| value.parse::<u32>().ok()))
                .unwrap_or(0);
            let gid = self
                .fs
                .read("/etc/group")
                .ok()
                .and_then(|contents| {
                    String::from_utf8_lossy(contents).lines().find_map(|line| {
                        let mut fields = line.split(':');
                        let name = fields.next()?;
                        let _password = fields.next()?;
                        let id = fields.next()?.parse::<u32>().ok()?;
                        (name == node.group).then_some(id)
                    })
                })
                .unwrap_or(0);
            output.push_str(&format!("  File: {path}\n  Size: {}\tBlocks: {}\tIO Block: 4096 {kind}\nDevice: 0,45\tInode: {}\tLinks: 1\nAccess: ({:04o}/{})\tUid: ({uid:>5}/ {})\tGid: ({gid:>5}/ {})\nAccess: {}\nModify: {}\nChange: {}\n Birth: -\n", node.len(), node.len().div_ceil(512), stable_inode(&path), node.permissions.0, permissions, node.owner, node.group, node.modified_at.format("%Y-%m-%d %H:%M:%S%.9f %z"), node.modified_at.format("%Y-%m-%d %H:%M:%S%.9f %z"), node.modified_at.format("%Y-%m-%d %H:%M:%S%.9f %z")));
        }
        success(output)
    }

    fn readlink(&self, args: &[String]) -> ShellOutput {
        let canonical = args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "-f" | "-e" | "-m" | "--canonicalize" | "--canonicalize-existing"
            )
        });
        let canonical_existing = args
            .iter()
            .any(|arg| matches!(arg.as_str(), "-e" | "--canonicalize-existing"));
        let missing_ok = args.iter().any(|arg| arg == "-m");
        let no_newline = args.iter().any(|arg| arg == "-n");
        let Some(raw) = args.iter().find(|arg| !arg.starts_with('-')) else {
            return failure("readlink: missing operand\n");
        };
        let path = match self.path(raw) {
            Ok(path) => path,
            Err(error) => return fs_failure("readlink", raw, error),
        };
        if let Err(error) = self.fs.authorize_traverse(&path, &self.user) {
            return fs_failure("readlink", raw, error);
        }
        if canonical {
            if canonical_existing && !self.fs.exists(&path) || !missing_ok && !self.fs.exists(&path)
            {
                return failure("");
            }
            return match self.fs.canonicalize(&path) {
                Ok(target) => success(if no_newline {
                    target
                } else {
                    format!("{target}\n")
                }),
                Err(_) => failure(""),
            };
        }
        match self.fs.readlink(&path) {
            Ok(target) => success(if no_newline {
                target.to_owned()
            } else {
                format!("{target}\n")
            }),
            Err(FsError::InvalidPath) => failure(format!("readlink: {}: Invalid argument\n", raw)),
            Err(error) => fs_failure("readlink", raw, error),
        }
    }

    fn chmod(&mut self, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        if args.len() < 2 {
            return failure("chmod: missing operand\n");
        }
        let Some(mode) = parse_mode(&args[0]) else {
            return failure(format!("chmod: invalid mode: ‘{}’\n", args[0]));
        };
        let mut result = ShellOutput::default();
        for raw in &args[1..] {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure("chmod", raw, error),
            };
            if let Err(error) = self.fs.chmod(&path, &self.user, mode, now) {
                return fs_failure("chmod", raw, error);
            }
            result.fs_actions.push(FsAction {
                kind: FsActionKind::Modified,
                operation: "chmod",
                path,
            });
        }
        result
    }

    fn su(&mut self, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        let user = args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .map_or("root", String::as_str);
        if self.user != "root" {
            return failure("su: Authentication failure\n");
        }
        if self.account(user).is_none() {
            return failure(format!("su: user {user} does not exist\n"));
        }
        let command_index = args.iter().position(|arg| arg == "-c");
        let new_home = self
            .account(user)
            .and_then(|entry| entry.get(5).cloned())
            .unwrap_or_else(|| format!("/home/{user}"));
        let previous_user = std::mem::replace(&mut self.user, user.to_owned());
        let previous_home = std::mem::replace(&mut self.home, new_home);
        let output = if let Some(index) = command_index {
            args.get(index + 1)
                .map(|command| self.execute(command, now))
                .unwrap_or_else(|| failure("su: option requires an argument -- 'c'\n"))
        } else {
            success("")
        };
        self.user = previous_user;
        self.home = previous_home;
        output
    }

    fn shell_interpreter(
        &mut self,
        name: &str,
        args: &[String],
        now: DateTime<Utc>,
    ) -> ShellOutput {
        if args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--version" | "-version"))
        {
            let Some(profile) = self.fs.distribution().linux_profile() else {
                return failure(format!("{name}: command not found\n"));
            };
            if matches!(name, "dash" | "sh") {
                return success(profile.dash_version_output);
            }
            let version = packages::installed_bash_version(&self.fs, profile)
                .unwrap_or_else(|| profile.bash_version.to_owned());
            return success(format!(
                "GNU bash, version {version}(1)-release (x86_64-pc-linux-gnu)\n"
            ));
        }
        if let Some(index) = args
            .iter()
            .position(|arg| arg == "-c" || (arg.starts_with('-') && arg.contains('c')))
        {
            let Some(command) = args.get(index + 1) else {
                return failure("bash: -c: option requires an argument\n");
            };
            return self.execute(command, now);
        }
        success("")
    }

    fn nano(&self, args: &[String]) -> ShellOutput {
        if args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--version" | "-V"))
        {
            return self.fs.distribution().linux_profile().map_or_else(
                || failure("nano: command not found\n"),
                |profile| success(profile.nano_version_output),
            );
        }
        success(
            "GNU nano 8.4                       New Buffer\n\n^G Help  ^O Write Out  ^W Where Is  ^K Cut  ^T Execute\n",
        )
    }

    fn cd(&mut self, args: &[String]) -> ShellOutput {
        if args.len() > 1 {
            return failure("bash: cd: too many arguments\n");
        }
        let raw = args.first().map_or(self.home.as_str(), String::as_str);
        let path = match self.path(raw) {
            Ok(path) => path,
            Err(error) => return fs_failure("cd", raw, error),
        };
        if let Err(error) = self.fs.authorize_enter(&path, &self.user) {
            return fs_failure("cd", raw, error);
        }
        if !self.fs.is_dir(&path) {
            return fs_failure("cd", raw, FsError::NotDirectory);
        }
        self.cwd = path.clone();
        with_action(success(""), FsActionKind::Accessed, "cd", path)
    }

    fn ls(&self, args: &[String]) -> ShellOutput {
        if args.iter().any(|arg| arg == "--version") {
            let version = packages::installed_version(&self.fs, "coreutils")
                .map(|version| version.split('-').next().unwrap_or(&version).to_owned())
                .unwrap_or_else(|| "8.32".into());
            return success(format!(
                "ls (GNU coreutils) {version}\nCopyright (C) Free Software Foundation, Inc.\nLicense GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n"
            ));
        }
        if args.iter().any(|arg| arg == "--help") {
            return success(
                "Usage: ls [OPTION]... [FILE]...\nList information about the FILEs (the current directory by default).\n",
            );
        }
        let long = args
            .iter()
            .any(|arg| arg.starts_with('-') && arg.contains('l'));
        let all = args
            .iter()
            .any(|arg| arg.starts_with('-') && arg.contains('a'));
        let paths = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if paths.len() > 1 {
            let mut output = String::new();
            for raw in paths {
                let path = match self.path(raw) {
                    Ok(path) => path,
                    Err(error) => return fs_failure("ls", raw, error),
                };
                let mut single = args
                    .iter()
                    .filter(|arg| arg.starts_with('-'))
                    .cloned()
                    .collect::<Vec<_>>();
                single.push(raw.to_owned());
                if self.fs.is_dir(&path) {
                    output.push_str(&format!("{raw}:\n"));
                    output.push_str(&self.ls(&single).output);
                    output.push('\n');
                } else {
                    if let Err(error) = self.fs.authorize_traverse(&path, &self.user) {
                        return fs_failure("ls", raw, error);
                    }
                    let node = match self.fs.lstat(&path) {
                        Ok(node) => node,
                        Err(error) => return fs_failure("ls", raw, error),
                    };
                    if long {
                        let display_node = self.fs.lstat(&path).unwrap_or(node);
                        output.push_str(&format!(
                            "{}\n",
                            long_entry(path.rsplit('/').next().unwrap_or(&path), display_node)
                        ));
                    } else {
                        output.push_str(&format!("{}\n", path.rsplit('/').next().unwrap_or(&path)));
                    }
                }
            }
            return success(output);
        }
        let raw = paths.first().copied().unwrap_or(".");
        let path = match self.path(raw) {
            Ok(path) => path,
            Err(error) => return fs_failure("ls", raw, error),
        };
        let directory_itself = args
            .iter()
            .any(|arg| arg.starts_with('-') && arg.contains('d'));
        let access = if self.fs.is_dir(&path) && !directory_itself {
            self.fs.authorize_list(&path, &self.user)
        } else {
            self.fs.authorize_traverse(&path, &self.user)
        };
        if let Err(error) = access {
            return fs_failure("ls", raw, error);
        }
        let node = match self.fs.lstat(&path) {
            Ok(node) => node,
            Err(error) => return fs_failure("ls", raw, error),
        };
        let output = if self.fs.is_dir(&path) && !directory_itself {
            match self.fs.list(&path) {
                Ok(entries) if long => {
                    let entries = entries
                        .into_iter()
                        .filter(|(name, _)| all || !name.starts_with('.'))
                        .collect::<Vec<_>>();
                    let blocks = entries
                        .iter()
                        .map(|(_, node)| node.len().div_ceil(1024))
                        .sum::<usize>()
                        + if all { 8 } else { 0 };
                    let mut lines = vec![format!("total {}", blocks)];
                    if all {
                        lines.push(long_entry(".", node));
                        let parent = if path == "/" {
                            "/"
                        } else {
                            path.rsplit_once('/').map_or("/", |(parent, _)| {
                                if parent.is_empty() { "/" } else { parent }
                            })
                        };
                        if let Ok(parent_node) = self.fs.node(parent) {
                            lines.push(long_entry("..", parent_node));
                        }
                    }
                    lines.extend(
                        entries
                            .into_iter()
                            .map(|(name, node)| long_entry(&name, node)),
                    );
                    lines.join("\n") + "\n"
                }
                Ok(entries) => {
                    entries
                        .into_iter()
                        .filter(|(name, _)| all || !name.starts_with('.'))
                        .map(|(name, _)| name)
                        .collect::<Vec<_>>()
                        .join("  ")
                        + "\n"
                }
                Err(error) => return fs_failure("ls", raw, error),
            }
        } else if long {
            let display_node = self.fs.lstat(&path).unwrap_or(node);
            format!(
                "{}\n",
                long_entry(path.rsplit('/').next().unwrap_or(&path), display_node)
            )
        } else {
            format!("{}\n", path.rsplit('/').next().unwrap_or(&path))
        };
        with_action(success(output), FsActionKind::Accessed, "list", path)
    }

    fn cat(&self, args: &[String]) -> ShellOutput {
        if args.is_empty() {
            return self
                .pipe_input
                .as_ref()
                .map(|input| success(input.clone()))
                .unwrap_or_else(|| failure("cat: missing operand\n"));
        }
        let mut result = ShellOutput::default();
        for raw in args {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure("cat", raw, error),
            };
            if let Err(error) = self.fs.authorize_read(&path, &self.user) {
                return fs_failure("cat", raw, error);
            }
            match self.fs.read(&path) {
                Ok(data) => result.output.push_str(&String::from_utf8_lossy(data)),
                Err(error) => return fs_failure("cat", raw, error),
            }
            result.fs_actions.push(FsAction {
                kind: FsActionKind::Accessed,
                operation: "read",
                path,
            });
        }
        result
    }

    fn uname(&self, args: &[String]) -> ShellOutput {
        let distribution = self.fs.distribution();
        let options = args
            .iter()
            .filter(|arg| arg.starts_with('-'))
            .map(String::as_str)
            .collect::<String>();
        if options.contains('a') {
            return success(format!(
                "Linux {} {} {} x86_64 GNU/Linux\n",
                self.hostname,
                distribution.kernel_release(),
                distribution
                    .proc_version()
                    .split_once(')')
                    .map_or("#1 SMP PREEMPT_DYNAMIC", |(_, rest)| rest.trim())
            ));
        }
        let mut fields = Vec::new();
        if options.is_empty() || options.contains('s') {
            fields.push("Linux".to_owned());
        }
        if options.contains('n') {
            fields.push(self.hostname.clone());
        }
        if options.contains('r') {
            fields.push(distribution.kernel_release().to_owned());
        }
        if options.contains('v') {
            fields.push(
                distribution
                    .proc_version()
                    .split_once(')')
                    .map_or("#1 SMP PREEMPT_DYNAMIC", |(_, rest)| rest.trim())
                    .to_owned(),
            );
        }
        if options.contains('m') {
            fields.push("x86_64".to_owned());
        }
        if options.contains('o') {
            fields.push("GNU/Linux".to_owned());
        }
        success(format!("{}\n", fields.join(" ")))
    }

    fn sudo(&mut self, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        // The default virtual Ubuntu account has explicit passwordless sudo.
        // Only commands implemented by this emulator can be elevated.
        if args == ["-l"] {
            let manager = if self.fs.distribution().is_apt() {
                "/usr/bin/apt, /usr/bin/apt-get"
            } else {
                "/usr/bin/pacman"
            };
            return success(format!(
                "Matching Defaults entries for {} on this host:\n    env_reset, mail_badpass\n\nUser {} may run the following commands on this host:\n    (ALL : ALL) NOPASSWD: {}, /usr/bin/systemctl, /usr/bin/whoami, /usr/bin/id\n",
                self.user, self.user, manager
            ));
        }
        let mut non_interactive = false;
        let mut command_index = 0;
        while let Some(argument) = args.get(command_index) {
            match argument.as_str() {
                "-n" | "--non-interactive" => non_interactive = true,
                "-u" | "--user" => {
                    if args.get(command_index + 1).is_none() {
                        return failure("sudo: option requires an argument -- 'u'\n");
                    }
                    command_index += 1;
                }
                "--" => {
                    command_index += 1;
                    break;
                }
                _ if argument.starts_with('-') => {
                    return failure(format!(
                        "sudo: invalid option -- '{}'\n",
                        argument.trim_start_matches('-')
                    ));
                }
                _ => break,
            }
            command_index += 1;
        }
        let command_args = &args[command_index..];
        match command_args.split_first() {
            Some((command, rest)) if command == "whoami" && rest.is_empty() => success("root\n"),
            Some((command, rest)) if command == "id" && rest.is_empty() => {
                success("uid=0(root) gid=0(root) groups=0(root)\n")
            }
            Some((command, rest))
                if (command == "apt" || command == "apt-get")
                    && self.fs.distribution().is_apt() =>
            {
                self.apt(rest, true, now)
            }
            Some((command, rest)) if command == "pacman" && !self.fs.distribution().is_apt() => {
                self.pacman(rest, true, now)
            }
            Some((command, rest)) if command == "systemctl" => self
                .virtual_server
                .execute("systemctl", rest, &self.cwd, &mut self.fs, now)
                .map(shell_output)
                .unwrap_or_else(|| failure("sudo: systemctl unavailable\n")),
            Some((command, rest)) => {
                let command_path = self
                    .executable_path(command)
                    .and_then(|path| self.fs.canonicalize(&path).ok());
                let allowed_paths: &[&str] = if self.fs.distribution().is_apt() {
                    &[
                        "/usr/bin/apt",
                        "/usr/bin/apt-get",
                        "/usr/bin/systemctl",
                        "/usr/bin/whoami",
                        "/usr/bin/id",
                    ]
                } else {
                    &[
                        "/usr/bin/pacman",
                        "/usr/bin/systemctl",
                        "/usr/bin/whoami",
                        "/usr/bin/id",
                    ]
                };
                let allowed = self.user == "root"
                    || command_path
                        .as_deref()
                        .is_some_and(|path| allowed_paths.contains(&path));
                if !allowed {
                    if self.command_path(command).is_some() {
                        if non_interactive {
                            return failure("sudo: a password is required\n");
                        }
                        return failure(format!("sudo: a password is required\n"));
                    }
                    return failure(format!("sudo: {command}: command not found\n"));
                }
                let previous_user = std::mem::replace(&mut self.user, "root".into());
                let mut words = vec![command.clone()];
                words.extend_from_slice(rest);
                let result = self.execute_words(words, now);
                self.user = previous_user;
                result
            }
            None => failure("usage: sudo command\n"),
        }
    }

    fn apt(&mut self, args: &[String], privileged: bool, now: DateTime<Utc>) -> ShellOutput {
        let Some(profile) = self.fs.distribution().linux_profile() else {
            return failure("apt: command not found\n");
        };
        if args
            .first()
            .is_some_and(|arg| arg == "--version" || arg == "-v")
        {
            return success(profile.apt_version_output);
        }
        let mut words = args
            .iter()
            .filter(|arg| arg.as_str() != "-y" && arg.as_str() != "--yes");
        let action = words.next().map(String::as_str).unwrap_or("");
        let distro = profile.distribution;
        let suite = profile.apt_codename;
        let mirror = profile.apt_mirror;
        let name = words.next().map(String::as_str);
        if matches!(action, "install" | "remove" | "purge" | "update") && !privileged {
            return failure(
                "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock, are you root?\n",
            );
        }
        match action {
            "update" if name.is_none() => success(format!(
                "Hit:1 {mirror} {suite} InRelease\nReading package lists... Done\nBuilding dependency tree... Done\nAll packages are up to date.\n"
            )),
            "search" => {
                let query = name.unwrap_or("");
                let output = packages::CATALOG
                    .iter()
                    .filter(|package| {
                        package.name.contains(query) || package.description.contains(query)
                    })
                    .map(|package| {
                        format!(
                            "{}/{} {} amd64\n  {}\n",
                            package.name,
                            suite,
                            packages::version_for(package, distro),
                            package.description
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                success(format!(
                    "Sorting... Done\nFull Text Search... Done\n{output}"
                ))
            }
            "show" => match name.and_then(packages::lookup) {
                Some(package) => success(format!(
                    "Package: {}\nVersion: {}\nArchitecture: amd64\nDescription: {}\n",
                    package.name,
                    packages::version_for(package, distro),
                    package.description
                )),
                None => {
                    let status = String::from_utf8_lossy(
                        self.fs.read("/var/lib/dpkg/status").unwrap_or_default(),
                    )
                    .into_owned();
                    match status
                        .split("\n\n")
                        .find(|record| dpkg_field(record, "Package:") == name)
                    {
                        Some(record) => success(format!("{}\n", record.trim())),
                        None => failure("E: No packages found\n"),
                    }
                }
            },
            "list" => {
                let installed_only = name == Some("--installed");
                let requested = if installed_only {
                    words.next().map(String::as_str)
                } else {
                    name
                };
                let status = String::from_utf8_lossy(
                    self.fs.read("/var/lib/dpkg/status").unwrap_or_default(),
                )
                .into_owned();
                let records = status
                    .split("\n\n")
                    .filter(|record| dpkg_field(record, "Package:").is_some())
                    .collect::<Vec<_>>();
                let mut rows = Vec::new();
                if installed_only {
                    for record in records {
                        let Some(package_name) = dpkg_field(record, "Package:") else {
                            continue;
                        };
                        if requested.is_some_and(|query| !package_name.contains(query))
                            || !dpkg_field(record, "Status:")
                                .is_some_and(|state| state.ends_with("installed"))
                        {
                            continue;
                        }
                        rows.push(format!(
                            "{package_name}/{suite} {} amd64 [installed]",
                            dpkg_field(record, "Version:").unwrap_or("(none)")
                        ));
                    }
                } else {
                    for package in packages::CATALOG {
                        if requested.is_some_and(|query| !package.name.contains(query)) {
                            continue;
                        }
                        rows.push(format!(
                            "{}/{} {} amd64{}",
                            package.name,
                            suite,
                            packages::version_for(package, distro),
                            if packages::installed(&self.fs, package.name) {
                                " [installed]"
                            } else {
                                ""
                            }
                        ));
                    }
                    for record in records {
                        let Some(package_name) = dpkg_field(record, "Package:") else {
                            continue;
                        };
                        if packages::lookup(package_name).is_some()
                            || requested.is_some_and(|query| !package_name.contains(query))
                        {
                            continue;
                        }
                        rows.push(format!(
                            "{package_name}/{suite} {} amd64 [installed]",
                            dpkg_field(record, "Version:").unwrap_or("(none)")
                        ));
                    }
                }
                success(format!("Listing... Done\n{}\n", rows.join("\n")))
            }
            "install" | "remove" | "purge" => {
                if words.next().is_some() {
                    return failure("E: only one package can be changed at a time\n");
                }
                let Some(package) = name.and_then(packages::lookup) else {
                    return failure(format!(
                        "E: Unable to locate package {}\n",
                        name.unwrap_or("")
                    ));
                };
                let already = packages::installed(&self.fs, package.name);
                if action == "install" {
                    if already {
                        return success(format!(
                            "Reading package lists... Done\nBuilding dependency tree... Done\n{} is already the newest version ({}).\n0 upgraded, 0 newly installed, 0 to remove.\n",
                            package.name,
                            packages::version_for(package, distro)
                        ));
                    }
                    let mut next_fs = self.fs.clone();
                    if let Err(error) = packages::install(&mut next_fs, package, now) {
                        return failure(format!(
                            "E: virtual package installation failed: {error}\n"
                        ));
                    }
                    self.fs = next_fs;
                    self.virtual_server.refresh_packages(&mut self.fs, now);
                    let mut result = with_action(
                        success(format!(
                            "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\nThe following NEW packages will be installed:\n  {}\n0 upgraded, 1 newly installed, 0 to remove.\nNeed to get {} kB of archives.\nAfter this operation, {} kB of additional disk space will be used.\nGet:1 {mirror} {suite}/main {} {} amd64 [{} kB]\nFetched {} kB\nUnpacking {} ({}) ...\nSetting up {} ({}) ...\nProcessing triggers for man-db ...\n",
                            package.name,
                            package.archive_kib,
                            package.installed_kib,
                            package.name,
                            packages::version_for(package, distro),
                            package.archive_kib,
                            package.archive_kib,
                            package.name,
                            packages::version_for(package, distro),
                            package.name,
                            packages::version_for(package, distro)
                        )),
                        FsActionKind::Modified,
                        "package_install",
                        packages::registry_path(distro).into(),
                    );
                    result.stream_output = true;
                    result
                } else {
                    if !already
                        && !(action == "purge" && packages::configured(&self.fs, package.name))
                    {
                        return success(format!(
                            "Package '{}' is not installed, so not removed\n",
                            package.name
                        ));
                    }
                    let mut next_fs = self.fs.clone();
                    let removal = if action == "purge" {
                        packages::purge(&mut next_fs, package, now)
                    } else {
                        packages::remove(&mut next_fs, package, now)
                    };
                    if let Err(error) = removal {
                        return failure(format!("E: virtual package removal failed: {error}\n"));
                    }
                    self.fs = next_fs;
                    self.virtual_server.refresh_packages(&mut self.fs, now);
                    let verb = if action == "purge" {
                        "Purging"
                    } else {
                        "Removing"
                    };
                    with_action(
                        success(format!(
                            "Reading package lists... Done\n{verb} {} ({}) ...\nProcessing triggers for man-db ...\n",
                            package.name,
                            packages::version_for(package, distro)
                        )),
                        FsActionKind::Modified,
                        "package_remove",
                        packages::registry_path(distro).into(),
                    )
                }
            }
            _ => failure("apt: supported commands: update, search, show, list, install, remove\n"),
        }
    }

    fn pacman(&mut self, args: &[String], privileged: bool, now: DateTime<Utc>) -> ShellOutput {
        if args
            .iter()
            .any(|argument| matches!(argument.as_str(), "--version" | "-V"))
        {
            return success("Pacman v7.1.0 - libalpm v15.0.0\n");
        }
        let action_index = args.iter().position(|arg| {
            matches!(
                arg.as_str(),
                "-Sy"
                    | "-Syu"
                    | "-Syyu"
                    | "-Su"
                    | "-Ss"
                    | "-Si"
                    | "-S"
                    | "-R"
                    | "-Rs"
                    | "-Rns"
                    | "-Q"
                    | "-Qq"
                    | "-Qi"
                    | "-Qii"
                    | "-Ql"
                    | "-Qo"
                    | "-Qe"
                    | "-Qd"
                    | "-Qdt"
                    | "-Qk"
                    | "-Qkk"
                    | "-Qu"
            )
        });
        let Some(action_index) = action_index else {
            return failure(
                "pacman: supported operations: -S, -R, -Sy, -Syu, -Ss, -Si, -Q, -Qq, -Qi, -Ql, -Qo, -Qe, -Qdt, -Qk, -Qkk\n",
            );
        };
        let action = args[action_index].as_str();
        let operands = args
            .iter()
            .skip(action_index + 1)
            .filter(|arg| !arg.starts_with('-'))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if matches!(
            action,
            "-Sy" | "-Syu" | "-Syyu" | "-Su" | "-S" | "-R" | "-Rs" | "-Rns"
        ) && !privileged
        {
            return failure(
                "error: failed to init transaction (unable to lock database)\nerror: could not lock database: Permission denied\n",
            );
        }
        match action {
            "-Sy" | "-Syu" | "-Syyu" | "-Su" if operands.is_empty() => {
                let mut next = self.fs.clone();
                if matches!(action, "-Sy" | "-Syu" | "-Syyu") {
                    if let Err(error) = packages::write_sync_database(&mut next, now) {
                        return failure(format!(
                            "error: could not synchronize package databases: {error}\n"
                        ));
                    }
                }
                let upgrades = packages::arch_upgrades(&next);
                let mut output = String::new();
                if matches!(action, "-Sy" | "-Syu" | "-Syyu") {
                    output.push_str(
                        ":: Synchronizing package databases...\n core is up to date\n extra is up to date\n",
                    );
                }
                if matches!(action, "-Syu" | "-Syyu" | "-Su") {
                    output.push_str(":: Starting full system upgrade...\n");
                    if upgrades.is_empty() {
                        output.push_str(" there is nothing to do\n");
                    } else {
                        output.push_str(&format!("Packages ({})\n", upgrades.len()));
                        for (installed, available) in &upgrades {
                            output.push_str(&format!(
                                " {} {} -> {}\n",
                                installed.name, installed.version, available.version
                            ));
                        }
                        for (installed, available) in &upgrades {
                            if let Err(error) =
                                packages::upgrade_arch(&mut next, installed, available, now)
                            {
                                return failure(format!(
                                    "error: could not upgrade {}: {error}\n",
                                    installed.name
                                ));
                            }
                        }
                    }
                }
                self.fs = next;
                self.virtual_server.refresh_packages(&mut self.fs, now);
                with_action(
                    success(output),
                    FsActionKind::Modified,
                    "package_database_sync",
                    "/var/lib/pacman".into(),
                )
            }
            "-Ss" => {
                let query = operands.first().copied().unwrap_or("");
                let output = packages::arch_repository()
                    .iter()
                    .filter(|package| {
                        package.repository != "local"
                            && (package.name.contains(query) || package.description.contains(query))
                    })
                    .map(|package| {
                        format!(
                            "{}/{} {}\n    {}",
                            package.repository, package.name, package.version, package.description
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                success(format!("{output}\n"))
            }
            "-Si" => {
                let Some(name) = operands.first().copied() else {
                    return failure("error: package name is required\n");
                };
                let Some(package) = packages::arch_lookup(name) else {
                    return failure(format!("error: package '{}' was not found\n", name));
                };
                let (archive_size, installed_size) = packages::arch_package_sizes(package);
                success(format!(
                    "Repository      : {}\nName            : {}\nVersion         : {}\nDescription     : {}\nArchitecture    : x86_64\nURL             : https://archlinux.org/packages/{}/x86_64/{}/\nLicenses        : GPL\nGroups          : None\nProvides        : None\nDepends On      : {}\nOptional Deps   : None\nConflicts With  : None\nReplaces        : None\nDownload Size   : {} KiB\nInstalled Size  : {} KiB\nPackager        : Arch Linux Package Maintainer <packages@archlinux.org>\nBuild Date      : {}\nValidated By    : SHA-256 Sum  Signature\n",
                    package.repository,
                    package.name,
                    package.version,
                    package.description,
                    package.repository,
                    package.name,
                    if package.dependencies.is_empty() {
                        "None".into()
                    } else {
                        package.dependencies.join("  ")
                    },
                    archive_size / 1024,
                    installed_size / 1024,
                    packages::arch_build_date_text(package.name)
                ))
            }
            "-Q" | "-Qq" | "-Qi" | "-Qii" | "-Ql" | "-Qo" | "-Qe" | "-Qd" | "-Qdt" | "-Qk"
            | "-Qkk" | "-Qu" => {
                let local = packages::arch_local_packages(&self.fs);
                if action == "-Qo" {
                    if operands.is_empty() {
                        return failure("error: path name is required\n");
                    }
                    let mut output = String::new();
                    for raw_path in operands {
                        let path = match self.path(raw_path) {
                            Ok(path) => path,
                            Err(error) => {
                                return failure(format!(
                                    "error: invalid path '{}': {error}\n",
                                    raw_path
                                ));
                            }
                        };
                        match packages::arch_file_owner(&self.fs, &path) {
                            Some(owner) => output.push_str(&format!(
                                "{} is owned by {owner}\n",
                                self.fs.canonicalize(&path).unwrap_or(path)
                            )),
                            None => {
                                return failure(format!(
                                    "error: No package owns {}\n",
                                    self.fs.canonicalize(&path).unwrap_or(path)
                                ));
                            }
                        }
                    }
                    return success(output);
                }
                if action == "-Qu" {
                    let updates = packages::arch_upgrades(&self.fs);
                    return success(format!(
                        "{}\n",
                        updates
                            .iter()
                            .map(|(installed, available)| format!(
                                "{} {} -> {}",
                                installed.name, installed.version, available.version
                            ))
                            .collect::<Vec<_>>()
                            .join("\n")
                    ));
                }
                let selected = if operands.is_empty() {
                    local
                        .iter()
                        .filter(|package| match action {
                            "-Qe" => package.reason == 0,
                            "-Qd" => package.reason == 1,
                            "-Qdt" => {
                                package.reason == 1
                                    && !local.iter().any(|other| {
                                        other.dependencies.iter().any(|dependency| {
                                            dependency
                                                .split(|ch| matches!(ch, '<' | '>' | '='))
                                                .next()
                                                == Some(package.name.as_str())
                                        })
                                    })
                            }
                            _ => true,
                        })
                        .cloned()
                        .collect::<Vec<_>>()
                } else {
                    let mut selected = Vec::new();
                    for name in operands {
                        let Some(package) = packages::arch_installed(&self.fs, name) else {
                            return failure(format!("error: package '{}' was not found\n", name));
                        };
                        let orphaned_dependency = package.reason == 1
                            && !local.iter().any(|other| {
                                other.dependencies.iter().any(|dependency| {
                                    dependency.split(|ch| matches!(ch, '<' | '>' | '=')).next()
                                        == Some(package.name.as_str())
                                })
                            });
                        let include = match action {
                            "-Qe" => package.reason == 0,
                            "-Qd" => package.reason == 1,
                            "-Qdt" => orphaned_dependency,
                            _ => true,
                        };
                        if include {
                            selected.push(package);
                        }
                    }
                    selected
                };
                let mut output = Vec::new();
                for package in selected {
                    match action {
                        "-Qi" | "-Qii" => {
                            let required_by = local
                                .iter()
                                .filter(|other| {
                                    other.dependencies.iter().any(|dependency| {
                                        dependency.split(|ch| matches!(ch, '<' | '>' | '=')).next()
                                            == Some(package.name.as_str())
                                    })
                                })
                                .map(|other| other.name.clone())
                                .collect::<Vec<_>>();
                            let dependencies = if package.dependencies.is_empty() {
                                "None".into()
                            } else {
                                package.dependencies.join("  ")
                            };
                            let installed_reason = if package.reason == 0 {
                                "Explicitly installed"
                            } else {
                                "Installed as a dependency for another package"
                            };
                            output.push(format!("Name            : {}\nVersion         : {}\nDescription     : {}\nArchitecture    : {}\nURL             : https://archlinux.org/packages/{}/x86_64/{}/\nLicenses        : GPL\nGroups          : None\nProvides        : None\nDepends On      : {}\nRequired By     : {}\nOptional For    : None\nConflicts With  : None\nReplaces        : None\nInstalled Size  : {} KiB\nPackager        : Arch Linux Package Maintainer <packages@archlinux.org>\nBuild Date      : {}\nInstall Date    : {}\nInstall Reason  : {}\nInstall Script  : No\nValidated By    : Signature\n", package.name, package.version, package.description, package.architecture, package.repository, package.name, dependencies, if required_by.is_empty() { "None".into() } else { required_by.join("  ") }, package.installed_size / 1024, package.build_date, package.install_date, installed_reason));
                        }
                        "-Ql" => {
                            for path in &package.files {
                                output.push(format!("{} {}", package.name, path));
                            }
                        }
                        "-Qk" | "-Qkk" => {
                            let (missing, altered) =
                                packages::check_arch_files(&self.fs, &package, action == "-Qkk");
                            output.push(format!(
                                "{}: {missing} missing files, {altered} altered files",
                                package.name
                            ));
                        }
                        "-Qq" => output.push(package.name.clone()),
                        _ => output.push(format!("{} {}", package.name, package.version)),
                    }
                }
                success(format!("{}\n", output.join("\n")))
            }
            "-S" => {
                if operands.is_empty() {
                    return failure("error: target not found: no package specified\n");
                }
                let mut next = self.fs.clone();
                let mut installed_names = Vec::new();
                for name in &operands {
                    let Some(package) = packages::arch_lookup(name) else {
                        return failure(format!("error: target not found: {name}\n"));
                    };
                    if let Err(error) = packages::install_arch(&mut next, package, now) {
                        return failure(format!(
                            "error: virtual package transaction failed: {error}\n"
                        ));
                    }
                    installed_names.push(format!("{}-{}", package.name, package.version));
                }
                self.fs = next;
                self.virtual_server.refresh_packages(&mut self.fs, now);
                let package_names = installed_names.join(" ");
                with_action(
                    success(format!(
                        "resolving dependencies...\nlooking for conflicting packages...\nPackages ({}) {package_names}\n:: Proceed with installation? [Y/n] y\n{}\n",
                        installed_names.len(),
                        installed_names
                            .iter()
                            .enumerate()
                            .map(|(index, name)| format!(
                                "({}/{}) installing {name}",
                                index + 1,
                                installed_names.len()
                            ))
                            .collect::<Vec<_>>()
                            .join("\n")
                    )),
                    FsActionKind::Modified,
                    "package_install",
                    packages::registry_path(self.fs.distribution()).into(),
                )
            }
            "-R" | "-Rs" | "-Rns" => {
                if operands.is_empty() {
                    return failure("error: target not found: no package specified\n");
                }
                let mut next = self.fs.clone();
                let mut removed = Vec::new();
                for name in &operands {
                    let Some(package) = packages::arch_installed(&next, name) else {
                        return failure(format!("error: target not found: {name}\n"));
                    };
                    if let Err(error) = packages::remove_arch(&mut next, &package, now) {
                        return failure(format!(
                            "error: virtual package removal failed: {error}\n"
                        ));
                    }
                    removed.push(format!("{}-{}", package.name, package.version));
                }
                self.fs = next;
                self.virtual_server.refresh_packages(&mut self.fs, now);
                with_action(
                    success(format!(
                        "checking dependencies...\nPackages ({}) {}\n:: Do you want to remove these packages? [Y/n] y\n{}\n",
                        removed.len(),
                        removed.join(" "),
                        removed
                            .iter()
                            .map(|name| format!("removing {name}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    )),
                    FsActionKind::Modified,
                    "package_remove",
                    packages::registry_path(self.fs.distribution()).into(),
                )
            }
            _ => failure(
                "pacman: supported operations: -S, -R, -Sy, -Syu, -Ss, -Si, -Q, -Qq, -Qi, -Ql, -Qo, -Qe, -Qdt, -Qk, -Qkk\n",
            ),
        }
    }

    fn dpkg(&self, args: &[String]) -> ShellOutput {
        let action = args.first().map(String::as_str).unwrap_or("");
        if action == "--print-architecture" {
            return success("amd64\n");
        }
        if action == "--version" {
            return self.fs.distribution().linux_profile().map_or_else(
                || failure("dpkg: command not found\n"),
                |profile| success(profile.dpkg_version_output),
            );
        }
        let status =
            String::from_utf8_lossy(self.fs.read("/var/lib/dpkg/status").unwrap_or_default())
                .into_owned();
        let records = status
            .split("\n\n")
            .filter(|record| dpkg_field(record, "Package:").is_some())
            .collect::<Vec<_>>();
        match action {
            "-L" | "--listfiles" => {
                let Some(package) = args.get(1).filter(|arg| !arg.starts_with('-')) else {
                    return failure("dpkg-query: package name required\n");
                };
                let Some(record) = records
                    .iter()
                    .find(|record| dpkg_field(record, "Package:") == Some(package))
                else {
                    return failure(format!(
                        "dpkg-query: package '{package}' is not installed\n"
                    ));
                };
                if !dpkg_field(record, "Status:").is_some_and(|state| state.ends_with("installed"))
                {
                    return failure(format!(
                        "dpkg-query: package '{package}' is not installed\n"
                    ));
                }
                let list_path = format!("/var/lib/dpkg/info/{package}.list");
                match self.fs.read(&list_path) {
                    Ok(contents) => success(format!(
                        "{}\n",
                        String::from_utf8_lossy(contents).trim_end()
                    )),
                    Err(_) => failure(format!(
                        "dpkg-query: no list file for package '{package}'\n"
                    )),
                }
            }
            "-S" | "--search" => {
                let Some(path) = args.get(1).filter(|arg| !arg.starts_with('-')) else {
                    return failure("dpkg-query: filename search pattern required\n");
                };
                let mut owners = Vec::new();
                if let Ok(files) = self.fs.list("/var/lib/dpkg/info") {
                    for (name, node) in files {
                        if node.is_dir() || !name.ends_with(".list") {
                            continue;
                        }
                        let list_path = format!("/var/lib/dpkg/info/{name}");
                        let listed = self
                            .fs
                            .read(&list_path)
                            .map(String::from_utf8_lossy)
                            .unwrap_or_default();
                        if listed.lines().any(|listed_path| listed_path == path) {
                            owners.push(format!("{}: {path}", name.trim_end_matches(".list")));
                        }
                    }
                }
                if owners.is_empty() {
                    failure(format!(
                        "dpkg-query: no path found matching pattern {path}\n"
                    ))
                } else {
                    success(format!("{}\n", owners.join("\n")))
                }
            }
            "-l" | "--list" => {
                let requested = args
                    .iter()
                    .skip(1)
                    .filter(|arg| !arg.starts_with('-'))
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                let mut rows = Vec::new();
                for record in &records {
                    let Some(name) = dpkg_field(record, "Package:") else {
                        continue;
                    };
                    let installed = dpkg_field(record, "Status:")
                        .is_some_and(|state| state.ends_with("installed"));
                    let residual = dpkg_field(record, "Status:")
                        .is_some_and(|state| state.ends_with("config-files"));
                    if (installed || residual)
                        && (requested.is_empty() || requested.contains(&name))
                    {
                        let state = if installed { "ii" } else { "rc" };
                        rows.push(format!(
                            "{state}  {:<20} {:<24} {:<10} {}",
                            name,
                            dpkg_field(record, "Version:").unwrap_or("(none)"),
                            dpkg_field(record, "Architecture:").unwrap_or("amd64"),
                            dpkg_field(record, "Description:").unwrap_or("")
                        ));
                    }
                }
                if !requested.is_empty()
                    && requested.iter().any(|name| {
                        !rows
                            .iter()
                            .any(|row| row.split_whitespace().nth(1) == Some(*name))
                    })
                {
                    let missing = requested
                        .iter()
                        .find(|name| {
                            !rows
                                .iter()
                                .any(|row| row.split_whitespace().nth(1) == Some(**name))
                        })
                        .copied()
                        .unwrap_or("");
                    return failure(format!(
                        "dpkg-query: no packages found matching {missing}\n"
                    ));
                }
                success(format!(
                    "Desired=Unknown/Install/Remove/Purge/Hold\n| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n||/ Name                 Version                  Architecture Description\n+++-====================-========================-============-\n{}\n",
                    rows.join("\n")
                ))
            }
            "-s" | "--status" => {
                let requested = args
                    .iter()
                    .skip(1)
                    .filter(|arg| !arg.starts_with('-'))
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                if requested.is_empty() {
                    return failure("dpkg-query: package name required\n");
                }
                let mut output = Vec::new();
                for name in requested {
                    if let Some(record) = records
                        .iter()
                        .find(|record| dpkg_field(record, "Package:") == Some(name))
                    {
                        output.push(record.trim().to_owned());
                    } else {
                        return failure(format!("dpkg-query: no packages found matching {name}\n"));
                    }
                }
                success(format!("{}\n", output.join("\n\n")))
            }
            "-W" | "--show" => {
                let requested = args
                    .iter()
                    .skip(1)
                    .filter(|arg| !arg.starts_with('-'))
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                let mut rows = Vec::new();
                for record in &records {
                    let Some(name) = dpkg_field(record, "Package:") else {
                        continue;
                    };
                    if requested.is_empty() || requested.contains(&name) {
                        rows.push(format!(
                            "{}\t{}",
                            name,
                            dpkg_field(record, "Version:").unwrap_or("(none)")
                        ));
                    }
                }
                success(format!("{}\n", rows.join("\n")))
            }
            _ => failure(
                "dpkg: supported operations: -l [package], -s package, -W [package], -L package, -S path, --print-architecture\n",
            ),
        }
    }

    fn apt_cache(&self, args: &[String]) -> ShellOutput {
        let action = args.first().map(String::as_str).unwrap_or("");
        match action {
            "policy" => {
                let name = args.get(1).map(String::as_str);
                let Some(name) = name else {
                    return failure("E: Package name is required\n");
                };
                let package = packages::lookup(name);
                let status = String::from_utf8_lossy(
                    self.fs.read("/var/lib/dpkg/status").unwrap_or_default(),
                )
                .into_owned();
                let record = status
                    .split("\n\n")
                    .find(|record| dpkg_field(record, "Package:") == Some(name));
                let Some(version) = package
                    .map(|package| packages::version_for(package, self.fs.distribution()))
                    .or_else(|| record.and_then(|record| dpkg_field(record, "Version:")))
                else {
                    return success(format!(
                        "{name}:\n  Installed: (none)\n  Candidate: (none)\n  Version table:\n"
                    ));
                };
                let installed = package.map_or_else(
                    || record.is_some(),
                    |package| packages::installed(&self.fs, package.name),
                );
                let profile = self.fs.distribution().linux_profile();
                let suite = profile.map_or("jammy/main", |profile| profile.apt_suite);
                let mirror = profile.map_or("http://archive.ubuntu.com/ubuntu", |profile| {
                    profile.apt_mirror
                });
                let codename = profile.map_or("jammy", |profile| profile.apt_codename);
                success(format!(
                    "{name}:\n  Installed: {}\n  Candidate: {version}\n  Version table:\n     {version} 500\n        500 {mirror} {codename} {suite} amd64 Packages\n",
                    if installed { version } else { "(none)" }
                ))
            }
            "show" | "showpkg" => {
                let Some(name) = args.get(1).map(String::as_str) else {
                    return failure("E: No packages found\n");
                };
                if let Some(package) = packages::lookup(name) {
                    success(format!(
                        "Package: {}\nVersion: {}\nArchitecture: amd64\nPriority: optional\nSection: web\nFilename: pool/main/{}/{}_{}_amd64.deb\nSize: {}\nDescription: {}\n",
                        package.name,
                        packages::version_for(package, self.fs.distribution()),
                        package.name.chars().next().unwrap_or('n'),
                        package.name,
                        packages::version_for(package, self.fs.distribution()),
                        package.archive_kib * 1024,
                        package.description
                    ))
                } else {
                    let status = String::from_utf8_lossy(
                        self.fs.read("/var/lib/dpkg/status").unwrap_or_default(),
                    )
                    .into_owned();
                    status
                        .split("\n\n")
                        .find(|record| dpkg_field(record, "Package:") == Some(name))
                        .map_or_else(
                            || failure("E: No packages found\n"),
                            |record| success(format!("{}\n", record.trim())),
                        )
                }
            }
            "search" => {
                let query = args.get(1).map(String::as_str).unwrap_or("");
                let output = packages::CATALOG
                    .iter()
                    .filter(|package| {
                        package.name.contains(query) || package.description.contains(query)
                    })
                    .map(|package| format!("{} - {}", package.name, package.description))
                    .collect::<Vec<_>>()
                    .join("\n");
                success(format!("{output}\n"))
            }
            "stats" => success(format!("{} packages found.\n", packages::CATALOG.len())),
            _ => failure("apt-cache: supported commands: policy, show, showpkg, search, stats\n"),
        }
    }

    fn hostnamectl(&mut self, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        match args.first().map(String::as_str).unwrap_or("status") {
            "status" | "--static" | "--transient" => {
                if args.first().is_some_and(|arg| arg.starts_with("--")) {
                    return success(format!("{}\n", self.hostname));
                }
                let distribution = self.fs.distribution();
                let pretty_name = distribution
                    .os_release()
                    .lines()
                    .find_map(|line| line.strip_prefix("PRETTY_NAME=\""))
                    .and_then(|line| line.strip_suffix('"'))
                    .unwrap_or(distribution.as_str());
                success(format!(
                    " Static hostname: {}\n       Icon name: computer-vm\n  Chassis: vm\nOperating System: {pretty_name}\n          Kernel: Linux {}\n    Architecture: x86-64\n",
                    self.hostname,
                    distribution.kernel_release()
                ))
            }
            "hostname" => success(format!("{}\n", self.hostname)),
            "set-hostname" => {
                let Some(hostname) = args.get(1) else {
                    return failure("hostnamectl: hostname is required\n");
                };
                if self.user != "root" {
                    return failure("Failed to set static hostname: Access denied\n");
                }
                if hostname.len() > 253
                    || hostname.is_empty()
                    || !hostname
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
                {
                    return failure("Could not set property: Invalid hostname\n");
                }
                self.hostname = hostname.clone();
                self.fs
                    .put_file("/etc/hostname", format!("{hostname}\n"), now);
                self.fs.put_file("/etc/hosts", format!("127.0.0.1 localhost\n127.0.1.1 {hostname}\n::1 localhost ip6-localhost ip6-loopback\n"), now);
                with_action(
                    success("\n"),
                    FsActionKind::Modified,
                    "set_hostname",
                    "/etc/hostname".into(),
                )
            }
            _ => failure("hostnamectl: supported commands: status, hostname, set-hostname\n"),
        }
    }

    fn hostname_command(&self, args: &[String]) -> ShellOutput {
        match args {
            [] => success(format!("{}\n", self.hostname)),
            [flag] if flag == "-I" => success("10.20.4.21\n"),
            [flag] if flag == "-i" => success("127.0.1.1\n"),
            [flag] if flag == "-s" => success(format!(
                "{}\n",
                self.hostname.split('.').next().unwrap_or(&self.hostname)
            )),
            [flag] if flag == "-f" => success(format!("{}\n", self.hostname)),
            [flag] if flag == "--help" => success(
                "Usage: hostname [OPTION]... [NAME]\n  -i, --ip-address  addresses for the hostname\n  -I, --all-ip-addresses  all addresses for the host\n",
            ),
            _ => failure("hostname: this virtual host does not allow changing its name\n"),
        }
    }

    fn nproc(&self, args: &[String]) -> ShellOutput {
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            return success(
                "Usage: nproc [OPTION]...\nPrint the number of processing units available.\n",
            );
        }
        let processors = self
            .fs
            .read("/proc/cpuinfo")
            .map(|contents| {
                String::from_utf8_lossy(contents)
                    .lines()
                    .filter(|line| line.starts_with("processor : "))
                    .count()
            })
            .unwrap_or(1)
            .max(1);
        success(format!("{processors}\n"))
    }

    fn lsblk(&self, args: &[String]) -> ShellOutput {
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            return success(
                "Usage: lsblk [OPTIONS] [<device> ...]\nList information about block devices.\n",
            );
        }
        if args.iter().any(|arg| arg == "-f" || arg == "--fs") {
            return success(
                "NAME   FSTYPE FSVER LABEL UUID                                 FSAVAIL FSUSE% MOUNTPOINTS\nsda1   ext4   1.0         7c2b7d42-4b9d-4f5c-a101-6d29aa9c1841   60.0G    22% /\n",
            );
        }
        success(
            "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\nsda      8:0    0   80G  0 disk\n└─sda1   8:1    0   80G  0 part /\n",
        )
    }

    fn service(&mut self, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        if args.len() < 2 {
            return failure("Usage: service <service> <action>\n");
        }
        let service = args[0].trim_end_matches(".service");
        let mut systemctl_args = vec![args[1].clone(), service.to_owned()];
        systemctl_args.extend(args[2..].iter().cloned());
        self.virtual_server
            .execute("systemctl", &systemctl_args, &self.cwd, &mut self.fs, now)
            .map(shell_output)
            .unwrap_or_else(|| failure(format!("{service}: unrecognized service\n")))
    }

    fn login_users(&self, command: &str, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            return success(match command {
                "who" => "Usage: who [OPTION]... [FILE | ARG1 ARG2]\n",
                "w" => "Usage: w [options] [user]\n",
                _ => "Usage: users [OPTION]... [FILE]\n",
            });
        }
        let timestamp = now.format("%Y-%m-%d %H:%M");
        match command {
            "users" => success(format!("{}\n", self.user)),
            "who" => success(format!("{} pts/0        {timestamp}\n", self.user)),
            "w" => success(format!(
                " {now} up 17 days,  1 user,  load average: 0.08, 0.04, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n{}     pts/0    203.0.113.42     {}    0.00s  0.02s  0.00s -bash\n",
                self.user,
                now.format("%H:%M")
            )),
            _ => failure(format!("{command}: command not found\n")),
        }
    }

    fn ping(&self, args: &[String]) -> ShellOutput {
        let mut count = 4_u32;
        let mut target = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "-c" | "-W" | "-i" => {
                    index += 1;
                    let Some(value) = args.get(index) else {
                        return failure(format!(
                            "ping: option requires an argument -- '{}'\n",
                            args[index - 1]
                        ));
                    };
                    if args[index - 1] == "-c" {
                        let Ok(parsed) = value.parse::<u32>() else {
                            return failure("ping: invalid count\n");
                        };
                        count = parsed.min(20);
                    }
                }
                arg if arg.starts_with('-') => {
                    return failure(format!(
                        "ping: invalid option -- '{}'\n",
                        arg.trim_start_matches('-')
                    ));
                }
                host => target = Some(host),
            }
            index += 1;
        }
        let Some(target) = target else {
            return failure("ping: usage error: Destination address required\n");
        };
        let count = count.max(1);
        let mut output = format!("PING {target} ({target}) 56(84) bytes of data.\n");
        for sequence in 1..=count {
            output.push_str(&format!(
                "64 bytes from {target}: icmp_seq={sequence} ttl=64 time=0.0{} ms\n",
                sequence % 9 + 1
            ));
        }
        output.push_str(&format!("\n--- {target} ping statistics ---\n{count} packets transmitted, {count} received, 0% packet loss, time {}ms\nrtt min/avg/max/mdev = 0.01/0.02/0.03/0.00 ms\n", count * 1000));
        success(output)
    }

    fn lsb_release(&self, args: &[String]) -> ShellOutput {
        let Some(profile) = self.fs.distribution().linux_profile() else {
            return failure("lsb_release: command not found\n");
        };
        let fields = [
            (
                "-i",
                "Distributor ID:",
                if self.fs.distribution() == Distribution::Ubuntu {
                    "Ubuntu"
                } else {
                    "Debian"
                },
            ),
            ("-d", "Description:", profile.operating_system_name),
            (
                "-r",
                "Release:",
                if self.fs.distribution() == Distribution::Ubuntu {
                    "22.04"
                } else {
                    "13"
                },
            ),
            ("-c", "Codename:", profile.apt_codename),
        ];
        if args.is_empty() || args.iter().any(|arg| arg == "-a" || arg == "--all") {
            return success(format!(
                "LSB Version:\tcore-11.1.0ubuntu4-amd64:core-11.1.0ubuntu4-noarch\n{}\t{}\n{}\t{}\n{}\t{}\n{}\t{}\n",
                fields[0].1,
                fields[0].2,
                fields[1].1,
                fields[1].2,
                fields[2].1,
                fields[2].2,
                fields[3].1,
                fields[3].2
            ));
        }
        let selected = fields
            .iter()
            .filter(|(flag, _, _)| args.iter().any(|arg| arg == flag))
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return failure("Usage: lsb_release [options]\n");
        }
        success(
            selected
                .into_iter()
                .map(|(_, label, value)| format!("{label}\t{value}\n"))
                .collect::<String>(),
        )
    }

    fn update_alternatives(&self, args: &[String]) -> ShellOutput {
        let action = args.first().map(String::as_str).unwrap_or("");
        let name = args
            .iter()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .map(String::as_str);
        match action {
            "--display" | "--query" => {
                if name != Some("editor") {
                    return failure(format!(
                        "update-alternatives: error: no alternatives for {}\n",
                        name.unwrap_or("")
                    ));
                }
                success(
                    "editor - auto mode\n  link best version is /usr/bin/nano\n  link currently points to /usr/bin/nano\n  link editor is /usr/bin/editor\n/usr/bin/nano - priority 40\n",
                )
            }
            "--list" => {
                if name == Some("editor") {
                    success("/usr/bin/nano\n")
                } else {
                    failure(format!(
                        "update-alternatives: error: no alternatives for {}\n",
                        name.unwrap_or("")
                    ))
                }
            }
            "--get-selections" => success("editor auto /usr/bin/nano\n"),
            _ => failure(
                "update-alternatives: supported options: --display name, --query name, --list name, --get-selections\n",
            ),
        }
    }

    fn which(&self, args: &[String]) -> ShellOutput {
        let Some(name) = args.first() else {
            return failure("which: missing command\n");
        };
        let path = self.executable_path(name);
        match path {
            Some(path) => success(format!("{path}\n")),
            None => failure(""),
        }
    }

    fn nginx(&self, args: &[String]) -> ShellOutput {
        let profile = self.fs.distribution().linux_profile();
        let executable = profile.map_or("/usr/sbin/nginx", |profile| profile.nginx_executable);
        if !packages::installed(&self.fs, "nginx") || !self.fs.exists(executable) {
            return failure("bash: nginx: command not found\n");
        }
        if args == ["-v"] || args == ["-V"] {
            let version = profile.map_or("1.30.4", |profile| profile.nginx_version);
            success(format!("nginx version: nginx/{version}\n"))
        } else {
            failure("nginx: [emerg] virtual service is managed by systemctl\n")
        }
    }

    fn sshd(&self, args: &[String]) -> ShellOutput {
        let profile = self.fs.distribution().linux_profile();
        let executable = profile.map_or("/usr/sbin/sshd", |profile| profile.sshd_executable);
        if !self.fs.is_executable(executable) {
            return failure("bash: sshd: command not found\n");
        }
        if args.iter().any(|arg| arg == "-V") {
            let version = profile.map_or("OpenSSH_9.6p1, OpenSSL 3.0.13", |profile| {
                profile.openssh_version
            });
            return success(format!("{version}\n"));
        }
        if args.iter().any(|arg| arg == "-t") {
            return if self.fs.exists("/etc/ssh/sshd_config") {
                success("")
            } else {
                failure("sshd: no hostkeys available -- exiting.\n")
            };
        }
        if args.iter().any(|arg| arg == "-T") {
            let root_login = if self
                .vulnerability_profiles
                .contains("ssh_root_login_enabled")
            {
                "yes"
            } else {
                "prohibit-password"
            };
            return success(format!(
                "port 22\naddressfamily any\nlistenaddress 0.0.0.0:22\npermitrootlogin {root_login}\npubkeyauthentication yes\npasswordauthentication yes\nallowtcpforwarding yes\nx11forwarding yes\nusepam yes\nsubsystem sftp /usr/lib/ssh/sftp-server\n"
            ));
        }
        failure("sshd: use systemctl to manage the virtual SSH service\n")
    }

    fn redis_server(&self, args: &[String]) -> ShellOutput {
        let Some(profile) = self.fs.distribution().linux_profile() else {
            return failure("bash: redis-server: command not found\n");
        };
        let Some(executable) = profile
            .redis_command
            .filter(|command| command.ends_with("redis-server"))
        else {
            return failure("bash: redis-server: command not found\n");
        };
        if !packages::installed(&self.fs, "redis-server") || !self.fs.exists(executable) {
            return failure("bash: redis-server: command not found\n");
        }
        if args == ["--version"] || args == ["-v"] {
            success("Redis server v=6.0.16 sha=virtual malloc=jemalloc bits=64\n")
        } else {
            failure("redis-server: use systemctl to manage this virtual service\n")
        }
    }

    fn valkey_server(&self, args: &[String]) -> ShellOutput {
        if self
            .fs
            .distribution()
            .linux_profile()
            .and_then(|profile| profile.redis_command)
            != Some("/usr/bin/valkey-server")
            || !packages::installed(&self.fs, "valkey")
            || !self.fs.exists("/usr/bin/valkey-server")
        {
            return failure("bash: valkey-server: command not found\n");
        }
        if args == ["--version"] || args == ["-v"] {
            success("Valkey server v=9.1.2 sha=virtual malloc=jemalloc bits=64\n")
        } else {
            failure("valkey-server: use systemctl to manage this virtual service\n")
        }
    }

    fn redis_cli(&mut self, executable: &str, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        let profile = self.fs.distribution().linux_profile();
        let pid_path = profile.map_or("/run/redis-server.pid", |profile| profile.redis_pid_file);
        if !self.fs.exists(pid_path) {
            return failure("Could not connect to Redis at 127.0.0.1:6379: Connection refused\n");
        }
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "-h" | "--host" | "-p" | "--port" | "-a" | "--pass" | "-n" | "-c" => {
                    index = (index + 2).min(args.len());
                }
                "--raw" | "--no-auth-warning" => index += 1,
                _ => break,
            }
        }
        let Some(command) = args.get(index).map(|value| value.to_ascii_uppercase()) else {
            return failure(
                "redis-cli: interactive mode is unavailable; provide a Redis command\n",
            );
        };
        let key = args.get(index + 1).cloned().unwrap_or_default();
        let store_path = profile.map_or("/var/lib/redis/virtual-store.json", |profile| {
            profile.redis_store_file
        });
        let mut store = self
            .fs
            .read(store_path)
            .ok()
            .and_then(|contents| {
                serde_json::from_slice::<std::collections::BTreeMap<String, String>>(contents).ok()
            })
            .unwrap_or_else(|| {
                std::collections::BTreeMap::from([
                    ("service:mode".into(), "production".into()),
                    ("app:environment".into(), "production".into()),
                    ("cache:health".into(), "ok".into()),
                ])
            });
        let mut result = match command.as_str() {
            "PING" => success("PONG\n"),
            "INFO" => success(
                "# Server\nredis_version:7.0.15\nmode:standalone\n# Keyspace\ndb0:keys=3,expires=0,avg_ttl=0\n",
            ),
            "DBSIZE" => success(format!("{}\n", store.len())),
            "KEYS" => {
                let pattern = args.get(index + 1).map(String::as_str).unwrap_or("*");
                let keys = store
                    .keys()
                    .filter(|key| pattern == "*" || key.as_str() == pattern)
                    .cloned()
                    .collect::<Vec<_>>();
                success(format!("{}\n", keys.join("\n")))
            }
            "GET" => store
                .get(&key)
                .map_or_else(|| success("(nil)\n"), |value| success(format!("{value}\n"))),
            "SET" if args.len() > index + 2 => {
                let value = args[index + 2].clone();
                store.insert(key.clone(), value);
                let serialized = serde_json::to_vec(&store).unwrap_or_default();
                let _ = self.fs.put_file(store_path, serialized, now);
                success("OK\n")
            }
            "DEL" => {
                let removed = store.remove(&key).is_some();
                let serialized = serde_json::to_vec(&store).unwrap_or_default();
                let _ = self.fs.put_file(store_path, serialized, now);
                success(format!("{}\n", u8::from(removed)))
            }
            "AUTH" => failure("ERR AUTH called without any password configured\n"),
            "QUIT" => success("OK\n"),
            _ => failure(format!("(error) ERR unknown command '{command}'\n")),
        };
        if self
            .vulnerability_profiles
            .contains("redis_unauthenticated_access")
        {
            result.vulnerability_attempts.push(VulnerabilityAttempt {
                profile_id: "redis_unauthenticated_access".into(),
                details: serde_json::json!({"source":"ssh_terminal","command":command,"key":key,"client":executable}),
            });
        }
        result
    }

    fn mysql_cli(&self, args: &[String]) -> ShellOutput {
        let mut username = "root";
        let mut password = "";
        let mut port = 3306_u16;
        let mut query = None;
        let mut index = 0;
        while index < args.len() {
            let arg = args[index].as_str();
            match arg {
                "-u" | "--user" => {
                    if let Some(value) = args.get(index + 1) {
                        username = value;
                    }
                    index += 2;
                }
                "-P" | "--port" => {
                    if let Some(value) = args.get(index + 1) {
                        port = value.parse().unwrap_or(0);
                    }
                    index += 2;
                }
                "-h" | "--host" => index += 2,
                "-e" | "--execute" => {
                    query = args.get(index + 1).map(String::as_str);
                    index += 2;
                }
                "-p" | "--password" => index += 1,
                _ if arg.starts_with("--user=") => {
                    username = &arg[7..];
                    index += 1;
                }
                _ if arg.starts_with("--port=") => {
                    port = arg[7..].parse().unwrap_or(0);
                    index += 1;
                }
                _ if arg.starts_with("-p") && arg.len() > 2 => {
                    password = &arg[2..];
                    index += 1;
                }
                _ if arg.starts_with("--password=") => {
                    password = &arg[11..];
                    index += 1;
                }
                _ => index += 1,
            }
        }
        if !self
            .vulnerability_profiles
            .contains("sql_database_weak_credentials")
            || port != 13306
        {
            return failure(format!(
                "ERROR 2002 (HY000): Can't connect to server on '127.0.0.1' ({port})\n"
            ));
        }
        let accepted_user = matches!(
            username.to_ascii_lowercase().as_str(),
            "app" | "admin" | "deploy" | "root" | "mysql" | "dbadmin"
        );
        let accepted_password = matches!(
            password.to_ascii_lowercase().as_str(),
            "admin"
                | "admin123"
                | "password"
                | "password1"
                | "123456"
                | "12345678"
                | "qwerty"
                | "letmein"
                | "welcome"
                | "ubuntu"
                | "toor"
        );
        let accepted = accepted_user && accepted_password;
        let mut result = if !accepted {
            failure(format!(
                "ERROR 1045 (28000): Access denied for user '{username}'@'localhost' (using password: {})\n",
                if password.is_empty() { "NO" } else { "YES" }
            ))
        } else if let Some(query) = query {
            let query = query.trim().trim_end_matches(';').to_ascii_lowercase();
            if query == "show databases" {
                success("Database\nbilling\ninformation_schema\nmysql\nperformance_schema\n")
            } else if query == "select version()" {
                success("version()\n8.0.36-mellcore\n")
            } else if query.contains("from users") {
                success(
                    "id\temail\trole\n1\talice@example.test\tadmin\n2\tops@example.test\toperator\n3\tdemo@example.test\tviewer\n",
                )
            } else {
                success("Query OK, 0 rows affected\n")
            }
        } else {
            success(
                "Welcome to the MySQL monitor.  Commands end with ; or \\g.\nYour MySQL connection id is 41\nServer version: 8.0.36-mellcore MySQL Community Server - GPL\n\nmysql> ",
            )
        };
        result.vulnerability_attempts.push(VulnerabilityAttempt {
            profile_id: "sql_database_weak_credentials".into(),
            details: serde_json::json!({"source":"ssh_terminal","database":"mysql","username":username,"accepted":accepted,"port":port}),
        });
        result
    }

    fn ftp_client(&self, args: &[String]) -> ShellOutput {
        let positional = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .map(String::as_str)
            .collect::<Vec<_>>();
        let host = positional
            .iter()
            .find(|value| {
                value.parse::<u16>().is_err()
                    && !["ls", "dir", "pwd", "bye", "quit", "anonymous"].contains(value)
            })
            .copied()
            .unwrap_or("localhost");
        let port = positional
            .iter()
            .find_map(|value| value.parse::<u16>().ok())
            .unwrap_or(21);
        if !self.vulnerability_profiles.contains("ftp_anonymous_login") || port != 2121 {
            return failure(format!(
                "ftp: connect: Connection refused ({host}:{port})\n"
            ));
        }
        let action = positional
            .iter()
            .find(|value| ["ls", "dir", "pwd", "get", "put"].contains(value))
            .copied()
            .unwrap_or("connect");
        let output = match action {
            "pwd" => {
                "Connected to localhost.\n220 (vsFTPd 3.0.5)\n230 Login successful.\n257 \"/\" is the current directory\n"
            }
            "ls" | "dir" => {
                "Connected to localhost.\n220 (vsFTPd 3.0.5)\n230 Login successful.\n-rw-r--r--    1 0        0              23 Oct 14 00:00 README.txt\ndrwxr-xr-x    2 0        0            4096 Oct 14 00:00 pub\n"
            }
            "get" => {
                "Connected to localhost.\n220 (vsFTPd 3.0.5)\n230 Login successful.\n150 Opening BINARY mode data connection.\n226 Transfer complete.\n"
            }
            "put" => {
                "Connected to localhost.\n220 (vsFTPd 3.0.5)\n230 Login successful.\n550 Permission denied.\n"
            }
            _ => {
                "Connected to localhost.\n220 (vsFTPd 3.0.5)\nName: anonymous\n230 Login successful.\nRemote system type is UNIX.\nUsing binary mode to transfer files.\nftp>\n"
            }
        };
        let mut result = success(output);
        result.vulnerability_attempts.push(VulnerabilityAttempt {
            profile_id: "ftp_anonymous_login".into(),
            details: serde_json::json!({"source":"ssh_terminal","username":"anonymous","port":port,"action":action,"accepted":true}),
        });
        result
    }

    fn curl(&self, args: &[String]) -> ShellOutput {
        if !packages::installed(&self.fs, "curl") || !self.fs.exists("/usr/bin/curl") {
            return failure("bash: curl: command not found\n");
        }
        let target = args
            .iter()
            .find(|arg| arg.starts_with("http://") || arg.starts_with("https://"))
            .map(String::as_str)
            .unwrap_or("");
        let method = args
            .windows(2)
            .find(|pair| pair[0] == "-X" || pair[0] == "--request")
            .map(|pair| pair[1].to_ascii_uppercase())
            .unwrap_or_else(|| {
                if args.iter().any(|arg| arg == "-d" || arg == "--data") {
                    "POST".into()
                } else {
                    "GET".into()
                }
            });
        let body = args
            .windows(2)
            .find(|pair| pair[0] == "-d" || pair[0] == "--data" || pair[0] == "--data-raw")
            .map(|pair| pair[1].as_str())
            .unwrap_or("");
        let url = target
            .strip_prefix("http://")
            .or_else(|| target.strip_prefix("https://"))
            .unwrap_or(target);
        let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
        let port = host_port
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or(if target.starts_with("https://") {
                443
            } else {
                80
            });
        let path = format!("/{path}");
        let is_loopback = host_port.starts_with("localhost")
            || host_port.starts_with("127.0.0.1")
            || host_port.starts_with("[::1]");

        if is_loopback
            && port == 2375
            && !self.vulnerability_profiles.contains("docker_api_exposed")
        {
            return failure(
                "curl: (7) Failed to connect to localhost port 2375: Connection refused\n",
            );
        }
        if is_loopback && port == 2375 && self.vulnerability_profiles.contains("docker_api_exposed")
        {
            let response = if path.starts_with("/version") {
                "{\"Version\":\"27.3.1\",\"ApiVersion\":\"1.47\",\"Os\":\"linux\",\"Arch\":\"amd64\"}\n"
            } else if path.starts_with("/info") {
                let os = self
                    .fs
                    .distribution()
                    .linux_profile()
                    .map_or("Linux", |profile| profile.operating_system_name);
                let mut result = success(format!(
                    "{{\"ID\":\"MELLCORE-DOCKER-01\",\"Containers\":4,\"ContainersRunning\":3,\"ContainersPaused\":0,\"ContainersStopped\":1,\"Images\":2,\"Driver\":\"overlay2\",\"OperatingSystem\":\"{os}\",\"NCPU\":4}}\n"
                ));
                result.vulnerability_attempts.push(VulnerabilityAttempt {
                    profile_id: "docker_api_exposed".into(),
                    details: serde_json::json!({"source":"ssh_terminal","method":method,"path":path}),
                });
                return result;
            } else if path.starts_with("/containers/json") {
                "[{\"Id\":\"9d42ab41cd73\",\"Names\":[\"/billing-api\"],\"Image\":\"registry.internal/billing-api:2.8.4\",\"State\":\"running\"},{\"Id\":\"5a7c091efc20\",\"Names\":[\"/billing-worker\"],\"Image\":\"registry.internal/billing-api:2.8.4\",\"State\":\"running\"},{\"Id\":\"a82f4c0d19e7\",\"Names\":[\"/redis\"],\"Image\":\"redis:7.2-alpine\",\"State\":\"running\"}]\n"
            } else {
                "{\"message\":\"page not found\"}\n"
            };
            let mut result = success(response);
            result.vulnerability_attempts.push(VulnerabilityAttempt {
                profile_id: "docker_api_exposed".into(),
                details: serde_json::json!({"source":"ssh_terminal","method":method,"path":path}),
            });
            return result;
        }

        if is_loopback && port == 8080 {
            let lowered = path.to_ascii_lowercase();
            if self.vulnerability_profiles.contains("web_path_traversal")
                && (lowered.contains("../")
                    || lowered.contains("%2e%2e")
                    || lowered.contains("..%2f"))
            {
                let mut result = success(
                    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\napp:x:1001:1001:Application:/home/app:/bin/bash\n",
                );
                result.vulnerability_attempts.push(VulnerabilityAttempt {
                    profile_id: "web_path_traversal".into(),
                    details: serde_json::json!({"source":"ssh_terminal","path":path}),
                });
                return result;
            }
            if self
                .vulnerability_profiles
                .contains("web_command_injection")
                && (path.contains("cmd=") || path.contains("host="))
                && (path.contains(';')
                    || path.contains('|')
                    || lowered.contains("%3b")
                    || lowered.contains("%7c"))
            {
                let mut result = success("uid=1001(app) gid=1001(app) groups=1001(app)\n");
                result.vulnerability_attempts.push(VulnerabilityAttempt {
                    profile_id: "web_command_injection".into(),
                    details: serde_json::json!({"source":"ssh_terminal","path":path,"executed":false}),
                });
                return result;
            }
            if self
                .vulnerability_profiles
                .contains("http_admin_panel_exposure")
            {
                if method == "POST"
                    && (path.starts_with("/login") || path.starts_with("/admin/login"))
                {
                    let accepted = [
                        "username=admin&password=admin",
                        "username=admin&password=admin123",
                        "username=admin&password=password",
                        "username=root&password=toor",
                    ]
                    .iter()
                    .any(|pair| body.contains(pair));
                    let mut result = if accepted {
                        success("<html><h1>Admin dashboard</h1><p>Welcome</p></html>\n")
                    } else {
                        failure("<html><h1>Invalid credentials</h1></html>\n")
                    };
                    result.vulnerability_attempts.push(VulnerabilityAttempt {
                        profile_id: "http_admin_panel_exposure".into(),
                        details: serde_json::json!({"source":"ssh_terminal","path":path,"method":method,"accepted":accepted}),
                    });
                    return result;
                }
                if path == "/" || path.starts_with("/admin") {
                    let mut result = success(
                        "<html><title>Administration</title><form method=post action=/login><input name=username><input name=password type=password><button>Sign in</button></form></html>\n",
                    );
                    result.vulnerability_attempts.push(VulnerabilityAttempt {
                        profile_id: "http_admin_panel_exposure".into(),
                        details: serde_json::json!({"source":"ssh_terminal","path":path,"method":method}),
                    });
                    return result;
                }
            }
            return success(
                "<html><title>Billing API</title><h1>Internal application</h1></html>\n",
            );
        }

        if is_loopback && (target == "http://localhost" || target == "http://127.0.0.1") {
            if self.fs.exists("/run/nginx.pid") {
                return success("<html><body><h1>Welcome to nginx!</h1></body></html>\n");
            }
            return failure(
                "curl: (7) Failed to connect to localhost port 80: Connection refused\n",
            );
        }
        failure("curl: (6) Could not resolve host\n")
    }

    fn vim(&self, args: &[String]) -> ShellOutput {
        if !packages::installed(&self.fs, "vim") || !self.fs.exists("/usr/bin/vim") {
            return failure("bash: vim: command not found\n");
        }
        if args == ["--version"] {
            success("VIM - Vi IMproved 8.2 (virtual Ubuntu build)\n")
        } else {
            failure("vim: interactive editor is unavailable in this virtual terminal\n")
        }
    }

    fn uptime(&self, now: DateTime<Utc>) -> ShellOutput {
        let duration = (now - self.started_at).to_std().unwrap_or_default();
        let days = duration.as_secs() / 86_400;
        let hours = duration.as_secs() / 3_600 % 24;
        let minutes = duration.as_secs() / 60 % 60;
        let uptime = if days > 0 {
            format!("{days} days, {hours}:{minutes:02}")
        } else {
            format!("{hours}:{minutes:02}")
        };
        success(format!(
            " {} up {uptime},  1 user,  load average: 0.08, 0.04, 0.01\n",
            now.format("%H:%M:%S")
        ))
    }

    fn df(&self, args: &[String]) -> ShellOutput {
        let human = args
            .iter()
            .any(|arg| arg == "-h" || arg == "--human-readable" || arg.contains('h'));
        let requested = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .map(String::as_str)
            .collect::<Vec<_>>();
        let mounts = self
            .fs
            .read("/proc/mounts")
            .ok()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        let mut output = if human {
            "Filesystem      Size  Used Avail Use% Mounted on\n".to_owned()
        } else {
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n".to_owned()
        };
        for line in mounts.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 2 {
                continue;
            }
            let device = fields[0];
            let mountpoint = fields[1];
            if !requested.is_empty() && !requested.contains(&mountpoint) {
                continue;
            }
            let (total, used, available, percent) = match mountpoint {
                "/" => (83_886_080_u64, 17_694_720_u64, 62_914_560_u64, "22%"),
                "/dev" => (2_048_000, 0, 2_048_000, "0%"),
                "/run" => (819_200, 1_024, 818_176, "1%"),
                "/dev/shm" => (524_288, 0, 524_288, "0%"),
                _ => continue,
            };
            if human {
                output.push_str(&format!(
                    "{device:<14} {:>5} {:>5} {:>5} {:>4} {mountpoint}\n",
                    human_kib(total),
                    human_kib(used),
                    human_kib(available),
                    percent
                ));
            } else {
                output.push_str(&format!(
                    "{device:<14} {total:>10} {used:>8} {available:>9} {percent:>4} {mountpoint}\n"
                ));
            }
        }
        if output.lines().count() == 1 {
            failure("df: no mounted filesystem matches the requested path\n")
        } else {
            success(output)
        }
    }

    fn du(&self, args: &[String]) -> ShellOutput {
        let human = args.iter().any(|arg| {
            arg == "--human-readable"
                || arg
                    .strip_prefix('-')
                    .is_some_and(|flags| !flags.starts_with('-') && flags.contains('h'))
        });
        let summarize = args.iter().any(|arg| arg == "-s" || arg == "--summarize");
        let raw = args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .map_or(".", String::as_str);
        let path = match self.path(raw) {
            Ok(path) => path,
            Err(error) => return fs_failure("du", raw, error),
        };
        fn size_kib(fs: &VirtualFileSystem, path: &str, user: &str) -> Result<u64, FsError> {
            let node = fs.node(path)?;
            if !node.is_dir() {
                fs.authorize_read(path, user)?;
                return Ok((node.len() as u64).div_ceil(1024).max(1));
            }
            fs.authorize_list(path, user)?;
            fs.list(path)?
                .into_iter()
                .try_fold(4_u64, |total, (name, child)| {
                    let child_path = if path == "/" {
                        format!("/{name}")
                    } else {
                        format!("{path}/{name}")
                    };
                    let bytes = if child.is_dir() {
                        size_kib(fs, &child_path, user)?
                    } else {
                        (child.len() as u64).div_ceil(1024).max(1)
                    };
                    Ok(total.saturating_add(bytes))
                })
        }
        let blocks = match size_kib(&self.fs, &path, &self.user) {
            Ok(blocks) => blocks,
            Err(error) => return fs_failure("du", raw, error),
        };
        let amount = if human {
            human_kib(blocks)
        } else {
            format!("{blocks}")
        };
        let display_path = if raw == "." { &self.cwd } else { raw };
        let _ = summarize;
        with_action(
            success(format!("{amount}\t{display_path}\n")),
            FsActionKind::Accessed,
            "du",
            path,
        )
    }

    fn free(&self, args: &[String]) -> ShellOutput {
        let Ok(contents) = self.fs.read("/proc/meminfo") else {
            return failure("free: cannot read /proc/meminfo\n");
        };
        let meminfo = String::from_utf8_lossy(contents);
        let values = meminfo
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                let value = value.split_whitespace().next()?.parse::<u64>().ok()?;
                Some((name, value))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let total = values.get("MemTotal").copied().unwrap_or_default();
        let free = values.get("MemFree").copied().unwrap_or_default();
        let available = values.get("MemAvailable").copied().unwrap_or(free);
        let buffers = values.get("Buffers").copied().unwrap_or_default();
        let cached = values.get("Cached").copied().unwrap_or_default();
        let buff_cache = buffers.saturating_add(cached);
        let used = total.saturating_sub(available);
        let swap_total = values.get("SwapTotal").copied().unwrap_or_default();
        let swap_free = values.get("SwapFree").copied().unwrap_or_default();
        let swap_used = swap_total.saturating_sub(swap_free);
        let human = args.iter().any(|arg| arg == "-h" || arg == "--human");
        let (total, used, free, buff_cache, available, swap_total, swap_used, swap_free) = if human
        {
            (
                human_kib(total),
                human_kib(used),
                human_kib(free),
                human_kib(buff_cache),
                human_kib(available),
                human_kib(swap_total),
                human_kib(swap_used),
                human_kib(swap_free),
            )
        } else {
            (
                total.to_string(),
                used.to_string(),
                free.to_string(),
                buff_cache.to_string(),
                available.to_string(),
                swap_total.to_string(),
                swap_used.to_string(),
                swap_free.to_string(),
            )
        };
        success(format!(
            "               total        used        free      shared  buff/cache   available\nMem:       {:>10} {:>11} {:>11} {:>10} {:>11} {:>11}\nSwap:      {:>10} {:>11} {:>11}\n",
            total, used, free, "0", buff_cache, available, swap_total, swap_used, swap_free
        ))
    }

    fn file(&self, args: &[String]) -> ShellOutput {
        let paths = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return failure("file: missing file operand\n");
        }
        let mut result = ShellOutput::default();
        for raw in paths {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure("file", raw, error),
            };
            if let Err(error) = self.fs.authorize_read(&path, &self.user) {
                return fs_failure("file", raw, error);
            }
            let node = match self.fs.node(&path) {
                Ok(node) => node,
                Err(error) => return fs_failure("file", raw, error),
            };
            let kind = if node.is_dir() {
                "directory"
            } else if let Ok(data) = self.fs.read(&path) {
                if data.starts_with(b"#!/") {
                    "POSIX shell script, ASCII text executable"
                } else if data.starts_with(b"ELF") {
                    "ELF 64-bit LSB executable, x86-64"
                } else if data.is_empty() {
                    "empty"
                } else if data.iter().all(|byte| {
                    *byte == b'\n'
                        || *byte == b'\r'
                        || *byte == b'\t'
                        || byte.is_ascii_graphic()
                        || *byte == b' '
                }) {
                    "ASCII text"
                } else {
                    "data"
                }
            } else {
                "symbolic link"
            };
            result.output.push_str(&format!("{}: {kind}\n", raw));
            result.fs_actions.push(FsAction {
                kind: FsActionKind::Accessed,
                operation: "read",
                path,
            });
        }
        result
    }

    fn environment(&self) -> BTreeMap<String, String> {
        let mut values = BTreeMap::from([
            ("HOME".into(), self.home.clone()),
            ("LANG".into(), "C.UTF-8".into()),
            ("LOGNAME".into(), self.user.clone()),
            (
                "PATH".into(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            ),
            ("PWD".into(), self.cwd.clone()),
            ("SHELL".into(), "/bin/bash".into()),
            ("SHLVL".into(), "1".into()),
            ("TERM".into(), "xterm-256color".into()),
            ("USER".into(), self.user.clone()),
        ]);
        for name in &self.exported_variables {
            if let Some(value) = self.variables.get(name) {
                values.insert(name.clone(), value.clone());
            }
        }
        values
    }

    fn env(&self, args: &[String]) -> ShellOutput {
        if args
            .iter()
            .any(|arg| arg == "-i" || arg == "--ignore-environment")
        {
            return success("");
        }
        success(
            self.environment()
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
    }

    fn printenv(&self, args: &[String]) -> ShellOutput {
        let values = self.environment();
        if args.is_empty() {
            return success(
                values
                    .into_iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n",
            );
        }
        let mut output = String::new();
        let mut status = 0;
        for name in args {
            if let Some(value) = values.get(name) {
                output.push_str(value);
                output.push('\n');
            } else {
                status = 1;
            }
        }
        ShellOutput {
            output,
            exit_status: status,
            ..ShellOutput::default()
        }
    }

    fn lscpu(&self, args: &[String]) -> ShellOutput {
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            return success("Usage: lscpu [options]\n");
        }
        success(
            "Architecture:                         x86_64\nCPU op-mode(s):                       32-bit, 64-bit\nByte Order:                           Little Endian\nCPU(s):                               4\nOn-line CPU(s) list:                  0-3\nThread(s) per core:                   1\nCore(s) per socket:                   4\nSocket(s):                            1\nNUMA node(s):                         1\nVendor ID:                            GenuineIntel\nModel name:                           Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz\nVirtualization:                       full\nHypervisor vendor:                    KVM\nL1d cache:                            192 KiB\nL1i cache:                            128 KiB\nL2 cache:                             5 MiB\nL3 cache:                             48 MiB\nNUMA node0 CPU(s):                    0-3\n",
        )
    }

    fn seq(&self, args: &[String]) -> ShellOutput {
        let mut number_args = Vec::new();
        let mut skip_next = false;
        for arg in args {
            if skip_next {
                skip_next = false;
                continue;
            }
            if arg == "-s" || arg == "--separator" {
                skip_next = true;
                continue;
            }
            if matches!(
                arg.as_str(),
                "-w" | "--equal-width" | "-f" | "--format" | "--help"
            ) {
                continue;
            }
            number_args.push(arg);
        }
        let numbers = number_args
            .iter()
            .map(|arg| arg.parse::<i64>())
            .collect::<Result<Vec<_>, _>>();
        let Ok(numbers) = numbers else {
            return failure("seq: invalid floating point argument\n");
        };
        let (start, step, end) = match numbers.as_slice() {
            [end] => (1, 1, *end),
            [start, end] => (*start, if start <= end { 1 } else { -1 }, *end),
            [start, step, end] if *step != 0 => (*start, *step, *end),
            _ => return failure("seq: usage: seq [FIRST [INCREMENT]] LAST\n"),
        };
        let distance = end.saturating_sub(start);
        if distance.unsigned_abs() > 10_000 || distance != 0 && distance.signum() != step.signum() {
            return failure("seq: invalid or excessive sequence range\n");
        }
        let mut output = String::new();
        let mut value = start;
        loop {
            if (step > 0 && value > end) || (step < 0 && value < end) {
                break;
            }
            output.push_str(&format!("{value}\n"));
            if output.len() > self.max_input_bytes.saturating_mul(16) {
                return failure("seq: output limit exceeded\n");
            }
            let Some(next) = value.checked_add(step) else {
                break;
            };
            value = next;
        }
        success(output)
    }

    fn tr(&self, args: &[String]) -> ShellOutput {
        let delete = args
            .first()
            .is_some_and(|arg| arg == "-d" || arg == "--delete");
        let squeeze = args
            .first()
            .is_some_and(|arg| arg == "-s" || arg == "--squeeze-repeats");
        let index = if delete || squeeze { 1 } else { 0 };
        let Some(from) = args.get(index) else {
            return failure("tr: missing operand\n");
        };
        let to = args.get(index + 1).map_or("", String::as_str);
        let input = self.pipe_input.as_deref().unwrap_or("");
        let from_chars = expand_tr_set(from);
        let to_chars = expand_tr_set(to);
        let mut output = String::with_capacity(input.len());
        let mut previous = None;
        for ch in input.chars() {
            let matched = from_chars.contains(&ch);
            if delete && matched {
                continue;
            }
            let mapped =
                if let Some(position) = from_chars.iter().position(|candidate| *candidate == ch) {
                    to_chars
                        .get(position)
                        .copied()
                        .or_else(|| to_chars.last().copied())
                        .unwrap_or(ch)
                } else {
                    ch
                };
            if squeeze && matched && previous == Some(mapped) {
                continue;
            }
            output.push(mapped);
            previous = Some(mapped);
        }
        success(output)
    }

    fn wc(&self, args: &[String]) -> ShellOutput {
        let lines_only = args.iter().any(|arg| arg == "-l" || arg == "--lines");
        let words_only = args.iter().any(|arg| arg == "-w" || arg == "--words");
        let bytes_only = args.iter().any(|arg| arg == "-c" || arg == "--bytes");
        let chars_only = args.iter().any(|arg| arg == "-m" || arg == "--chars");
        let files = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .collect::<Vec<_>>();
        if files.is_empty() {
            return success(wc_counts(
                self.pipe_input.as_deref().unwrap_or(""),
                lines_only,
                words_only,
                bytes_only,
                chars_only,
                "",
            ));
        }
        let mut result = ShellOutput::default();
        for raw in files {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure("wc", raw, error),
            };
            if let Err(error) = self.fs.authorize_read(&path, &self.user) {
                return fs_failure("wc", raw, error);
            }
            let data = match self.fs.read(&path) {
                Ok(data) => String::from_utf8_lossy(data),
                Err(error) => return fs_failure("wc", raw, error),
            };
            result.output.push_str(&wc_counts(
                &data, lines_only, words_only, bytes_only, chars_only, raw,
            ));
            result.fs_actions.push(FsAction {
                kind: FsActionKind::Accessed,
                operation: "read",
                path,
            });
        }
        result
    }

    fn sort(&self, args: &[String]) -> ShellOutput {
        let reverse = args.iter().any(|arg| arg == "-r" || arg == "--reverse");
        let numeric = args
            .iter()
            .any(|arg| arg == "-n" || arg == "--numeric-sort");
        let files = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .collect::<Vec<_>>();
        let mut contents = String::new();
        let mut result = ShellOutput::default();
        if files.is_empty() {
            contents = self.pipe_input.clone().unwrap_or_default();
        } else {
            for raw in files {
                let path = match self.path(raw) {
                    Ok(path) => path,
                    Err(error) => return fs_failure("sort", raw, error),
                };
                if let Err(error) = self.fs.authorize_read(&path, &self.user) {
                    return fs_failure("sort", raw, error);
                }
                match self.fs.read(&path) {
                    Ok(data) => contents.push_str(&String::from_utf8_lossy(data)),
                    Err(error) => return fs_failure("sort", raw, error),
                }
                result.fs_actions.push(FsAction {
                    kind: FsActionKind::Accessed,
                    operation: "read",
                    path,
                });
            }
        }
        let mut lines = contents.lines().collect::<Vec<_>>();
        if numeric {
            lines.sort_by(|left, right| {
                left.trim()
                    .parse::<f64>()
                    .unwrap_or_default()
                    .total_cmp(&right.trim().parse::<f64>().unwrap_or_default())
            });
        } else {
            lines.sort_unstable();
        }
        if reverse {
            lines.reverse();
        }
        result.output = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        result
    }

    fn rmdir(&mut self, args: &[String]) -> ShellOutput {
        let paths = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return failure("rmdir: missing operand\n");
        }
        let mut result = ShellOutput::default();
        for raw in paths {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure("rmdir", raw, error),
            };
            if !self.fs.is_dir(&path) {
                return fs_failure("rmdir", raw, FsError::NotDirectory);
            }
            if let Err(error) = self
                .fs
                .authorize_remove(&path, &self.user)
                .and_then(|_| self.fs.remove(&path, false))
            {
                return fs_failure("rmdir", raw, error);
            }
            result.fs_actions.push(FsAction {
                kind: FsActionKind::Modified,
                operation: "rmdir",
                path,
            });
        }
        result
    }

    fn mount(&self, args: &[String]) -> ShellOutput {
        let Some(raw_path) = args.iter().find(|arg| !arg.starts_with('-')) else {
            let mounts = self.fs.read("/proc/mounts").unwrap_or_default();
            return success(String::from_utf8_lossy(mounts).into_owned());
        };
        let mounts = String::from_utf8_lossy(self.fs.read("/proc/mounts").unwrap_or_default());
        match mounts
            .lines()
            .find(|row| row.split_whitespace().nth(1) == Some(raw_path.as_str()))
        {
            Some(row) => success(format!("{row}\n")),
            None => failure(format!("mount: {raw_path}: not mounted.\n")),
        }
    }

    fn findmnt(&self, args: &[String]) -> ShellOutput {
        let mut positional = Vec::new();
        let mut skip_next = false;
        for arg in args {
            if skip_next {
                skip_next = false;
                continue;
            }
            if matches!(arg.as_str(), "-o" | "--output" | "-t" | "--types") {
                skip_next = true;
                continue;
            }
            if !arg.starts_with('-') {
                positional.push(arg);
            }
        }
        let raw_target = positional.last().copied();
        let requested_column = args
            .iter()
            .find_map(|arg| arg.strip_prefix("-o").filter(|columns| !columns.is_empty()))
            .or_else(|| {
                args.windows(2)
                    .find(|pair| pair[0] == "-o")
                    .map(|pair| pair[1].as_str())
            });
        let mounts = String::from_utf8_lossy(self.fs.read("/proc/mounts").unwrap_or_default());
        let mut rows = Vec::new();
        let no_headings = args.iter().any(|arg| arg == "-n" || arg == "--noheadings");
        let include_header = requested_column.is_none() && !no_headings;
        if include_header {
            rows.push("TARGET SOURCE FSTYPE OPTIONS".to_owned());
        }
        for line in mounts.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 || raw_target.is_some_and(|target| fields[1] != target.as_str()) {
                continue;
            }
            let row = match requested_column {
                Some(columns) => columns
                    .split(',')
                    .map(|column| match column {
                        "SOURCE" => fields[0],
                        "TARGET" => fields[1],
                        "FSTYPE" => fields[2],
                        "OPTIONS" => fields[3],
                        _ => "",
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
                None => format!(
                    "{:<20} {:<20} {:<8} {}",
                    fields[1], fields[0], fields[2], fields[3]
                ),
            };
            rows.push(row);
        }
        if rows.is_empty() || include_header && rows.len() == 1 {
            return failure("findmnt: no mount point found\n");
        }
        success(rows.join("\n") + "\n")
    }

    fn history(&self) -> ShellOutput {
        let output = self
            .history
            .iter()
            .enumerate()
            .map(|(index, line)| format!("{:>5}  {line}", index + 1))
            .collect::<Vec<_>>()
            .join("\n");
        success(format!("{output}\n"))
    }

    fn mkdir(&mut self, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        let parents = args.iter().any(|arg| arg == "-p" || arg == "--parents");
        let paths = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return failure("mkdir: missing operand\n");
        }
        if !parents {
            return self.modify_many(
                "mkdir",
                &paths.into_iter().cloned().collect::<Vec<_>>(),
                now,
                |fs, path, now| fs.mkdir(path, now),
            );
        }
        let mut result = ShellOutput::default();
        for raw in paths {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure("mkdir", raw, error),
            };
            let mut current = String::new();
            for part in path.split('/').filter(|part| !part.is_empty()) {
                current.push('/');
                current.push_str(part);
                if self.fs.exists(&current) {
                    if !self.fs.is_dir(&current) {
                        return fs_failure("mkdir", raw, FsError::NotDirectory);
                    }
                    continue;
                }
                let group = self.fs.primary_group(&self.user);
                if let Err(error) = self
                    .fs
                    .authorize_write(&current, &self.user)
                    .and_then(|_| self.fs.mkdir(&current, now))
                {
                    return fs_failure("mkdir", raw, error);
                }
                if let Ok(node) = self.fs.node_mut(&current) {
                    node.owner = self.user.clone();
                    node.group = group;
                }
            }
            result.fs_actions.push(FsAction {
                kind: FsActionKind::Modified,
                operation: "mkdir",
                path,
            });
        }
        result
    }

    fn touch(&mut self, args: &[String], now: DateTime<Utc>) -> ShellOutput {
        self.modify_many("touch", args, now, |fs, path, now| fs.touch(path, now))
    }

    fn modify_many(
        &mut self,
        command: &'static str,
        args: &[String],
        now: DateTime<Utc>,
        operation: impl Fn(&mut VirtualFileSystem, &str, DateTime<Utc>) -> Result<(), FsError>,
    ) -> ShellOutput {
        if args.is_empty() {
            return failure(format!("{command}: missing operand\n"));
        }
        let mut result = ShellOutput::default();
        for raw in args {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure(command, raw, error),
            };
            let created = !self.fs.exists(&path);
            if let Err(error) = self
                .fs
                .authorize_write(&path, &self.user)
                .and_then(|_| operation(&mut self.fs, &path, now))
            {
                return fs_failure(command, raw, error);
            }
            if created {
                let group = self.fs.primary_group(&self.user);
                if let Ok(node) = self.fs.node_mut(&path) {
                    node.owner = self.user.clone();
                    node.group = group;
                }
            }
            result.fs_actions.push(FsAction {
                kind: FsActionKind::Modified,
                operation: command,
                path,
            });
        }
        result
    }

    fn rm(&mut self, args: &[String]) -> ShellOutput {
        let recursive = args.iter().any(|a| a == "-r" || a == "-rf" || a == "-fr");
        let operands: Vec<_> = args.iter().filter(|a| !a.starts_with('-')).collect();
        if operands.is_empty() {
            return failure("rm: missing operand\n");
        }
        let mut result = ShellOutput::default();
        for raw in operands {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure("rm", raw, error),
            };
            if let Err(error) = self
                .fs
                .authorize_remove(&path, &self.user)
                .and_then(|_| self.fs.remove(&path, recursive))
            {
                return fs_failure("rm", raw, error);
            }
            result.fs_actions.push(FsAction {
                kind: FsActionKind::Modified,
                operation: "remove",
                path,
            });
        }
        result
    }

    fn copy_move(&mut self, args: &[String], now: DateTime<Utc>, moving: bool) -> ShellOutput {
        let command = if moving { "mv" } else { "cp" };
        if args.len() != 2 {
            return failure(format!("{command}: expected source and destination\n"));
        }
        let source = match self.path(&args[0]) {
            Ok(path) => path,
            Err(error) => return fs_failure(command, &args[0], error),
        };
        let target = match self.path(&args[1]) {
            Ok(path) => path,
            Err(error) => return fs_failure(command, &args[1], error),
        };
        if let Err(error) = self
            .fs
            .authorize_read(&source, &self.user)
            .and_then(|_| self.fs.authorize_write(&target, &self.user))
            .and_then(|_| {
                if moving {
                    self.fs.authorize_remove(&source, &self.user)
                } else {
                    Ok(())
                }
            })
        {
            return fs_failure(command, &args[0], error);
        }
        let target_created = !self.fs.exists(&target);
        let operation = if moving {
            self.fs.rename(&source, &target, now)
        } else {
            self.fs.copy(&source, &target, now)
        };
        if let Err(error) = operation {
            return fs_failure(command, &args[0], error);
        }
        if target_created {
            let group = self.fs.primary_group(&self.user);
            if let Ok(node) = self.fs.node_mut(&target) {
                node.owner = self.user.clone();
                node.group = group;
            }
        }
        let mut result = ShellOutput::default();
        result.fs_actions.push(FsAction {
            kind: FsActionKind::Accessed,
            operation: "read",
            path: source,
        });
        result.fs_actions.push(FsAction {
            kind: FsActionKind::Modified,
            operation: command,
            path: target,
        });
        result
    }

    fn head_tail(&self, args: &[String], head: bool) -> ShellOutput {
        let command = if head { "head" } else { "tail" };
        if args.is_empty() || args.len() == 2 && args[0] == "-n" {
            if let Some(input) = &self.pipe_input {
                let count = if args.is_empty() {
                    10
                } else {
                    match args[1].parse::<usize>() {
                        Ok(value) if value <= 10_000 => value,
                        _ => return failure(format!("{command}: invalid number of lines\n")),
                    }
                };
                let lines: Vec<_> = input.lines().collect();
                let selected = if head {
                    &lines[..count.min(lines.len())]
                } else {
                    &lines[lines.len().saturating_sub(count)..]
                };
                return success(if selected.is_empty() {
                    String::new()
                } else {
                    format!("{}\n", selected.join("\n"))
                });
            }
        }
        let (count, raw) = match args {
            [path] => (10_usize, path.as_str()),
            [flag, count, path] if flag == "-n" => match count.parse::<usize>() {
                Ok(count) if count <= 10_000 => (count, path.as_str()),
                _ => return failure(format!("{command}: invalid number of lines\n")),
            },
            _ => return failure(format!("{command}: expected [-n count] file\n")),
        };
        let path = match self.path(raw) {
            Ok(path) => path,
            Err(error) => return fs_failure(command, raw, error),
        };
        if let Err(error) = self.fs.authorize_read(&path, &self.user) {
            return fs_failure(command, raw, error);
        }
        let data = match self.fs.read(&path) {
            Ok(data) => String::from_utf8_lossy(data),
            Err(error) => return fs_failure(command, raw, error),
        };
        let lines: Vec<_> = data.lines().collect();
        let selected = if head {
            &lines[..count.min(lines.len())]
        } else {
            &lines[lines.len().saturating_sub(count)..]
        };
        with_action(
            success(format!("{}\n", selected.join("\n"))),
            FsActionKind::Accessed,
            command,
            path,
        )
    }

    fn grep(&self, args: &[String]) -> ShellOutput {
        if args.len() == 1 {
            if let Some(input) = &self.pipe_input {
                let matches: Vec<_> = input
                    .lines()
                    .filter(|line| line.contains(&args[0]))
                    .collect();
                let mut result = success(if matches.is_empty() {
                    String::new()
                } else {
                    format!("{}\n", matches.join("\n"))
                });
                result.exit_status = u32::from(matches.is_empty());
                return result;
            }
        }
        if args.len() != 2 {
            return failure("grep: expected pattern and file\n");
        }
        let path = match self.path(&args[1]) {
            Ok(path) => path,
            Err(error) => return fs_failure("grep", &args[1], error),
        };
        if let Err(error) = self.fs.authorize_read(&path, &self.user) {
            return fs_failure("grep", &args[1], error);
        }
        let data = match self.fs.read(&path) {
            Ok(data) => String::from_utf8_lossy(data),
            Err(error) => return fs_failure("grep", &args[1], error),
        };
        let matches: Vec<_> = data
            .lines()
            .filter(|line| line.contains(&args[0]))
            .collect();
        let mut result = with_action(
            success(if matches.is_empty() {
                String::new()
            } else {
                format!("{}\n", matches.join("\n"))
            }),
            FsActionKind::Accessed,
            "grep",
            path,
        );
        result.exit_status = u32::from(matches.is_empty());
        result
    }

    fn find(&self, args: &[String]) -> ShellOutput {
        let mut raw = ".";
        let mut max_depth = None::<usize>;
        let mut file_type = None::<char>;
        let mut name_pattern = None::<String>;
        let mut index = 0;
        let mut has_path = false;
        while index < args.len() {
            match args[index].as_str() {
                "-maxdepth" | "-mindepth" => {
                    let option = args[index].as_str();
                    index += 1;
                    let Some(value) = args
                        .get(index)
                        .and_then(|value| value.parse::<usize>().ok())
                    else {
                        return failure(format!("find: invalid argument to '{option}'\n"));
                    };
                    if option == "-maxdepth" {
                        max_depth = Some(value);
                    }
                }
                "-type" => {
                    index += 1;
                    let Some(value) = args.get(index).filter(|value| {
                        value.len() == 1 && matches!(value.as_str(), "f" | "d" | "l")
                    }) else {
                        return failure("find: argument to -type must be one of f, d or l\n");
                    };
                    file_type = value.chars().next();
                }
                "-name" => {
                    index += 1;
                    let Some(value) = args.get(index) else {
                        return failure("find: missing argument to -name\n");
                    };
                    name_pattern = Some(value.clone());
                }
                "-print" | "-print0" => {}
                arg if arg.starts_with('-') => {
                    return failure(format!("find: unknown predicate '{arg}'\n"));
                }
                path if !has_path => {
                    raw = path;
                    has_path = true;
                }
                path => return failure(format!("find: paths must precede expressions: {path}\n")),
            }
            index += 1;
        }
        let path = match self.path(raw) {
            Ok(path) => path,
            Err(error) => return fs_failure("find", raw, error),
        };
        if let Err(error) = self.fs.authorize_list(&path, &self.user) {
            return fs_failure("find", raw, error);
        }
        let prefix = if path == "/" {
            "/".into()
        } else {
            format!("{path}/")
        };
        let matches = self
            .fs
            .all_paths()
            .filter(|candidate| {
                if !(*candidate == path || candidate.starts_with(&prefix))
                    || self.fs.authorize_traverse(candidate, &self.user).is_err()
                {
                    return false;
                }
                let depth = if *candidate == path {
                    0
                } else {
                    candidate
                        .strip_prefix(&prefix)
                        .map_or(usize::MAX, |relative| relative.matches('/').count() + 1)
                };
                if max_depth.is_some_and(|max_depth| depth > max_depth) {
                    return false;
                }
                let node_type = if self.fs.is_dir(candidate) {
                    'd'
                } else if self
                    .fs
                    .lstat(candidate)
                    .is_ok_and(|node| matches!(&node.kind, NodeKind::Symlink(_)))
                {
                    'l'
                } else {
                    'f'
                };
                if file_type.is_some_and(|expected| expected != node_type) {
                    return false;
                }
                let name = candidate.rsplit('/').next().unwrap_or(candidate);
                name_pattern.as_deref().is_none_or(|pattern| {
                    pattern == "*"
                        || (pattern.starts_with('*') && name.ends_with(&pattern[1..]))
                        || (pattern.ends_with('*')
                            && name.starts_with(&pattern[..pattern.len() - 1]))
                        || name == pattern
                })
            })
            .collect::<Vec<_>>();
        let output = if matches.is_empty() {
            String::new()
        } else {
            format!("{}\n", matches.join("\n"))
        };
        with_action(success(output), FsActionKind::Accessed, "find", path)
    }
}

fn expand_brace_sequence(value: &str) -> Option<Vec<String>> {
    let inner = value.strip_prefix('{')?.strip_suffix('}')?;
    let mut parts = inner.split("..");
    let start = parts.next()?.parse::<i64>().ok()?;
    let end = parts.next()?.parse::<i64>().ok()?;
    let step = parts
        .next()
        .map(str::parse::<i64>)
        .transpose()
        .ok()?
        .unwrap_or_else(|| if start <= end { 1 } else { -1 });
    if parts.next().is_some() || step == 0 || (end > start && step < 0) || (end < start && step > 0)
    {
        return None;
    }
    let mut values = Vec::new();
    let mut current = start;
    loop {
        values.push(current.to_string());
        if values.len() > 256 {
            return None;
        }
        if current == end {
            break;
        }
        let next = current.checked_add(step)?;
        if (step > 0 && next > end) || (step < 0 && next < end) {
            break;
        }
        current = next;
    }
    Some(values)
}

fn valid_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn find_control_end(words: &[String], start: usize) -> Option<usize> {
    let kind = words.get(start)?.as_str();
    let (opener, closer) = match kind {
        "for" => ("for", "done"),
        "if" => ("if", "fi"),
        _ => return None,
    };
    let mut nested = 0_usize;
    for index in start + 1..words.len() {
        let boundary =
            index == start + 1 || matches!(words[index - 1].as_str(), ";" | "do" | "then" | "else");
        if !boundary {
            continue;
        }
        if words[index] == opener {
            nested += 1;
        } else if words[index] == closer {
            if nested == 0 {
                return Some(index);
            }
            nested -= 1;
        }
    }
    None
}

fn find_top_level_else(words: &[String], start: usize, end: usize) -> Option<usize> {
    let mut nested_if = 0_usize;
    for index in start..end {
        let boundary =
            index == start || matches!(words[index - 1].as_str(), ";" | "do" | "then" | "else");
        if !boundary {
            continue;
        }
        match words[index].as_str() {
            "if" => nested_if += 1,
            "fi" if nested_if > 0 => nested_if -= 1,
            "else" if nested_if == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

fn numeric_test(left: &str, right: &str, predicate: impl FnOnce(i64, i64) -> bool) -> bool {
    left.parse::<i64>()
        .ok()
        .zip(right.parse::<i64>().ok())
        .is_some_and(|(left, right)| predicate(left, right))
}

fn wc_counts(
    contents: &str,
    lines_only: bool,
    words_only: bool,
    bytes_only: bool,
    chars_only: bool,
    name: &str,
) -> String {
    let mut counts = Vec::new();
    let all_counts = !lines_only && !words_only && !bytes_only && !chars_only;
    if all_counts || lines_only {
        counts.push(
            contents
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                .to_string(),
        );
    }
    if all_counts || words_only {
        counts.push(contents.split_whitespace().count().to_string());
    }
    if all_counts || bytes_only {
        counts.push(contents.len().to_string());
    } else if chars_only {
        counts.push(contents.chars().count().to_string());
    }
    if !name.is_empty() {
        counts.push(name.to_owned());
    }
    counts.join(" ") + "\n"
}

fn expand_tr_set(value: &str) -> Vec<char> {
    let class = match value {
        "[:lower:]" => Some(('a'..='z').collect()),
        "[:upper:]" => Some(('A'..='Z').collect()),
        "[:digit:]" => Some(('0'..='9').collect()),
        "[:space:]" => Some(vec![' ', '\t', '\n', '\r', '\u{000b}', '\u{000c}']),
        _ => None,
    };
    if let Some(class) = class {
        return class;
    }
    let mut chars = Vec::new();
    let mut source = value.chars().peekable();
    while let Some(start) = source.next() {
        let start = if start == '\\' {
            match source.next() {
                Some('n') => '\n',
                Some('t') => '\t',
                Some('\\') => '\\',
                Some(ch) => ch,
                None => '\\',
            }
        } else {
            start
        };
        if source.peek() == Some(&'-') {
            let mut range = source.clone();
            range.next();
            if let Some(end) = range.next()
                && start <= end
            {
                source.next();
                source.next();
                chars.extend(start..=end);
                continue;
            }
        }
        chars.push(start);
    }
    chars
}

#[derive(Clone, Debug)]
enum ArithmeticToken {
    Number(i64),
    Operator(char),
    LeftParen,
    RightParen,
}

fn evaluate_arithmetic(expression: &str, variables: &BTreeMap<String, String>) -> Option<i64> {
    let mut tokens = Vec::new();
    let mut chars = expression.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }
        if ch.is_ascii_digit() {
            let mut literal = String::from(ch);
            while chars
                .peek()
                .is_some_and(|next| next.is_ascii_alphanumeric() || *next == 'x' || *next == 'X')
            {
                literal.push(chars.next()?);
            }
            let number = if let Some(hex) = literal
                .strip_prefix("0x")
                .or_else(|| literal.strip_prefix("0X"))
            {
                i64::from_str_radix(hex, 16).ok()?
            } else if literal.len() > 1 && literal.starts_with('0') {
                i64::from_str_radix(&literal[1..], 8).ok()?
            } else {
                literal.parse().ok()?
            };
            tokens.push(ArithmeticToken::Number(number));
        } else if ch.is_ascii_alphabetic() || ch == '_' {
            let mut name = String::from(ch);
            while chars
                .peek()
                .is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_')
            {
                name.push(chars.next()?);
            }
            let value = variables
                .get(&name)
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_default();
            tokens.push(ArithmeticToken::Number(value));
        } else {
            tokens.push(match ch {
                '(' => ArithmeticToken::LeftParen,
                ')' => ArithmeticToken::RightParen,
                '+' | '-' | '*' | '/' | '%' => ArithmeticToken::Operator(ch),
                _ => return None,
            });
        }
    }
    let mut index = 0;
    let value = parse_arithmetic_expression(&tokens, &mut index, 0)?;
    (index == tokens.len()).then_some(value)
}

fn parse_arithmetic_expression(
    tokens: &[ArithmeticToken],
    index: &mut usize,
    minimum_precedence: u8,
) -> Option<i64> {
    let first = tokens.get(*index)?.clone();
    *index += 1;
    let mut left = match first {
        ArithmeticToken::Number(value) => value,
        ArithmeticToken::Operator('+') => parse_arithmetic_expression(tokens, index, 3)?,
        ArithmeticToken::Operator('-') => {
            parse_arithmetic_expression(tokens, index, 3)?.checked_neg()?
        }
        ArithmeticToken::LeftParen => {
            let value = parse_arithmetic_expression(tokens, index, 0)?;
            if !matches!(tokens.get(*index), Some(ArithmeticToken::RightParen)) {
                return None;
            }
            *index += 1;
            value
        }
        _ => return None,
    };
    loop {
        let Some(ArithmeticToken::Operator(operator)) = tokens.get(*index) else {
            break;
        };
        let precedence = match operator {
            '+' | '-' => 1,
            '*' | '/' | '%' => 2,
            _ => 0,
        };
        if precedence < minimum_precedence {
            break;
        }
        let operator = *operator;
        *index += 1;
        let right = parse_arithmetic_expression(tokens, index, precedence + 1)?;
        left = match operator {
            '+' => left.checked_add(right)?,
            '-' => left.checked_sub(right)?,
            '*' => left.checked_mul(right)?,
            '/' => left.checked_div(right)?,
            '%' => left.checked_rem(right)?,
            _ => return None,
        };
    }
    Some(left)
}

fn append_shell_output(combined: &mut ShellOutput, mut result: ShellOutput) {
    combined.output.push_str(&result.output);
    combined.exit_status = result.exit_status;
    combined.stream_output |= result.stream_output;
    combined.close |= result.close;
    combined.fs_actions.append(&mut result.fs_actions);
    combined
        .virtual_interactions
        .append(&mut result.virtual_interactions);
    combined.bait_opens.append(&mut result.bait_opens);
    combined
        .vulnerability_attempts
        .append(&mut result.vulnerability_attempts);
    if result.deception.is_some() {
        combined.deception = result.deception;
    }
}

fn ensure_virtual_directory(fs: &mut VirtualFileSystem, path: &str, now: DateTime<Utc>) {
    let mut current = String::new();
    for part in path.split('/').filter(|part| !part.is_empty()) {
        current.push('/');
        current.push_str(part);
        if !fs.exists(&current) {
            fs.mkdir(&current, now)
                .expect("validated virtual account home path has a valid parent");
        } else {
            assert!(
                fs.is_dir(&current),
                "virtual account home path is not a directory"
            );
        }
    }
}

fn shell_output(command: VirtualCommand) -> ShellOutput {
    ShellOutput {
        output: command.output,
        exit_status: command.exit_status,
        fs_actions: command
            .artifacts
            .into_iter()
            .map(|action| FsAction {
                kind: if action.modified {
                    FsActionKind::Modified
                } else {
                    FsActionKind::Accessed
                },
                operation: action.operation,
                path: action.path,
            })
            .collect(),
        virtual_interactions: vec![command.interaction],
        ..ShellOutput::default()
    }
}

fn bait_for_path(path: &str) -> Option<&'static str> {
    if path.starts_with("/proc/") || path == "/proc" {
        Some("processes")
    } else if path.starts_with("/home/") && path.ends_with("/.bash_history") {
        Some("history")
    } else if path.contains("authorized_keys") || path.starts_with("/var/spool/cron") {
        Some("persistence")
    } else if path.starts_with("/var/backups/") {
        Some("backups")
    } else if path.starts_with("/srv/billing-api/.env")
        || (path.starts_with("/home/")
            && (path.ends_with("/.ssh/id_deploy") || path.ends_with("/.ssh/config")))
        || path.starts_with("/root/.aws/")
        || path.starts_with("/etc/billing/")
    {
        Some("secrets")
    } else if path.starts_with("/srv/billing-api/") {
        Some("git")
    } else {
        None
    }
}

fn long_entry(name: &str, node: &Node) -> String {
    let mut permissions = node.permissions.display(node.is_dir());
    let label = if let NodeKind::Symlink(target) = &node.kind {
        permissions.replace_range(0..1, "l");
        format!("{name} -> {target}")
    } else {
        name.to_owned()
    };
    format!(
        "{} 1 {:<8} {:<8} {:>8} {} {}",
        permissions,
        node.owner,
        node.group,
        node.len(),
        node.modified_at.format("%b %e %H:%M"),
        label
    )
}

fn dpkg_field<'a>(record: &'a str, field: &str) -> Option<&'a str> {
    record
        .lines()
        .find_map(|line| line.strip_prefix(field).map(str::trim))
}

fn decode_escapes(value: &str) -> String {
    let mut chars = value.chars().peekable();
    let mut output = String::with_capacity(value.len());
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => output.push('\n'),
            Some('r') => output.push('\r'),
            Some('t') => output.push('\t'),
            Some('b') => output.push('\u{0008}'),
            Some('a') => output.push('\u{0007}'),
            Some('\\') => output.push('\\'),
            Some('x') => {
                let first = chars.next();
                let second = chars.next_if(|ch| ch.is_ascii_hexdigit());
                let hex = first.into_iter().chain(second).collect::<String>();
                if let Ok(code) = u32::from_str_radix(&hex, 16) {
                    if let Some(value) = char::from_u32(code) {
                        output.push(value);
                    }
                }
            }
            Some(other) => {
                output.push('\\');
                output.push(other);
            }
            None => output.push('\\'),
        }
    }
    output
}

fn parse_mode(value: &str) -> Option<u16> {
    let digits = value.strip_prefix("0o").unwrap_or(value);
    u16::from_str_radix(digits, 8)
        .ok()
        .filter(|mode| *mode <= 0o7777)
}

fn stable_inode(path: &str) -> u64 {
    path.bytes().fold(14695981039346656037_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(1099511628211)
    })
}

fn configure_virtual_sshd(
    fs: &mut VirtualFileSystem,
    profiles: &std::collections::BTreeSet<String>,
    now: DateTime<Utc>,
) {
    let root_login = profiles.contains("ssh_root_login_enabled");
    let existing = fs
        .read("/etc/ssh/sshd_config")
        .map(|contents| String::from_utf8_lossy(contents).into_owned())
        .unwrap_or_else(|_| {
            "Port 22\nPubkeyAuthentication yes\nPasswordAuthentication yes\n".into()
        });
    let mut lines = existing
        .lines()
        .filter(|line| {
            !line
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("permitrootlogin ")
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    lines.push(format!(
        "PermitRootLogin {}",
        if root_login {
            "yes"
        } else {
            "prohibit-password"
        }
    ));
    let _ = fs.put_file(
        "/etc/ssh/sshd_config",
        format!("{}\n", lines.join("\n")),
        now,
    );
}

fn docker_tcp_api_target(args: &[String]) -> bool {
    args.iter().enumerate().any(|(index, arg)| {
        let host = arg
            .strip_prefix("--host=")
            .or_else(|| arg.strip_prefix("-H="))
            .or_else(|| {
                matches!(arg.as_str(), "-H" | "--host")
                    .then(|| args.get(index + 1).map(String::as_str))
                    .flatten()
            });
        host.is_some_and(|host| matches!(host, "tcp://127.0.0.1:2375" | "tcp://localhost:2375"))
    })
}

fn human_kib(kib: u64) -> String {
    if kib < 1024 {
        return format!("{kib}K");
    }
    let mut amount = kib as f64;
    let mut unit = "K";
    for next in ["M", "G", "T", "P"] {
        amount /= 1024.0;
        unit = next;
        if amount < 1024.0 {
            break;
        }
    }
    format!("{amount:.1}{unit}")
}

fn is_shell_builtin(name: &str) -> bool {
    matches!(
        name,
        "cd" | "echo"
            | "printf"
            | "export"
            | "unset"
            | "pwd"
            | "true"
            | "false"
            | "command"
            | "history"
            | "test"
            | "["
            | "type"
            | "umask"
            | "clear"
            | "exit"
            | "logout"
    )
}

fn success(output: impl Into<String>) -> ShellOutput {
    ShellOutput {
        output: output.into(),
        ..ShellOutput::default()
    }
}

fn failure(output: impl Into<String>) -> ShellOutput {
    ShellOutput {
        output: output.into(),
        exit_status: 1,
        ..ShellOutput::default()
    }
}

fn fs_failure(command: &str, path: &str, error: FsError) -> ShellOutput {
    if command == "touch" {
        failure(format!("touch: cannot touch '{path}': {error}\n"))
    } else {
        failure(format!("{command}: {path}: {error}\n"))
    }
}

fn with_action(
    mut output: ShellOutput,
    kind: FsActionKind,
    operation: &'static str,
    path: String,
) -> ShellOutput {
    output.fs_actions.push(FsAction {
        kind,
        operation,
        path,
    });
    output
}
