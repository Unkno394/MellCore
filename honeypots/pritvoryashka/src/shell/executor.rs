use chrono::{DateTime, Utc};

use crate::{
    deception::{DeceptionEngine, DeceptionMetrics, Transition},
    filesystem::{FsError, VirtualFileSystem, node::Node},
};

use super::model::{VirtualCommand, VirtualInteraction, VirtualServer};
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
    pub close: bool,
    pub fs_actions: Vec<FsAction>,
    pub deception: Option<Transition>,
    pub virtual_interactions: Vec<VirtualInteraction>,
}

#[derive(Clone)]
pub struct Shell {
    cwd: String,
    user: String,
    hostname: String,
    history: Vec<String>,
    fs: VirtualFileSystem,
    deception: DeceptionEngine,
    virtual_server: VirtualServer,
    max_input_bytes: usize,
    started_at: DateTime<Utc>,
}

impl Shell {
    pub fn new(hostname: &str, max_input_bytes: usize, now: DateTime<Utc>) -> Self {
        let mut fs = VirtualFileSystem::linux(hostname, now);
        let virtual_server = VirtualServer::new(&mut fs, now);
        let history = VirtualServer::initial_history();
        virtual_server.sync_history(&mut fs, &history, now);
        Self {
            cwd: "/home/admin".into(),
            user: "admin".into(),
            hostname: hostname.into(),
            history,
            fs,
            deception: DeceptionEngine::default(),
            virtual_server,
            max_input_bytes,
            started_at: now,
        }
    }

    pub fn prompt(&self) -> String {
        let shown = self.cwd.strip_prefix("/home/admin").map_or_else(
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

    fn path(&self, raw: &str) -> Result<String, FsError> {
        let expanded = if raw == "~" {
            "/home/admin".to_owned()
        } else if let Some(rest) = raw.strip_prefix("~/") {
            format!("/home/admin/{rest}")
        } else {
            raw.to_owned()
        };
        VirtualFileSystem::normalize(&self.cwd, &expanded)
    }

    pub fn execute(&mut self, line: &str, now: DateTime<Utc>) -> ShellOutput {
        let line = line.trim_end_matches(['\r', '\n']);
        if !line.trim().is_empty() {
            self.history.push(line.to_owned());
            if self.history.len() > 1000 {
                self.history.remove(0);
            }
            self.virtual_server
                .sync_history(&mut self.fs, &self.history, now);
        }
        let words = match parser::parse(line, self.max_input_bytes) {
            Ok(words) => words,
            Err(error) => return failure(format!("bash: {error}\n")),
        };
        let Some((command, args)) = words.split_first() else {
            return ShellOutput::default();
        };
        let deception = self.deception.observe(command, args, &mut self.fs, now);
        let virtual_command =
            self.virtual_server
                .execute(command, args, &self.cwd, &mut self.fs, now);
        let mut result = if let Some(result) = virtual_command {
            shell_output(result)
        } else {
            match command.as_str() {
                "pwd" => success(format!("{}\n", self.cwd)),
                "cd" => self.cd(args),
                "ls" => self.ls(args),
                "cat" => self.cat(args),
                "echo" => success(format!("{}\n", self.expand_environment(args).join(" "))),
                "whoami" => success(format!("{}\n", self.user)),
                "id" => success("uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)\n"),
                "uname" => self.uname(args),
                "hostname" => success(format!("{}\n", self.hostname)),
                "date" => success(format!("{}\n", now.format("%a %b %e %T UTC %Y"))),
                "uptime" => self.uptime(now),
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
                _ => failure(format!("bash: {command}: command not found\n")),
            }
        };
        for action in &result.fs_actions {
            self.deception.record_object(&action.path);
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
                target: Some("/home/admin/.bash_history".into()),
                success: result.exit_status == 0,
            });
        }
        result.deception = deception;
        result
    }

    fn expand_environment(&self, args: &[String]) -> Vec<String> {
        args.iter()
            .map(|value| {
                value
                    .replace("${HOME}", "/home/admin")
                    .replace("$HOME", "/home/admin")
                    .replace("${USER}", &self.user)
                    .replace("$USER", &self.user)
                    .replace("${HOSTNAME}", &self.hostname)
                    .replace("$HOSTNAME", &self.hostname)
                    .replace("${SHELL}", "/bin/bash")
                    .replace("$SHELL", "/bin/bash")
                    .replace("${PWD}", &self.cwd)
                    .replace("$PWD", &self.cwd)
            })
            .collect()
    }

    fn cd(&mut self, args: &[String]) -> ShellOutput {
        if args.len() > 1 {
            return failure("bash: cd: too many arguments\n");
        }
        let raw = args.first().map_or("/home/admin", String::as_str);
        let path = match self.path(raw) {
            Ok(path) => path,
            Err(error) => return fs_failure("cd", raw, error),
        };
        if !self.fs.exists(&path) {
            return fs_failure("cd", raw, FsError::NotFound);
        }
        if !self.fs.is_dir(&path) {
            return fs_failure("cd", raw, FsError::NotDirectory);
        }
        self.cwd = path.clone();
        with_action(success(""), FsActionKind::Accessed, "cd", path)
    }

    fn ls(&self, args: &[String]) -> ShellOutput {
        let long = args
            .iter()
            .any(|arg| arg == "-l" || arg == "-la" || arg == "-al");
        let raw = args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .map_or(".", String::as_str);
        let path = match self.path(raw) {
            Ok(path) => path,
            Err(error) => return fs_failure("ls", raw, error),
        };
        let node = match self.fs.node(&path) {
            Ok(node) => node,
            Err(error) => return fs_failure("ls", raw, error),
        };
        let output = if node.is_dir() {
            match self.fs.list(&path) {
                Ok(entries) if long => {
                    entries
                        .into_iter()
                        .map(|(name, node)| long_entry(&name, node))
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n"
                }
                Ok(entries) => {
                    entries
                        .into_iter()
                        .map(|(name, _)| name)
                        .collect::<Vec<_>>()
                        .join("  ")
                        + "\n"
                }
                Err(error) => return fs_failure("ls", raw, error),
            }
        } else {
            format!("{}\n", path.rsplit('/').next().unwrap_or(&path))
        };
        with_action(success(output), FsActionKind::Accessed, "list", path)
    }

    fn cat(&self, args: &[String]) -> ShellOutput {
        if args.is_empty() {
            return failure("cat: missing operand\n");
        }
        let mut result = ShellOutput::default();
        for raw in args {
            let path = match self.path(raw) {
                Ok(path) => path,
                Err(error) => return fs_failure("cat", raw, error),
            };
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
        if args.iter().any(|arg| arg == "-a") {
            success(format!(
                "Linux {} 5.15.0-119-generic #129-Ubuntu SMP x86_64 GNU/Linux\n",
                self.hostname
            ))
        } else {
            success("Linux\n")
        }
    }

    fn uptime(&self, now: DateTime<Utc>) -> ShellOutput {
        let minutes = (now - self.started_at).num_minutes().max(0);
        success(format!(
            " 12:41:08 up {} min,  1 user,  load average: 0.08, 0.04, 0.01\n",
            minutes
        ))
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
        self.modify_many("mkdir", args, now, |fs, path, now| fs.mkdir(path, now))
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
            if let Err(error) = operation(&mut self.fs, &path, now) {
                return fs_failure(command, raw, error);
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
            if let Err(error) = self.fs.remove(&path, recursive) {
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
        let operation = if moving {
            self.fs.rename(&source, &target, now)
        } else {
            self.fs.copy(&source, &target, now)
        };
        if let Err(error) = operation {
            return fs_failure(command, &args[0], error);
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
        if args.len() != 2 {
            return failure("grep: expected pattern and file\n");
        }
        let path = match self.path(&args[1]) {
            Ok(path) => path,
            Err(error) => return fs_failure("grep", &args[1], error),
        };
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
        if args.len() > 1 {
            return failure("find: only a start path is supported\n");
        }
        let raw = args.first().map_or(".", String::as_str);
        let path = match self.path(raw) {
            Ok(path) => path,
            Err(error) => return fs_failure("find", raw, error),
        };
        if !self.fs.exists(&path) {
            return fs_failure("find", raw, FsError::NotFound);
        }
        let prefix = if path == "/" {
            "/".into()
        } else {
            format!("{path}/")
        };
        let output = self
            .fs
            .all_paths()
            .filter(|candidate| *candidate == path || candidate.starts_with(&prefix))
            .collect::<Vec<_>>()
            .join("\n");
        with_action(
            success(format!("{output}\n")),
            FsActionKind::Accessed,
            "find",
            path,
        )
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
    } else if path == "/home/admin/.bash_history" {
        Some("history")
    } else if path.contains("authorized_keys") || path.starts_with("/var/spool/cron") {
        Some("persistence")
    } else if path.starts_with("/var/backups/") {
        Some("backups")
    } else if path.starts_with("/srv/billing-api/.env")
        || path == "/home/admin/.ssh/id_deploy"
        || path == "/home/admin/.ssh/config"
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
    format!(
        "{} 1 {:<8} {:<8} {:>8} {} {}",
        node.permissions.display(node.is_dir()),
        node.owner,
        node.owner,
        node.len(),
        node.modified_at.format("%b %e %H:%M"),
        name
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
    failure(format!("{command}: {path}: {error}\n"))
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
