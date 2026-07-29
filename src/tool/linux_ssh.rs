//! SSH client module for Linux IR remote execution.
//! Uses russh (pure Rust SSH implementation) for secure remote command execution.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Config, Handler};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::ChannelMsg;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// SSH authentication method
#[derive(Clone)]
pub enum SshAuth {
    /// Password authentication
    Password(String),
    /// Private key file (with optional passphrase)
    KeyFile {
        path: String,
        passphrase: Option<String>,
    },
}

/// SSH connection configuration
#[derive(Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    pub timeout_secs: u64,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            username: "root".to_string(),
            auth: SshAuth::Password(String::new()),
            timeout_secs: 30,
        }
    }
}

/// Result of a remote command execution
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// SSH client handler for russh
struct ClientHandler {
    /// Known hosts verification (simplified: accept all for now)
    accept_all: bool,
}

#[async_trait::async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // In production, verify against known_hosts
        // For IR scenarios, we often connect to unknown hosts
        Ok(self.accept_all)
    }
}

/// SSH session wrapper
pub struct SshClient {
    config: SshConfig,
    session: Option<client::Handle<ClientHandler>>,
}

impl SshClient {
    /// Create a new SSH client (not yet connected)
    pub fn new(config: SshConfig) -> Self {
        Self {
            config,
            session: None,
        }
    }

    /// Connect and authenticate to the remote host
    pub async fn connect(&mut self) -> Result<(), SshError> {
        let config = Config::default();

        let handler = ClientHandler { accept_all: true };

        // Connect TCP + SSH handshake
        let addr = (self.config.host.as_str(), self.config.port);
        let mut session = client::connect(Arc::new(config), addr, handler)
            .await
            .map_err(|e| SshError::Connection(format!("SSH connect failed: {}", e)))?;

        // Authenticate
        match &self.config.auth {
            SshAuth::Password(password) => {
                let auth_result = session
                    .authenticate_password(&self.config.username, password)
                    .await
                    .map_err(|e| SshError::Auth(format!("Password auth failed: {}", e)))?;
                if !auth_result {
                    return Err(SshError::Auth("Password authentication rejected".into()));
                }
            }
            SshAuth::KeyFile { path, passphrase } => {
                let key = russh_keys::load_secret_key(path, passphrase.as_deref())
                    .map_err(|e| SshError::Key(format!("Failed to load key {}: {}", path, e)))?;
                let key_with_hash = PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    None, // Use default hash algorithm
                ).map_err(|e| SshError::Key(format!("Failed to create key: {}", e)))?;
                let auth_result = session
                    .authenticate_publickey(&self.config.username, key_with_hash)
                    .await
                    .map_err(|e| SshError::Auth(format!("Key auth failed: {}", e)))?;
                if !auth_result {
                    return Err(SshError::Auth("Public key authentication rejected".into()));
                }
            }
        }

        self.session = Some(session);
        Ok(())
    }

    /// Execute a command on the remote host
    pub async fn exec(&mut self, command: &str) -> Result<CommandOutput, SshError> {
        let session = self
            .session
            .as_mut()
            .ok_or(SshError::NotConnected)?;

        // Open a new channel for this command
        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| SshError::Channel(format!("Failed to open channel: {}", e)))?;

        // Execute the command
        channel
            .exec(true, command)
            .await
            .map_err(|e| SshError::Exec(format!("Failed to exec '{}': {}", command, e)))?;

        // Collect output
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = -1;

        let read_timeout = Duration::from_secs(self.config.timeout_secs);

        loop {
            let msg = match timeout(read_timeout, channel.wait()).await {
                Ok(Some(msg)) => msg,
                Ok(None) => break, // Channel closed
                Err(_) => return Err(SshError::Timeout(command.to_string())),
            };

            match msg {
                ChannelMsg::Data { data } => {
                    stdout.extend_from_slice(&data);
                }
                ChannelMsg::ExtendedData { data, ext } => {
                    if ext == 1 {
                        stderr.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = exit_status as i32;
                }
                ChannelMsg::Eof => break,
                _ => {}
            }
        }

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&stdout).to_string(),
            stderr: String::from_utf8_lossy(&stderr).to_string(),
            exit_code,
        })
    }

    /// Execute multiple commands and return all outputs
    pub async fn exec_batch(
        &mut self,
        commands: &[&str],
    ) -> Result<Vec<CommandOutput>, SshError> {
        let mut results = Vec::with_capacity(commands.len());
        for cmd in commands {
            results.push(self.exec(cmd).await?);
        }
        Ok(results)
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }

    /// Disconnect
    pub async fn disconnect(&mut self) {
        if let Some(session) = self.session.take() {
            let _ = session.disconnect(russh::Disconnect::ByApplication, "", "English").await;
        }
    }
}

/// SSH connection pool for multiple targets
pub struct SshPool {
    connections: Mutex<HashMap<String, SshConfig>>,
}

impl SshPool {
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// Store config for a target
    pub async fn store_config(&self, config: SshConfig) {
        let key = format!("{}@{}:{}", config.username, config.host, config.port);
        let mut conns = self.connections.lock().await;
        conns.insert(key, config);
    }
}

impl Default for SshPool {
    fn default() -> Self {
        Self::new()
    }
}

/// SSH error types
#[derive(Debug)]
pub enum SshError {
    Connection(String),
    Auth(String),
    Key(String),
    Channel(String),
    Exec(String),
    Timeout(String),
    NotConnected,
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::Connection(msg) => write!(f, "SSH connection error: {}", msg),
            SshError::Auth(msg) => write!(f, "SSH authentication error: {}", msg),
            SshError::Key(msg) => write!(f, "SSH key error: {}", msg),
            SshError::Channel(msg) => write!(f, "SSH channel error: {}", msg),
            SshError::Exec(msg) => write!(f, "SSH execution error: {}", msg),
            SshError::Timeout(cmd) => write!(f, "SSH command timed out: {}", cmd),
            SshError::NotConnected => write!(f, "SSH not connected"),
        }
    }
}

impl std::error::Error for SshError {}

/// Parse SSH target string (user@host or user@host:port)
pub fn parse_target(target: &str) -> Result<(String, String, u16), SshError> {
    // Format: user@host or user@host:port
    let (user_host, port) = if let Some(idx) = target.rfind(':') {
        if let Ok(p) = target[idx + 1..].parse::<u16>() {
            (&target[..idx], p)
        } else {
            (target, 22)
        }
    } else {
        (target, 22)
    };

    let (username, host) = if let Some(idx) = user_host.find('@') {
        (&user_host[..idx], &user_host[idx + 1..])
    } else {
        ("root", user_host)
    };

    Ok((username.to_string(), host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target() {
        assert_eq!(
            parse_target("root@10.0.0.5").unwrap(),
            ("root".into(), "10.0.0.5".into(), 22)
        );
        assert_eq!(
            parse_target("admin@192.168.1.1:2222").unwrap(),
            ("admin".into(), "192.168.1.1".into(), 2222)
        );
        assert_eq!(
            parse_target("10.0.0.5").unwrap(),
            ("root".into(), "10.0.0.5".into(), 22)
        );
    }
}
