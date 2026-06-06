use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbConfig {
    pub user: String,
    pub name: String,
    pub password: Option<String>,
    pub readonly: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerInfo {
    pub alias: String,
    pub user: String,
    pub key_path: String,
    pub db_config: Option<DbConfig>,
    pub default_env_path: Option<String>,
    pub secrets_path: Option<String>,
    /// Optional allowlist of permitted command prefixes for this server. When
    /// present and non-empty, `run_command` only executes commands that start
    /// with one of these prefixes (in addition to the global secret denylist).
    #[serde(default)]
    pub allowed_command_prefixes: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub servers: HashMap<String, ServerInfo>,
}

pub struct Secrets {
    pub data: HashMap<String, String>,
}

impl Secrets {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Secrets { data: HashMap::new() });
        }
        let content = fs::read_to_string(path)?;
        let data: HashMap<String, String> = serde_json::from_str(&content)
            .context("Failed to parse secrets JSON")?;
        Ok(Secrets { data })
    }

    pub fn list_names(&self) -> Vec<String> {
        self.data.keys().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<String> {
        self.data.get(name).cloned()
    }

    pub fn values(&self) -> Vec<String> {
        self.data.values().cloned().collect()
    }
}

/// Loads the literal vault secret values associated with a target server so they
/// can be scrubbed out of tool output. Failures (missing/unreadable vault) yield
/// an empty list — scrubbing then falls back to pattern matching only.
pub fn known_secret_values(config: &Config, target: &str) -> Vec<String> {
    let Some((_ip, info)) = config.get_server_by_target(target) else {
        return Vec::new();
    };
    let home = std::env::var("HOME").unwrap_or_default();
    let secrets_path = info
        .secrets_path
        .clone()
        .unwrap_or_else(|| format!("{}/.remote_connections/mcp_secrets.json", home));
    match Secrets::load(&secrets_path) {
        Ok(s) => s.values(),
        Err(_) => Vec::new(),
    }
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .context("Failed to read config file")?;
        let config: Config = serde_json::from_str(&content)
            .context("Failed to parse config JSON")?;
        Ok(config)
    }

    pub fn get_server_by_target(&self, target: &str) -> Option<(String, &ServerInfo)> {
        // First try to find by IP (the map key)
        if let Some(info) = self.servers.get(target) {
            return Some((target.to_string(), info));
        }
        
        // Then try to find by alias
        for (ip, info) in &self.servers {
            if info.alias == target {
                return Some((ip.clone(), info));
            }
        }
        
        None
    }

    pub fn allowed_servers(&self) -> Vec<(String, String)> {
        self.servers.iter()
            .map(|(ip, info)| (ip.clone(), info.alias.clone()))
            .collect()
    }
}
