use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerInfo {
    pub user: String,
    pub key_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub servers: HashMap<String, ServerInfo>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .context("Failed to read config file")?;
        let config: Config = serde_json::from_str(&content)
            .context("Failed to parse config JSON")?;
        Ok(config)
    }

    pub fn get_server(&self, ip: &str) -> Option<&ServerInfo> {
        self.servers.get(ip)
    }

    pub fn allowed_ips(&self) -> Vec<String> {
        self.servers.keys().cloned().collect()
    }
}
