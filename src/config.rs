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
