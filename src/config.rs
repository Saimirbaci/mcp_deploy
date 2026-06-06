use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

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

/// Service name used to namespace this application's entries in the OS keychain.
const KEYCHAIN_SERVICE: &str = "mcp_deploy_vault";

/// A secret vault backed by the OS keychain (macOS Keychain).
///
/// Secrets are encrypted at rest by the operating system and access is gated by
/// the OS. The vault for a given `secrets_path` is stored as a single JSON blob
/// under one keychain entry whose account is derived from that path, which keeps
/// per-server secret separation intact.
///
/// On first load, if no keychain entry exists yet but a legacy plaintext
/// `mcp_secrets.json` file is present, its contents are migrated into the
/// keychain automatically and the plaintext file is moved aside so that secrets
/// are no longer stored unencrypted on disk.
pub struct Secrets {
    pub data: HashMap<String, String>,
    /// Keychain account identifier (derived from the secrets path) used to
    /// persist this vault back to the OS keychain.
    account: String,
}

impl Secrets {
    /// Build the keychain entry for the vault identified by `account`.
    ///
    /// The account is kept out of any error message so that a configured
    /// secrets path is never leaked through error reporting.
    fn entry(account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .context("Failed to open OS keychain entry for the secret vault")
    }

    /// Load the vault for the given secrets path from the OS keychain.
    ///
    /// If the keychain has no entry yet but a legacy plaintext file exists at
    /// `path`, the file is migrated into the keychain and then moved aside.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let account = path.as_ref().to_string_lossy().into_owned();
        let entry = Self::entry(&account)?;

        match entry.get_password() {
            Ok(blob) => {
                let data: HashMap<String, String> = serde_json::from_str(&blob)
                    .context("Failed to parse secrets stored in the OS keychain")?;
                Ok(Secrets { data, account })
            }
            Err(keyring::Error::NoEntry) => Self::migrate_or_empty(path.as_ref(), account),
            Err(e) => Err(anyhow::anyhow!(
                "Failed to read secrets from the OS keychain: {}",
                e
            )),
        }
    }

    /// Handle the case where the keychain has no entry: migrate a legacy
    /// plaintext file if present, otherwise return an empty vault.
    fn migrate_or_empty(path: &Path, account: String) -> Result<Self> {
        if !path.exists() {
            return Ok(Secrets {
                data: HashMap::new(),
                account,
            });
        }

        let content = fs::read_to_string(path)?;
        let data: HashMap<String, String> = serde_json::from_str(&content)
            .context("Failed to parse legacy plaintext secrets JSON")?;
        let secrets = Secrets { data, account };
        secrets.save()?;

        // Move the plaintext file aside so secrets are no longer stored
        // unencrypted at rest. We rename rather than delete to avoid destroying
        // user data outright.
        let backup = path.with_extension("json.migrated");
        if let Err(e) = fs::rename(path, &backup) {
            tracing::warn!(
                "Migrated secrets into the OS keychain but failed to move the \
                 plaintext file aside: {}. Delete it manually to keep secrets \
                 encrypted at rest.",
                e
            );
        } else {
            tracing::warn!(
                "Migrated secrets into the OS keychain. The plaintext file was \
                 renamed to '{}'; delete it once you have verified the vault.",
                backup.display()
            );
        }

        Ok(secrets)
    }

    /// Persist the current vault contents to the OS keychain as a single
    /// encrypted JSON blob.
    pub fn save(&self) -> Result<()> {
        let blob = serde_json::to_string(&self.data)
            .context("Failed to serialize secrets for the OS keychain")?;
        let entry = Self::entry(&self.account)?;
        entry
            .set_password(&blob)
            .context("Failed to write secrets to the OS keychain")?;
        Ok(())
    }

    /// Insert or update a secret and persist the change to the keychain.
    pub fn set(&mut self, name: &str, value: &str) -> Result<()> {
        self.data.insert(name.to_string(), value.to_string());
        self.save()
    }

    /// Remove a secret and persist the change. Returns whether it existed.
    pub fn remove(&mut self, name: &str) -> Result<bool> {
        let existed = self.data.remove(name).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
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
        let content = fs::read_to_string(path).context("Failed to read config file")?;
        let config: Config =
            serde_json::from_str(&content).context("Failed to parse config JSON")?;
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
        self.servers
            .iter()
            .map(|(ip, info)| (ip.clone(), info.alias.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keychain_blob_round_trips_into_same_map() {
        // The vault is persisted to the keychain as a single JSON blob. Verify
        // that the on-keychain wire format round-trips into an identical map so
        // migrated and freshly-stored vaults stay compatible.
        let mut data = HashMap::new();
        data.insert("StripeProdKey".to_string(), "sk_live_abc123".to_string());
        data.insert("DbPassword".to_string(), "p@ss w0rd".to_string());

        let blob = serde_json::to_string(&data).unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(&blob).unwrap();

        assert_eq!(data, parsed);
    }

    #[test]
    fn test_get_and_list_names_operate_on_loaded_data() {
        let mut data = HashMap::new();
        data.insert("ApiKey".to_string(), "secret-value".to_string());
        let secrets = Secrets {
            data,
            account: "test-account".to_string(),
        };

        assert_eq!(secrets.get("ApiKey"), Some("secret-value".to_string()));
        assert_eq!(secrets.get("Missing"), None);
        assert_eq!(secrets.list_names(), vec!["ApiKey".to_string()]);
    }

    /// Full round-trip against the real OS keychain. Ignored by default because
    /// it requires keychain access (unavailable/headless in CI and may prompt
    /// on first access). Run manually on macOS with:
    ///   cargo test keychain_round_trip -- --ignored
    #[test]
    #[ignore]
    fn test_keychain_round_trip() {
        let account = "mcp_deploy_test_vault_round_trip";
        // Start clean in case a previous run left an entry behind.
        if let Ok(entry) = Secrets::entry(account) {
            let _ = entry.delete_credential();
        }

        let mut secrets = Secrets {
            data: HashMap::new(),
            account: account.to_string(),
        };
        secrets.set("TOKEN", "value-1").unwrap();

        let reloaded = Secrets::load(account).unwrap();
        assert_eq!(reloaded.get("TOKEN"), Some("value-1".to_string()));

        let mut reloaded = reloaded;
        assert!(reloaded.remove("TOKEN").unwrap());
        let after = Secrets::load(account).unwrap();
        assert_eq!(after.get("TOKEN"), None);

        // Clean up the keychain entry created by this test.
        if let Ok(entry) = Secrets::entry(account) {
            let _ = entry.delete_credential();
        }
    }
}
