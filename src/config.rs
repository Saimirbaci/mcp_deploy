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

/// How a service's credential is injected into outgoing HTTP requests.
///
/// Uses serde's default (externally tagged) representation so the unit variant
/// deserializes from a bare string (`"auth": "bearer"`) while the parameterized
/// variants deserialize from an object (`{"header": {"name": "X-Api-Key"}}` /
/// `{"query": {"name": "api_key"}}`).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    /// Send the secret as an `Authorization: Bearer <secret>` header.
    Bearer,
    /// Send the secret as the value of a named request header.
    Header { name: String },
    /// Send the secret as the value of a named query-string parameter.
    Query { name: String },
}

/// An allow-listed outbound HTTP API the agent can drive via `call_service_api`.
///
/// The agent only ever names the service; the credential lives in the local
/// vault under `secret_name` and is injected by the MCP server. The secret value
/// is never returned to the agent.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceInfo {
    /// Base URL the service's request paths are joined onto.
    pub base_url: String,
    /// How the credential is applied to each request.
    pub auth: AuthScheme,
    /// Name of the secret (in the local vault) holding the credential value.
    pub secret_name: String,
    /// Optional static headers applied to every request to this service.
    #[serde(default)]
    pub extra: Option<HashMap<String, String>>,
    /// Optional allowlist of permitted HTTP methods (case-insensitive). When
    /// present and non-empty, `call_service_api` only issues requests whose
    /// method is in this list (fail-closed); when absent/empty, any method in
    /// the global verb set (GET/POST/PUT/PATCH/DELETE) is permitted. Use it to
    /// pin a service to read-only access (`["GET"]`).
    #[serde(default)]
    pub allowed_methods: Option<Vec<String>>,
    /// Optional allowlist of permitted request path prefixes. When present and
    /// non-empty, the caller-supplied `path` must start with one of these
    /// prefixes (fail-closed); when absent/empty, any path under `base_url` is
    /// permitted. Confines the agent to a subset of the service's API surface.
    #[serde(default)]
    pub allowed_path_prefixes: Option<Vec<String>>,
}

/// Which persistence backend the secret vault uses.
///
/// Selected by the top-level `secret_backend` config field. Defaults to
/// `Keychain` (encrypted at rest) so that the secure-by-default posture of the
/// keychain-only baseline is preserved: configs that omit the field — including
/// those of users who already migrated their vault into the OS keychain — keep
/// reading the encrypted vault, and a legacy plaintext file is auto-migrated on
/// first load. `JsonFile` is an explicit opt-out (`"secret_backend": "json"`)
/// that stores the vault as a plaintext JSON map, protected only by `0600` file
/// permissions.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackend {
    /// OS keychain entry, encrypted at rest (default). Account derived from
    /// `secrets_path`; auto-migrates a legacy plaintext file on first load.
    #[default]
    Keychain,
    /// Plaintext JSON map at `secrets_path` (explicit opt-out; 0600 file perms).
    #[serde(rename = "json")]
    JsonFile,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub servers: HashMap<String, ServerInfo>,
    /// Optional map of allow-listed HTTP services. Absent in `servers`-only
    /// configs (back-compat), in which case it defaults to an empty map.
    #[serde(default)]
    pub services: HashMap<String, ServiceInfo>,
    /// Which backend the secret vault uses. Absent in older configs, in which
    /// case it defaults to `Keychain` so already-migrated vaults keep working
    /// and secrets stay encrypted at rest by default.
    #[serde(default)]
    pub secret_backend: SecretBackend,
}

/// Service name used to namespace this application's entries in the OS keychain.
const KEYCHAIN_SERVICE: &str = "mcp_deploy_vault";

/// Actionable suffix appended to keychain failures. The `Keychain` backend is
/// the default, but on non-macOS/headless/CI hosts the OS keyring (macOS
/// Keychain, Linux Secret Service / dbus, etc.) may be unavailable, in which
/// case keychain access fails hard. Rather than surface an opaque keyring error,
/// point the operator at the plaintext opt-out so a config that omitted
/// `secret_backend` and inherited the secure default can recover.
const KEYCHAIN_UNAVAILABLE_HINT: &str = "The OS keychain may be unavailable on \
    this host (e.g. non-macOS, headless, SSH, or CI). If so, set \
    \"secret_backend\": \"json\" in the config to use the plaintext vault \
    instead (0600 file permissions, not encrypted at rest).";

/// A secret vault with a selectable persistence backend.
///
/// The in-memory shape is identical regardless of backend: a `name -> value`
/// map. The configured [`SecretBackend`] decides where the map is persisted:
///
/// * [`SecretBackend::JsonFile`] reads/writes a plaintext JSON map at the
///   `secrets_path` (the original, back-compatible behavior). Writes are atomic
///   (temp file + rename) and the file is created `0600` so the plaintext is at
///   least protected by file permissions.
/// * [`SecretBackend::Keychain`] stores the vault as a single JSON blob under
///   one OS keychain entry whose account is derived from `secrets_path`, so
///   secrets are encrypted at rest. On first load, a legacy plaintext file at
///   that path is migrated into the keychain and then moved aside.
///
/// In both cases the agent-facing interface is unchanged: only secret *names*
/// are ever exposed; values are read internally for injection only.
pub struct SecretStore {
    pub data: HashMap<String, String>,
    /// The backend this vault persists to.
    backend: SecretBackend,
    /// Backend-specific locator: the JSON file path for `JsonFile`, or the
    /// keychain account (derived from the secrets path) for `Keychain`.
    locator: String,
}

impl SecretStore {
    /// Build the keychain entry for the vault identified by `account`.
    ///
    /// The account is kept out of any error message so that a configured
    /// secrets path is never leaked through error reporting.
    fn entry(account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| {
            anyhow::anyhow!(
                "Failed to open OS keychain entry for the secret vault: {}. {}",
                e,
                KEYCHAIN_UNAVAILABLE_HINT
            )
        })
    }

    /// Load the vault for the given secrets path using `backend`.
    pub fn load<P: AsRef<Path>>(backend: SecretBackend, path: P) -> Result<Self> {
        let locator = path.as_ref().to_string_lossy().into_owned();
        match backend {
            SecretBackend::JsonFile => {
                let data = Self::read_json_file(&locator)?;
                Ok(SecretStore {
                    data,
                    backend,
                    locator,
                })
            }
            SecretBackend::Keychain => Self::load_keychain(locator),
        }
    }

    /// Read the plaintext JSON map at `path`. A missing file is an empty vault;
    /// an empty file is also treated as empty. The path is not embedded in error
    /// messages.
    fn read_json_file(path: &str) -> Result<HashMap<String, String>> {
        match fs::read_to_string(path) {
            Ok(content) if content.trim().is_empty() => Ok(HashMap::new()),
            Ok(content) => {
                // The tool always writes 0600, but a file created manually,
                // restored from backup, or left as a `.json.migrated` artifact
                // could be group/world-readable. Warn rather than fail so a
                // legitimate-but-loose vault still loads, but the operator is
                // alerted that plaintext secrets are exposed.
                warn_if_world_readable(path);
                serde_json::from_str(&content)
                    .context("Failed to parse plaintext secrets JSON file")
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(e) => Err(anyhow::anyhow!("Failed to read secrets file: {}", e)),
        }
    }

    /// Load the vault from the OS keychain, migrating a legacy plaintext file
    /// the first time the keychain has no entry yet.
    fn load_keychain(account: String) -> Result<Self> {
        let entry = Self::entry(&account)?;
        match entry.get_password() {
            Ok(blob) => {
                let data: HashMap<String, String> = serde_json::from_str(&blob)
                    .context("Failed to parse secrets stored in the OS keychain")?;
                Ok(SecretStore {
                    data,
                    backend: SecretBackend::Keychain,
                    locator: account,
                })
            }
            Err(keyring::Error::NoEntry) => Self::migrate_or_empty(account),
            Err(e) => Err(anyhow::anyhow!(
                "Failed to read secrets from the OS keychain: {}. {}",
                e,
                KEYCHAIN_UNAVAILABLE_HINT
            )),
        }
    }

    /// Handle the case where the keychain has no entry: migrate a legacy
    /// plaintext file if present, otherwise return an empty vault.
    fn migrate_or_empty(account: String) -> Result<Self> {
        let path = std::path::PathBuf::from(&account);
        if !path.exists() {
            return Ok(SecretStore {
                data: HashMap::new(),
                backend: SecretBackend::Keychain,
                locator: account,
            });
        }

        // A legacy plaintext vault about to be migrated may have been created
        // manually or restored loosely-permissioned; alert the operator if its
        // secrets were exposed beyond the owner before we move it aside.
        warn_if_world_readable(&account);
        let content = fs::read_to_string(&path)?;
        let data: HashMap<String, String> = serde_json::from_str(&content)
            .context("Failed to parse legacy plaintext secrets JSON")?;
        let secrets = SecretStore {
            data,
            backend: SecretBackend::Keychain,
            locator: account,
        };
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

    /// Persist the current vault contents to the configured backend.
    pub fn save(&self) -> Result<()> {
        match self.backend {
            SecretBackend::JsonFile => self.save_json_file(),
            SecretBackend::Keychain => self.save_keychain(),
        }
    }

    /// Persist the vault to the OS keychain as a single encrypted JSON blob.
    fn save_keychain(&self) -> Result<()> {
        let blob = serde_json::to_string(&self.data)
            .context("Failed to serialize secrets for the OS keychain")?;
        let entry = Self::entry(&self.locator)?;
        entry.set_password(&blob).map_err(|e| {
            anyhow::anyhow!(
                "Failed to write secrets to the OS keychain: {}. {}",
                e,
                KEYCHAIN_UNAVAILABLE_HINT
            )
        })?;
        Ok(())
    }

    /// Persist the vault to a plaintext JSON file. The write is atomic (temp
    /// file + rename) and the file is restricted to owner-only permissions so
    /// the plaintext is never world-readable and there is no truncation window
    /// where a reader could observe a partially-written vault.
    fn save_json_file(&self) -> Result<()> {
        let blob = serde_json::to_string_pretty(&self.data)
            .context("Failed to serialize secrets to JSON")?;
        let path = Path::new(&self.locator);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            // Collect the missing ancestors BEFORE creating them so each level
            // create_dir_all materializes can be restricted to the owner — not
            // just the leaf. create_dir_all honors the umask (typically 0755),
            // which would leave intermediate levels world-traversable.
            #[cfg(unix)]
            let created: Vec<std::path::PathBuf> = {
                let mut missing = Vec::new();
                let mut cur = Some(parent);
                while let Some(dir) = cur {
                    if dir.as_os_str().is_empty() || dir.exists() {
                        break;
                    }
                    missing.push(dir.to_path_buf());
                    cur = dir.parent();
                }
                missing
            };

            fs::create_dir_all(parent).context("Failed to create secrets directory")?;

            // Restrict every directory we just created to the owner so its
            // existence and listing are not world-traversable. Only applied to
            // directories we created — we never forcibly re-chmod a pre-existing
            // directory, and a failure here must not block persisting the vault.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for dir in &created {
                    if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
                        tracing::warn!(
                            "Failed to restrict secrets directory permissions: {}",
                            e
                        );
                    }
                }
            }
        }

        let tmp = path.with_extension("json.tmp");
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(&tmp)
                .context("Failed to open temporary secrets file for writing")?;
            use std::io::Write;
            f.write_all(blob.as_bytes())
                .context("Failed to write secrets to temporary file")?;
            f.sync_all().context("Failed to flush secrets to disk")?;
        }

        // Enforce 0600 even when the temp file already existed (the create mode
        // only applies when the file is newly created).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
                .context("Failed to set secrets file permissions")?;
        }

        fs::rename(&tmp, path).context("Failed to persist secrets file")?;
        Ok(())
    }

    /// Insert or update a secret and persist the change.
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

/// Warn (without failing) when a plaintext secrets file is readable by group or
/// others. No-op on non-unix platforms where these mode bits don't apply. The
/// path is not embedded in the message so a configured secrets path is not
/// leaked into logs.
#[cfg(unix)]
fn warn_if_world_readable(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o077;
        if mode != 0 {
            tracing::warn!(
                "Plaintext secrets file is accessible beyond its owner \
                 (mode {:o}); tighten it to 0600 to avoid exposing secrets.",
                meta.permissions().mode() & 0o777
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_path: &str) {}

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
    match SecretStore::load(config.secret_backend(), &secrets_path) {
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

    /// The resolved secret-vault backend (defaults to `Keychain`; plaintext
    /// `JsonFile` is an explicit `"secret_backend": "json"` opt-out).
    pub fn secret_backend(&self) -> SecretBackend {
        self.secret_backend
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

    /// Look up an allow-listed service by name.
    pub fn get_service(&self, name: &str) -> Option<&ServiceInfo> {
        self.services.get(name)
    }

    /// List the allow-listed services as `(name, base_url)` pairs. The secret
    /// name and value are intentionally never exposed here.
    pub fn allowed_services(&self) -> Vec<(String, String)> {
        self.services
            .iter()
            .map(|(name, info)| (name.clone(), info.base_url.clone()))
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
    fn test_servers_only_config_loads_without_services() {
        // Back-compat: a config with no `services` block must still load, with
        // `services` defaulting to an empty map.
        let json = r#"{
            "servers": {
                "10.0.0.1": {
                    "alias": "web",
                    "user": "deploy",
                    "key_path": "/home/deploy/.ssh/id_rsa",
                    "db_config": null,
                    "default_env_path": null,
                    "secrets_path": null
                }
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert!(config.services.is_empty());
        assert!(config.allowed_services().is_empty());
    }

    #[test]
    fn test_secret_backend_defaults_to_keychain_when_absent() {
        // Secure default: a config without `secret_backend` must resolve to the
        // Keychain backend so already-migrated vaults keep working and secrets
        // stay encrypted at rest. Plaintext JSON is an explicit opt-out.
        let json = r#"{ "servers": {} }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.secret_backend(), SecretBackend::Keychain);
    }

    #[test]
    fn test_secret_backend_parses_explicit_values() {
        let keychain: Config =
            serde_json::from_str(r#"{ "servers": {}, "secret_backend": "keychain" }"#).unwrap();
        assert_eq!(keychain.secret_backend(), SecretBackend::Keychain);

        let json: Config =
            serde_json::from_str(r#"{ "servers": {}, "secret_backend": "json" }"#).unwrap();
        assert_eq!(json.secret_backend(), SecretBackend::JsonFile);
    }

    #[test]
    fn test_services_block_parses_each_auth_scheme() {
        let json = r#"{
            "servers": {},
            "services": {
                "cloudflare": {
                    "base_url": "https://api.cloudflare.com/client/v4",
                    "auth": "bearer",
                    "secret_name": "CloudflareToken"
                },
                "resend": {
                    "base_url": "https://api.resend.com",
                    "auth": { "header": { "name": "X-Api-Key" } },
                    "secret_name": "ResendKey"
                },
                "legacy": {
                    "base_url": "https://api.legacy.test",
                    "auth": { "query": { "name": "api_key" } },
                    "secret_name": "LegacyKey"
                }
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();

        let cf = config.get_service("cloudflare").unwrap();
        assert!(matches!(cf.auth, AuthScheme::Bearer));
        assert_eq!(cf.secret_name, "CloudflareToken");

        let resend = config.get_service("resend").unwrap();
        match &resend.auth {
            AuthScheme::Header { name } => assert_eq!(name, "X-Api-Key"),
            other => panic!("expected Header scheme, got {:?}", other),
        }

        let legacy = config.get_service("legacy").unwrap();
        match &legacy.auth {
            AuthScheme::Query { name } => assert_eq!(name, "api_key"),
            other => panic!("expected Query scheme, got {:?}", other),
        }

        // allowed_services exposes name + base_url only, never the secret name.
        let mut allowed = config.allowed_services();
        allowed.sort();
        assert_eq!(allowed[0].0, "cloudflare");
        assert_eq!(allowed[0].1, "https://api.cloudflare.com/client/v4");
        assert!(!format!("{:?}", allowed).contains("CloudflareToken"));
    }

    #[test]
    fn test_get_and_list_names_operate_on_loaded_data() {
        let mut data = HashMap::new();
        data.insert("ApiKey".to_string(), "secret-value".to_string());
        let secrets = SecretStore {
            data,
            backend: SecretBackend::JsonFile,
            locator: "test-locator".to_string(),
        };

        assert_eq!(secrets.get("ApiKey"), Some("secret-value".to_string()));
        assert_eq!(secrets.get("Missing"), None);
        assert_eq!(secrets.list_names(), vec!["ApiKey".to_string()]);
        // list_names must never surface a value.
        assert!(!format!("{:?}", secrets.list_names()).contains("secret-value"));
    }

    /// A unique temp file path for a JsonFile-backend test. Uses the process id
    /// plus a caller-supplied tag to avoid collisions without needing a random
    /// source (which is unavailable in this environment).
    fn temp_secrets_path(tag: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "mcp_deploy_secrets_{}_{}.json",
            std::process::id(),
            tag
        ));
        dir
    }

    #[test]
    fn test_jsonfile_backend_round_trips_set_get_list_remove() {
        let path = temp_secrets_path("round_trip");
        let _ = fs::remove_file(&path);

        // Fresh load of a non-existent file is an empty vault.
        let mut store = SecretStore::load(SecretBackend::JsonFile, &path).unwrap();
        assert!(store.list_names().is_empty());

        store.set("ApiKey", "sk_live_abc123").unwrap();
        store.set("DbPassword", "p@ss w0rd").unwrap();

        // A fresh load from disk sees the persisted values.
        let reloaded = SecretStore::load(SecretBackend::JsonFile, &path).unwrap();
        assert_eq!(reloaded.get("ApiKey"), Some("sk_live_abc123".to_string()));
        let mut names = reloaded.list_names();
        names.sort();
        assert_eq!(names, vec!["ApiKey".to_string(), "DbPassword".to_string()]);

        // Remove persists and reports prior existence.
        let mut store = reloaded;
        assert!(store.remove("ApiKey").unwrap());
        assert!(!store.remove("ApiKey").unwrap());
        let after = SecretStore::load(SecretBackend::JsonFile, &path).unwrap();
        assert_eq!(after.get("ApiKey"), None);
        assert_eq!(after.get("DbPassword"), Some("p@ss w0rd".to_string()));

        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn test_jsonfile_backend_writes_0600_and_contains_value() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_secrets_path("perms");
        let _ = fs::remove_file(&path);

        let mut store = SecretStore::load(SecretBackend::JsonFile, &path).unwrap();
        store.set("Token", "plaintext-secret").unwrap();

        // The JsonFile backend is intentionally plaintext for back-compat, so
        // the value is present on disk — but the file must be owner-only.
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secrets file must be 0600, got {:o}", mode);
        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("plaintext-secret"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn test_jsonfile_backend_restricts_all_created_dir_levels_to_0700() {
        use std::os::unix::fs::PermissionsExt;

        // Build a vault path several missing levels deep so save() must create
        // more than one directory; every level it creates must be owner-only
        // (0700), not just the leaf.
        let mut base = std::env::temp_dir();
        base.push(format!("mcp_deploy_dirperms_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let nested = base.join("level1").join("level2");
        let path = nested.join("mcp_secrets.json");

        let mut store = SecretStore::load(SecretBackend::JsonFile, &path).unwrap();
        store.set("Token", "plaintext-secret").unwrap();

        for dir in [&base, &base.join("level1"), &nested] {
            let mode = fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o700,
                "created dir {:?} must be 0700, got {:o}",
                dir,
                mode
            );
        }

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_known_secret_values_uses_jsonfile_backend() {
        let path = temp_secrets_path("known_values");
        let _ = fs::remove_file(&path);
        let mut store = SecretStore::load(SecretBackend::JsonFile, &path).unwrap();
        store.set("Token", "sk_live_known_value").unwrap();

        let mut servers = HashMap::new();
        servers.insert(
            "10.0.0.5".to_string(),
            ServerInfo {
                alias: "web".to_string(),
                user: "deploy".to_string(),
                key_path: "/home/deploy/.ssh/id_rsa".to_string(),
                db_config: None,
                default_env_path: None,
                secrets_path: Some(path.to_string_lossy().into_owned()),
                allowed_command_prefixes: None,
            },
        );
        let config = Config {
            servers,
            services: HashMap::new(),
            secret_backend: SecretBackend::JsonFile,
        };

        let values = known_secret_values(&config, "web");
        assert_eq!(values, vec!["sk_live_known_value".to_string()]);

        let _ = fs::remove_file(&path);
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
        if let Ok(entry) = SecretStore::entry(account) {
            let _ = entry.delete_credential();
        }

        let mut secrets = SecretStore {
            data: HashMap::new(),
            backend: SecretBackend::Keychain,
            locator: account.to_string(),
        };
        secrets.set("TOKEN", "value-1").unwrap();

        let reloaded = SecretStore::load(SecretBackend::Keychain, account).unwrap();
        assert_eq!(reloaded.get("TOKEN"), Some("value-1".to_string()));

        let mut reloaded = reloaded;
        assert!(reloaded.remove("TOKEN").unwrap());
        let after = SecretStore::load(SecretBackend::Keychain, account).unwrap();
        assert_eq!(after.get("TOKEN"), None);

        // Clean up the keychain entry created by this test.
        if let Ok(entry) = SecretStore::entry(account) {
            let _ = entry.delete_credential();
        }
    }

    /// Keychain auto-migration of a legacy plaintext file. Ignored by default
    /// because it touches the real OS keychain. Run manually on macOS with:
    ///   cargo test keychain_migrates_legacy -- --ignored
    #[test]
    #[ignore]
    fn test_keychain_migrates_legacy_plaintext_file() {
        let path = temp_secrets_path("legacy_migrate");
        let account = path.to_string_lossy().into_owned();
        let _ = fs::remove_file(&path);
        let migrated_aside = path.with_extension("json.migrated");
        let _ = fs::remove_file(&migrated_aside);
        if let Ok(entry) = SecretStore::entry(&account) {
            let _ = entry.delete_credential();
        }

        // Seed a legacy plaintext vault on disk.
        let mut legacy = HashMap::new();
        legacy.insert("Legacy".to_string(), "legacy-value".to_string());
        fs::write(&path, serde_json::to_string(&legacy).unwrap()).unwrap();

        // First keychain load migrates the file into the keychain and moves it aside.
        let store = SecretStore::load(SecretBackend::Keychain, &path).unwrap();
        assert_eq!(store.get("Legacy"), Some("legacy-value".to_string()));
        assert!(!path.exists(), "plaintext file should be moved aside");
        assert!(
            migrated_aside.exists(),
            "a .json.migrated backup should exist"
        );

        // Clean up keychain entry and files.
        if let Ok(entry) = SecretStore::entry(&account) {
            let _ = entry.delete_credential();
        }
        let _ = fs::remove_file(&migrated_aside);
    }
}
