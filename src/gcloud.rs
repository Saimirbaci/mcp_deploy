//! Local `gcloud` CLI execution against a pre-authenticated service account.
//!
//! Mirrors `ssh.rs`'s resolve → authorize → execute shape, but the "remote" is
//! a local subprocess rather than an SSH session: the service-account key is
//! loaded from the vault, briefly materialized to a 0600 temp file to
//! activate an isolated `CLOUDSDK_CONFIG` directory, then deleted — after
//! that, `gcloud` calls run non-interactively against that isolated config
//! and never see the raw key again.

use crate::config::{Config, GcpConfig, SecretStore};
use anyhow::{Context, Result, anyhow};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// Non-streaming, bounded execution time budget for a single `gcloud` call,
/// mirroring `run_command`'s non-interactive/non-streaming constraint.
const GCLOUD_TIMEOUT: Duration = Duration::from_secs(60);

/// How often to poll a spawned gcloud process for completion.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Captured result of a `gcloud` invocation.
#[derive(Debug)]
pub struct GcloudOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Resolve the default (shared) secret-vault path. The GCP service-account
/// key is a single global secret, not tied to any particular `servers` entry,
/// so it is resolved the same way `call_service_api`'s credentials are.
fn default_secrets_path() -> Result<String> {
    let home = std::env::var("HOME").context("Could not find HOME environment variable")?;
    Ok(format!("{}/.remote_connections/mcp_secrets.json", home))
}

/// Materialize the service-account key JSON to a securely-created,
/// exclusively-opened temp file (0600 on unix by default). Using
/// `tempfile::NamedTempFile` rather than a PID-derived path opened with
/// `create(true)` closes a symlink-race window: a co-resident local user
/// could otherwise pre-create a symlink at a predictable
/// `temp_dir()/mcp_deploy_gcp_key_<pid>.json` path (the PID is not secret)
/// and have the service-account key written through it into an arbitrary
/// target file. `NamedTempFile` creates its (randomly-named) file with
/// `O_EXCL` semantics, which refuses to follow a pre-existing symlink.
/// Deleted automatically on drop, regardless of how the enclosing scope
/// exits, so the key JSON never lingers on disk beyond the activation call.
fn write_temp_key_file(key_json: &str) -> Result<NamedTempFile> {
    let mut file = tempfile::Builder::new()
        .prefix("mcp_deploy_gcp_key_")
        .suffix(".json")
        .tempfile()
        .context("Failed to create temporary service-account key file")?;
    file.write_all(key_json.as_bytes())
        .context("Failed to write service-account key to temp file")?;
    file.flush()
        .context("Failed to flush service-account key to temp file")?;
    Ok(file)
}

/// Pre-authenticate the pinned service account into an isolated
/// `CLOUDSDK_CONFIG` directory. The key is loaded from the local vault by
/// `gcp.key_secret_name`, materialized to a 0600 temp file only for the
/// duration of `gcloud auth activate-service-account`, then deleted —
/// credentials persist in gcloud's own store under `CLOUDSDK_CONFIG`, so the
/// raw JSON need not remain on disk afterward.
pub fn activate_service_account(gcp: &GcpConfig, config: &Config) -> Result<()> {
    let secrets_path = default_secrets_path()?;
    let secrets = SecretStore::load(config.secret_backend(), &secrets_path)
        .with_context(|| format!("Failed to load secret vault from {}", secrets_path))?;
    let key_json = secrets.get(&gcp.key_secret_name).ok_or_else(|| {
        anyhow!(
            "GCP service-account key secret '{}' was not found in the local vault",
            gcp.key_secret_name
        )
    })?;

    let temp_key = write_temp_key_file(&key_json)?;

    let cloudsdk_config_dir = gcp.resolved_cloudsdk_config_dir();
    std::fs::create_dir_all(&cloudsdk_config_dir)
        .context("Failed to create CLOUDSDK_CONFIG directory")?;

    let output = Command::new("gcloud")
        .arg("auth")
        .arg("activate-service-account")
        .arg(format!("--key-file={}", temp_key.path().display()))
        .arg(format!("--project={}", gcp.project_id))
        .env("CLOUDSDK_CONFIG", &cloudsdk_config_dir)
        .output()
        .context("Failed to spawn gcloud auth activate-service-account")?;

    // Delete the temp key file now, before returning, regardless of outcome.
    drop(temp_key);

    if !output.status.success() {
        return Err(anyhow!(
            "gcloud auth activate-service-account failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Returns whether `argv` already contains the given long flag, matching both
/// the `--flag value` and `--flag=value` forms.
fn has_flag(argv: &[String], flag: &str) -> bool {
    argv.iter()
        .any(|a| a == flag || a.starts_with(&format!("{}=", flag)))
}

/// Build the final argv for a `gcloud` invocation: injects `--project`, and
/// for zonal resource groups a `--zone`, when the caller didn't supply one.
/// Pure and I/O-free so it is unit-testable without invoking the real binary.
pub fn build_gcloud_argv(args: &[String], gcp: &GcpConfig) -> Vec<String> {
    let mut out = args.to_vec();

    if !has_flag(&out, "--project") {
        out.push(format!("--project={}", gcp.project_id));
    }

    // Only `compute instances` and `compute disks` are zonal among the
    // allow-listed resource groups; firewall-rules/snapshots/images/networks
    // are global and must not get a spurious --zone appended. Compared
    // lowercase to match `gcloud_guard::validate_gcloud_args`'s
    // case-insensitive comparison, so mixed-case argv is treated consistently
    // by both guards.
    let is_zonal = out.len() >= 2
        && out[0].eq_ignore_ascii_case("compute")
        && matches!(out[1].to_ascii_lowercase().as_str(), "instances" | "disks");
    if is_zonal
        && !has_flag(&out, "--zone")
        && !has_flag(&out, "--region")
        && let Some(zone) = &gcp.default_zone
    {
        out.push(format!("--zone={}", zone));
    }

    out
}

/// Execute an already-validated `gcloud` argv against the pre-authenticated
/// `CLOUDSDK_CONFIG`. Non-streaming and bounded: std::process has no built-in
/// timeout, so completion is polled with a deadline; a child that exceeds
/// `GCLOUD_TIMEOUT` is killed so a hang cannot block the MCP event loop
/// indefinitely. Stdout/stderr are drained on background threads while
/// polling so a chatty child cannot deadlock by filling an OS pipe buffer.
pub fn run_gcloud(args: &[String], gcp: &GcpConfig) -> Result<GcloudOutput> {
    let argv = build_gcloud_argv(args, gcp);
    let cloudsdk_config_dir = gcp.resolved_cloudsdk_config_dir();

    let mut child = Command::new("gcloud")
        .args(&argv)
        .env("CLOUDSDK_CONFIG", &cloudsdk_config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn gcloud")?;

    let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr was piped");

    let stdout_handle = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout_pipe.read_to_string(&mut buf);
        buf
    });
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });

    let deadline = Instant::now() + GCLOUD_TIMEOUT;
    let status = loop {
        match child.try_wait().context("Failed to poll gcloud process")? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                // Join the drain threads (they unblock once the killed
                // child's pipes close) for consistency with the success
                // path below, rather than leaving them to be dropped.
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(anyhow!(
                    "gcloud command timed out after {} seconds",
                    GCLOUD_TIMEOUT.as_secs()
                ));
            }
            None => std::thread::sleep(POLL_INTERVAL),
        }
    };

    let stdout = stdout_handle.join().unwrap_or_default();
    let stderr = stderr_handle.join().unwrap_or_default();

    Ok(GcloudOutput {
        stdout,
        stderr,
        exit_code: status.code().unwrap_or(-1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn gcp(default_zone: Option<&str>) -> GcpConfig {
        GcpConfig {
            project_id: "my-gcp-project".to_string(),
            default_zone: default_zone.map(String::from),
            default_region: None,
            key_secret_name: "GcpServiceAccountKey".to_string(),
            cloudsdk_config_dir: None,
        }
    }

    #[test]
    fn write_temp_key_file_writes_content_with_owner_only_permissions() {
        let file = write_temp_key_file(r#"{"type":"service_account"}"#).unwrap();
        let path = file.path().to_path_buf();
        assert!(path.exists());
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, r#"{"type":"service_account"}"#);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key temp file must be 0600, got {:o}", mode);
        }

        // Dropping the handle deletes the file (no lingering key material).
        drop(file);
        assert!(!path.exists());
    }

    #[test]
    fn write_temp_key_file_does_not_reuse_a_predictable_pid_derived_path() {
        // Regression test for the symlink-race fix: the old implementation
        // used a fully predictable `temp_dir()/mcp_deploy_gcp_key_<pid>.json`
        // path opened non-exclusively, which a co-resident local user could
        // pre-create as a symlink to redirect the key write. The securely
        // created temp file's name must not match that predictable pattern.
        let file = write_temp_key_file("test").unwrap();
        let predictable =
            std::env::temp_dir().join(format!("mcp_deploy_gcp_key_{}.json", std::process::id()));
        assert_ne!(file.path(), predictable);
    }

    #[test]
    fn build_gcloud_argv_injects_project() {
        let out = build_gcloud_argv(&args(&["compute", "instances", "list"]), &gcp(None));
        assert!(out.contains(&"--project=my-gcp-project".to_string()));
    }

    #[test]
    fn build_gcloud_argv_does_not_duplicate_an_existing_project_flag() {
        // gcloud_guard::validate_gcloud_args denies any caller-supplied
        // --project outright (it must stay pinned to the configured value),
        // so this only exercises build_gcloud_argv's own idempotency as a
        // pure helper: it must not append a second --project if one is
        // already present in argv.
        let out = build_gcloud_argv(
            &args(&["compute", "instances", "list", "--project=my-gcp-project"]),
            &gcp(None),
        );
        assert_eq!(out.iter().filter(|a| a.starts_with("--project")).count(), 1);
    }

    #[test]
    fn build_gcloud_argv_injects_default_zone_for_zonal_resources() {
        let out = build_gcloud_argv(
            &args(&["compute", "instances", "start", "my-vm"]),
            &gcp(Some("us-central1-a")),
        );
        assert!(out.contains(&"--zone=us-central1-a".to_string()));

        let out = build_gcloud_argv(
            &args(&["compute", "disks", "list"]),
            &gcp(Some("us-central1-a")),
        );
        assert!(out.contains(&"--zone=us-central1-a".to_string()));
    }

    #[test]
    fn build_gcloud_argv_does_not_inject_zone_for_global_resources() {
        let out = build_gcloud_argv(
            &args(&["compute", "firewall-rules", "list"]),
            &gcp(Some("us-central1-a")),
        );
        assert!(!out.iter().any(|a| a.starts_with("--zone")));

        let out = build_gcloud_argv(
            &args(&["compute", "networks", "list"]),
            &gcp(Some("us-central1-a")),
        );
        assert!(!out.iter().any(|a| a.starts_with("--zone")));
    }

    #[test]
    fn build_gcloud_argv_does_not_override_caller_supplied_zone_or_region() {
        let out = build_gcloud_argv(
            &args(&["compute", "instances", "list", "--zone=us-east1-b"]),
            &gcp(Some("us-central1-a")),
        );
        assert_eq!(out.iter().filter(|a| a.starts_with("--zone")).count(), 1);
        assert!(out.contains(&"--zone=us-east1-b".to_string()));

        let out = build_gcloud_argv(
            &args(&["compute", "instances", "list", "--region=us-east1"]),
            &gcp(Some("us-central1-a")),
        );
        assert!(!out.iter().any(|a| a.starts_with("--zone")));
    }

    #[test]
    fn build_gcloud_argv_omits_zone_when_no_default_configured() {
        let out = build_gcloud_argv(&args(&["compute", "instances", "list"]), &gcp(None));
        assert!(!out.iter().any(|a| a.starts_with("--zone")));
    }

    /// Full round-trip against the real `gcloud` binary and a real service
    /// account. Ignored by default since it needs live GCP credentials in the
    /// vault. Run manually with:
    ///   cargo test gcloud::tests::test_activate_and_list_instances -- --ignored
    #[test]
    #[ignore]
    fn test_activate_and_list_instances() {
        let gcp = GcpConfig {
            project_id: std::env::var("MCP_DEPLOY_TEST_GCP_PROJECT").unwrap(),
            default_zone: std::env::var("MCP_DEPLOY_TEST_GCP_ZONE").ok(),
            default_region: None,
            key_secret_name: "GcpServiceAccountKey".to_string(),
            cloudsdk_config_dir: None,
        };
        let config = Config {
            servers: std::collections::HashMap::new(),
            services: std::collections::HashMap::new(),
            secret_backend: crate::config::SecretBackend::default(),
            gcp: Some(gcp.clone()),
        };

        activate_service_account(&gcp, &config).unwrap();
        let out = run_gcloud(
            &[
                "compute".to_string(),
                "instances".to_string(),
                "list".to_string(),
            ],
            &gcp,
        )
        .unwrap();
        assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
    }
}
