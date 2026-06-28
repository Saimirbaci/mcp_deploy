mod audit;
mod command_guard;
mod config;
mod diff;
mod http;
mod mcp;
mod scrubber;
mod sql_guard;
mod ssh;

use std::io::{IsTerminal, Read};

use crate::config::{Config, SecretStore};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mcp-deploy")]
#[command(about = "MCP server and CLI for secure deployment commands", long_about = None)]
struct Cli {
    /// Path to the JSON configuration file
    #[arg(short, long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP server
    Mcp {},
    /// Run a command on a remote server (CLI mode)
    Cli {
        /// IP address of the target server
        #[arg(short, long)]
        ip: String,
        /// Command to execute
        #[arg(short = 'x', long)]
        command: String,
    },
    /// Manage the local secret vault (JSON file or OS keychain, per config)
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Inspect the tamper-evident tool-call audit log
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Verify the integrity of the hash-chained audit log
    Verify {
        /// Path to the audit log (defaults to the standard location)
        #[arg(short, long)]
        path: Option<String>,
    },
    /// Print a human-readable summary of recorded tool calls
    Show {
        /// Path to the audit log (defaults to the standard location)
        #[arg(short, long)]
        path: Option<String>,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Add or update a secret. The value is never taken from an argument (so it
    /// cannot leak into shell history or the process table): when run in an
    /// interactive terminal it is read with a no-echo prompt; when stdin is
    /// piped, it is read from stdin so scripting still works.
    #[command(alias = "set")]
    Add {
        /// The name (label) of the secret in the vault
        name: String,
        /// Server alias or IP whose vault to use (defaults to the shared vault)
        #[arg(short, long)]
        server: Option<String>,
    },
    /// List the names of secrets stored in the vault (values are never shown)
    List {
        /// Server alias or IP whose vault to use (defaults to the shared vault)
        #[arg(short, long)]
        server: Option<String>,
    },
    /// Remove a secret from the vault
    #[command(alias = "rm")]
    Remove {
        /// The name (label) of the secret to remove
        name: String,
        /// Server alias or IP whose vault to use (defaults to the shared vault)
        #[arg(short, long)]
        server: Option<String>,
    },
}

/// Resolve the secrets vault path for an optional server target, falling back
/// to the shared default vault location.
fn resolve_secrets_path(config: &Config, server: &Option<String>) -> Result<String> {
    let home = std::env::var("HOME").context("Could not find HOME environment variable")?;
    let default_path = format!("{}/.remote_connections/mcp_secrets.json", home);

    match server {
        Some(target) => match config.get_server_by_target(target) {
            Some((_ip, info)) => Ok(info.secrets_path.clone().unwrap_or(default_path)),
            None => anyhow::bail!("Target '{}' not found in configuration", target),
        },
        None => Ok(default_path),
    }
}

fn run_secret_action(config_path: &str, action: SecretAction) -> Result<()> {
    let config =
        Config::load(config_path).context(format!("Failed to load config from {}", config_path))?;

    match action {
        SecretAction::Add { name, server } => {
            let path = resolve_secrets_path(&config, &server)?;
            // Read the secret value without ever taking it from argv (which would
            // leak into shell history and the process table). In an interactive
            // terminal, use a no-echo prompt so the typed value is not shown;
            // otherwise read piped stdin so scripted usage keeps working.
            let value = if std::io::stdin().is_terminal() {
                rpassword::prompt_password(format!("Value for secret '{}': ", name))
                    .context("Failed to read secret value")?
            } else {
                let mut buf = String::new();
                std::io::stdin()
                    .read_to_string(&mut buf)
                    .context("Failed to read secret value from stdin")?;
                buf
            };
            let value = value.trim_end_matches(['\n', '\r']);
            if value.is_empty() {
                anyhow::bail!("No secret value provided");
            }

            let mut secrets = SecretStore::load(config.secret_backend(), &path)?;
            secrets.set(&name, value)?;
            // Print only the name — never the value.
            println!("Stored secret '{}' in the vault.", name);
        }
        SecretAction::List { server } => {
            let path = resolve_secrets_path(&config, &server)?;
            let secrets = SecretStore::load(config.secret_backend(), &path)?;
            let mut names = secrets.list_names();
            names.sort();
            if names.is_empty() {
                println!("No secrets stored in the vault.");
            } else {
                println!("Secrets in the vault:");
                for name in names {
                    println!("  {}", name);
                }
            }
        }
        SecretAction::Remove { name, server } => {
            let path = resolve_secrets_path(&config, &server)?;
            let mut secrets = SecretStore::load(config.secret_backend(), &path)?;
            if secrets.remove(&name)? {
                println!("Removed secret '{}' from the vault.", name);
            } else {
                println!("Secret '{}' was not found in the vault.", name);
            }
        }
    }

    Ok(())
}

/// Resolve the audit log path. By default it lives alongside the config file
/// (so per-host setups keep their audit trail next to their config); falls back
/// to the standard `~/.remote_connections/` location.
fn resolve_audit_path(config_path: &str) -> Result<String> {
    if let Some(dir) = std::path::Path::new(config_path).parent()
        && !dir.as_os_str().is_empty()
    {
        return Ok(dir.join("audit.log").to_string_lossy().into_owned());
    }
    let home = std::env::var("HOME").context("Could not find HOME environment variable")?;
    Ok(format!("{}/.remote_connections/audit.log", home))
}

fn run_audit_action(config_path: &str, action: AuditAction) -> Result<()> {
    match action {
        AuditAction::Verify { path } => {
            let log_path = match path {
                Some(p) => p,
                None => resolve_audit_path(config_path)?,
            };
            let entries = audit::read_entries(&log_path)
                .context(format!("Failed to read audit log from {}", log_path))?;
            match audit::verify_chain(&entries) {
                Ok(n) => {
                    println!(
                        "Audit log OK: {} entries, hash chain intact ({}).",
                        n, log_path
                    );
                }
                Err(reason) => {
                    anyhow::bail!("Audit log INTEGRITY FAILURE: {} ({})", reason, log_path);
                }
            }
        }
        AuditAction::Show { path } => {
            let log_path = match path {
                Some(p) => p,
                None => resolve_audit_path(config_path)?,
            };
            let entries = audit::read_entries(&log_path)
                .context(format!("Failed to read audit log from {}", log_path))?;
            if entries.is_empty() {
                println!("No audit entries recorded in {}.", log_path);
            } else {
                for e in &entries {
                    let secrets = if e.secret_names.is_empty() {
                        String::new()
                    } else {
                        format!(" secrets={:?}", e.secret_names)
                    };
                    println!(
                        "#{:<4} {:<7} {:<14} actor={} target={} {}{}",
                        e.seq, e.outcome, e.tool, e.actor, e.target, e.action, secrets
                    );
                }
            }
        }
    }
    Ok(())
}

fn get_config_path(path: Option<String>) -> Result<String> {
    if let Some(p) = path {
        return Ok(p);
    }

    let home = std::env::var("HOME").context("Could not find HOME environment variable")?;
    let default_path = format!("{}/.remote_connections/mcp_config.json", home);
    Ok(default_path)
}

fn main() -> Result<()> {
    // Initialize tracing to stderr
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let config_path = get_config_path(cli.config)?;

    match cli.command {
        Commands::Mcp {} => {
            let cfg = Config::load(&config_path)
                .context(format!("Failed to load config from {}", config_path))?;
            let audit_path = resolve_audit_path(&config_path)?;
            mcp::run_server(cfg, config_path, audit_path)?;
        }
        Commands::Cli { ip, command } => {
            let cfg = Config::load(&config_path)
                .context(format!("Failed to load config from {}", config_path))?;
            let allowed_prefixes = cfg
                .get_server_by_target(&ip)
                .and_then(|(_ip, info)| info.allowed_command_prefixes.clone());
            command_guard::validate_command(&command, allowed_prefixes.as_deref())?;
            let output = ssh::run_ssh_command(&ip, &command, &cfg)?;
            let known_secrets = config::known_secret_values(&cfg, &ip);
            println!("{}", scrubber::scrub_output(&output, &known_secrets));
        }
        Commands::Secret { action } => {
            run_secret_action(&config_path, action)?;
        }
        Commands::Audit { action } => {
            run_audit_action(&config_path, action)?;
        }
    }

    Ok(())
}
