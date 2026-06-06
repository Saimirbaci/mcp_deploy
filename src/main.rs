mod config;
mod ssh;
mod mcp;
mod diff;

use std::io::Read;

use clap::{Parser, Subcommand};
use crate::config::{Config, Secrets};
use anyhow::{Result, Context};

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
    /// Manage the local secret vault (backed by the OS keychain)
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Add or update a secret. The value is read from stdin, never from an
    /// argument, so it does not leak into shell history or the process table.
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
    let config = Config::load(config_path)
        .context(format!("Failed to load config from {}", config_path))?;

    match action {
        SecretAction::Add { name, server } => {
            let path = resolve_secrets_path(&config, &server)?;
            // Read the secret value from stdin to keep it out of argv and shell history.
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .context("Failed to read secret value from stdin")?;
            let value = value.trim_end_matches(['\n', '\r']);
            if value.is_empty() {
                anyhow::bail!("No secret value provided on stdin");
            }

            let mut secrets = Secrets::load(&path)?;
            secrets.set(&name, value)?;
            println!("Stored secret '{}' in the OS keychain.", name);
        }
        SecretAction::List { server } => {
            let path = resolve_secrets_path(&config, &server)?;
            let secrets = Secrets::load(&path)?;
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
            let mut secrets = Secrets::load(&path)?;
            if secrets.remove(&name)? {
                println!("Removed secret '{}' from the OS keychain.", name);
            } else {
                println!("Secret '{}' was not found in the vault.", name);
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
            let cfg = Config::load(&config_path).context(format!("Failed to load config from {}", config_path))?;
            mcp::run_server(cfg, config_path)?;
        }
        Commands::Cli { ip, command } => {
            let cfg = Config::load(&config_path).context(format!("Failed to load config from {}", config_path))?;
            let output = ssh::run_ssh_command(&ip, &command, &cfg)?;
            println!("{}", output);
        }
        Commands::Secret { action } => {
            run_secret_action(&config_path, action)?;
        }
    }

    Ok(())
}
