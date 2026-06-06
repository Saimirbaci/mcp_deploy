mod config;
mod ssh;
mod mcp;
mod command_guard;

use clap::{Parser, Subcommand};
use crate::config::Config;
use anyhow::{Result, Context};
use tracing_subscriber;

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
            let allowed_prefixes = cfg
                .get_server_by_target(&ip)
                .and_then(|(_ip, info)| info.allowed_command_prefixes.clone());
            command_guard::validate_command(&command, allowed_prefixes.as_deref())?;
            let output = ssh::run_ssh_command(&ip, &command, &cfg)?;
            println!("{}", output);
        }
    }

    Ok(())
}
