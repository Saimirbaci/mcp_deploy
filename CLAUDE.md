## What This Is

A secure Model Context Protocol (MCP) server and CLI tool written in Rust for executing commands on remote deployment servers via SSH. It provides a safe way for AI agents to run commands on authorized servers without exposing SSH credentials.

**Key capabilities:**
- Execute commands on remote servers via SSH using local keys
- IP/alias whitelisting via JSON config
- Works in CLI mode (`cli` subcommand) or MCP mode (`mcp` subcommand)
- Hot-reloads configuration automatically
- Server discovery tool exposed for AI agents

## Quick Start

```bash
# Build
cargo build --release

# CLI usage
./target/release/mcp_deploy cli --ip <alias_or_ip> -x "<command>"

# Run in dev mode
cargo run

# Run tests
cargo test

# Lint
cargo clippy
```

## Architecture

**Language**: Rust (single language)

**Structure**: Standard Rust binary crate
```
src/          # All source code
Cargo.toml    # Project manifest
```

The codebase likely follows typical Rust binary organization with command-line argument parsing, SSH execution logic, and MCP server handler implementation in `src/`.

## Key Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Rust dependencies and project metadata |
| `sample_config.json` | Example configuration file |
| `src/` | Source code (commands, handlers, config loading) |

**Configuration format** (`$HOME/.remote_connections/mcp_config.json`):
```json
{
  "servers": {
    "192.168.1.100": {
      "alias": "prod-web-01",
      "user": "deploy",
      "key_path": "/path/to/key"
    }
  }
}
```

## Conventions

- **MCP subcommand**: Start the MCP server for AI integration: `mcp_deploy mcp`
- **CLI subcommand**: Run direct commands: `mcp_deploy cli --ip <alias> -x "<command>"`
- **Config path**: Uses `$HOME/.remote_connections/mcp_config.json` by default; override with `--config`
- **SSH keys**: Must exist locally; private keys are never exposed to AI agents
- **Aliases**: Servers can be referenced by alias (from config) or IP address

## Never Do

- **Never** pass raw SSH keys or credentials as command-line arguments
- **Never** execute on IPs not defined in the configuration whitelist
- **Never** disable the configuration validation
- **Never** modify the config file directly while the server is running for critical changes (use hot-reload for non-critical updates only)