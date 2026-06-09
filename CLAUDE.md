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
- **Command allowlist** (optional): A server entry may set `allowed_command_prefixes` (array of strings). When present and non-empty, `run_command` only runs commands starting with one of those prefixes (fail-closed), on top of the always-on secret denylist

## Never Do

- **Never** pass raw SSH keys or credentials as command-line arguments
- **Never** execute on IPs not defined in the configuration whitelist
- **Never** disable the configuration validation
- **Never** modify the config file directly while the server is running for critical changes (use hot-reload for non-critical updates only)
- **Never** weaken or bypass `command_guard::validate_command` — every remote command (CLI and `run_command`) must pass the secret/credential denylist. Use the `deploy_secret` tools to manage secrets instead of reading them via shell commands.
- **Never** return remote data output to the agent without passing it through `scrubber::scrub_output` — every data-bearing tool (`run_command`, `read_remote_file`, `query_database`, `list_db_tables`, and the CLI) must scrub secrets out of its output so they never reach chat history or logs.
- **Never** enforce the read-only DB guard with substring or `starts_with` matching — it is trivially bypassed by leading comments, CTEs, or stacked statements (e.g. `SELECT 1;DROP TABLE t`). The guard must use `sql_guard::validate_readonly_query` (SQL parser) plus `PGOPTIONS='-c default_transaction_read_only=on'` (Postgres-level enforcement) so writes are rejected structurally and at the DB boundary.