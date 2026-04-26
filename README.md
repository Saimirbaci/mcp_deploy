# MCP Deploy Server

A secure Model Context Protocol (MCP) server and CLI tool written in Rust for executing commands on remote deployment servers via SSH.

## Features

- **Secure SSH Execution**: Uses local SSH keys without exposing them to AI agents.
- **IP Whitelisting**: Strictly enforces execution only on allowed IP addresses.
- **Dual Mode**: Works as both a standard CLI tool and an MCP server for AI integration.
- **Discovery**: Exposes a tool for agents to list available servers.
- **Hot-Reloading**: Automatically detects and applies changes to the configuration file without restarting the server.

## Prerequisites

- **Rust**: [Install Rust](https://rustup.rs/)
- **SSH Keys**: Ensure you have SSH access to your target servers and the private keys are stored locally.

## Build

To build the project, run:

```bash
cargo build --release
```

The binary will be located at `target/release/mcp_deploy`.

## Configuration

The tool uses a JSON configuration file to map IPs to users and SSH keys.

### Default Path
By default, the tool looks for:
`$HOME/.remote_connections/mcp_config.json`

### JSON Format
```json
{
  "servers": {
    "192.168.1.100": {
      "alias": "prod-web-01",
      "user": "deploy",
      "key_path": "/Users/yourname/.ssh/id_rsa"
    },
    "10.0.0.5": {
      "alias": "staging-db",
      "user": "admin",
      "key_path": "/Users/yourname/.ssh/deploy_key"
    }
  }
}
```

## Usage

### CLI Mode
Run commands using either the IP or the Alias:

```bash
# Using Alias
./target/release/mcp_deploy cli --ip prod-web-01 -x "uptime"

# Using IP
./target/release/mcp_deploy cli --ip 192.168.1.100 -x "ls -la"
```

### MCP Mode
To use this with an MCP-compatible host (like Claude Desktop), add it to your configuration:

```json
{
  "mcpServers": {
    "deploy-server": {
      "command": "/path/to/mcp_deploy",
      "args": ["mcp"]
    }
  }
}
```

Or specify a custom config path:
```bash
/path/to/mcp_deploy --config /path/to/custom_config.json mcp
```

## Available Tools (MCP)

1. **`list_allowed_servers`**: Returns the list of IP addresses and Aliases the agent is allowed to connect to.
2. **`run_command`**: Executes a command on a remote server.
   - **Arguments**: `target` (string), `command` (string)
3. **`read_remote_file`**: Reads a file from the remote server using SFTP.
   - **Arguments**: `target` (string), `path` (string)
4. **`write_remote_file`**: Writes/Overwrites a file on the remote server using SFTP.
   - **Arguments**: `target` (string), `path` (string), `content` (string)
5. **`list_local_secret_names`**: Lists the names (labels) of secrets stored in your local Mac vault.
   - **Note**: Claude never sees the values, only the labels.
6. **`deploy_secret_to_server`**: Injects a secret from your local vault into a remote `.env` file.
   - **Arguments**: `target`, `remote_env_path`, `env_key`, `local_secret_name`

### Blind Secret Injection (Ultra-Secure)
This tool allows you to manage production secrets without Claude ever seeing them:
1. Create a file at `~/.remote_connections/mcp_secrets.json` on your Mac.
2. Store your secrets there: `{"StripeProdKey": "sk_live_..."}`.
3. Tell Claude: *"Deploy the 'StripeProdKey' to the beta server as 'STRIPE_SECRET'."*
4. The MCP server fetches the value locally and pushes it to the server over SSH.
5. **The secret never appears in the Claude chat history or logs.**

- **Agent Isolation**: Agents only provide the IP and the command. They never see the SSH keys or the usernames.
- **Boundary Control**: If an IP is not in the configuration file, the tool will refuse to connect, preventing unauthorized lateral movement.
- **Logging**: All logs are directed to `stderr`, keeping the MCP communication channel (`stdout`) clean and secure.

## License
MIT
