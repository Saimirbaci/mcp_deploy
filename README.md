# MCP Deploy Server

A secure Model Context Protocol (MCP) server and CLI tool written in Rust for executing commands on remote deployment servers via SSH.

## Features

- **Secure SSH Execution**: Uses local SSH keys without exposing them to AI agents.
- **IP Whitelisting**: Strictly enforces execution only on allowed IP addresses.
- **Dual Mode**: Works as both a standard CLI tool and an MCP server for AI integration.
- **Discovery**: Exposes a tool for agents to list available servers.
- **Automatic Configuration**: Defaults to using a configuration file in your home directory.

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
      "user": "deploy",
      "key_path": "/Users/yourname/.ssh/id_rsa"
    },
    "your-server-ip": {
      "user": "admin",
      "key_path": "/Users/yourname/.ssh/deploy_key"
    }
  }
}
```

## Usage

### CLI Mode
Run commands directly from your terminal:

```bash
# Using default config
./target/release/mcp_deploy cli --ip 192.168.1.100 -x "uptime"

# Using a custom config
./target/release/mcp_deploy --config ./my_config.json cli --ip 192.168.1.100 -x "ls -la /var/www"
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

1. **`list_allowed_servers`**: Returns the list of IP addresses the agent is allowed to connect to.
2. **`run_command`**: Executes a command on a remote server.
   - **Arguments**: `ip` (string), `command` (string)

## Security

- **Agent Isolation**: Agents only provide the IP and the command. They never see the SSH keys or the usernames.
- **Boundary Control**: If an IP is not in the configuration file, the tool will refuse to connect, preventing unauthorized lateral movement.
- **Logging**: All logs are directed to `stderr`, keeping the MCP communication channel (`stdout`) clean and secure.

## License
MIT
