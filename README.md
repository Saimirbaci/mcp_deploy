# MCP Deploy Server

A secure Model Context Protocol (MCP) server and CLI tool written in Rust for executing commands on remote deployment servers via SSH.

## Features

- **Secure SSH Execution**: Uses local SSH keys without exposing them to AI agents.
- **IP Whitelisting**: Strictly enforces execution only on allowed IP addresses.
- **Dual Mode**: Works as both a standard CLI tool and an MCP server for AI integration.
- **Discovery**: Exposes a tool for agents to list available servers.
- **Hot-Reloading**: Automatically detects and applies changes to the configuration file without restarting the server.
- **Tamper-Evident Audit Log**: Appends every tool call to an append-only, hash-chained log for security reviews and incident response.

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
   - **Security**: Commands are screened before execution. Reads of `.env` files,
     SSH/private keys (`id_rsa`, `*.pem`, `~/.ssh/...`), and credential stores
     (`~/.aws/credentials`, `~/.git-credentials`, `/etc/shadow`, etc.) are
     blocked, as are environment-dumping commands (`env`, `printenv`). Servers
     may additionally define an `allowed_command_prefixes` allowlist (see below).
3. **`read_remote_file`**: Reads a file from the remote server using SFTP.
   - **Arguments**: `target` (string), `path` (string)
4. **`write_remote_file`**: Writes/Overwrites a file on the remote server using SFTP.
   - **Arguments**: `target` (string), `path` (string), `content` (string), `confirm_token` (string, optional)
   - **Dry-run preview**: Called without `confirm_token`, it performs no write and
     instead returns a unified diff of what would change plus a `confirm_token`.
     Call it again with the same `target`/`path`/`content` and that token to apply
     the change. This prevents silently clobbering an existing file.
5. **`list_local_secret_names`**: Lists the names (labels) of secrets stored in your local Mac vault.
   - **Note**: Claude never sees the values, only the labels.
6. **`deploy_secret_to_server`**: Injects a secret from your local vault into a remote `.env` file.
   - **Arguments**: `target`, `remote_env_path`, `env_key`, `local_secret_name`, `confirm_token` (optional)
   - **Dry-run preview**: Like `write_remote_file`, the first call (without
     `confirm_token`) returns a diff showing whether the key is added or updated
     — the secret value is always **redacted** — plus a `confirm_token` that must
     be passed back to apply the change.
7. **`list_allowed_services`**: Returns the allow-listed HTTP services (name and
   `base_url`) that can be driven via `call_service_api`. The secret name and
   value are **never** returned.
8. **`call_service_api`**: Performs an authenticated HTTP request against an
   allow-listed service (see the `services` config block below).
   - **Arguments**: `service` (string), `method` (`GET`/`POST`/`PUT`/`PATCH`/`DELETE`),
     `path` (string), `query` (object, optional), `body` (object or string, optional)
   - **Blind credential model**: The agent only names the service. The MCP server
     looks up the configured secret in the local vault and injects it into the
     request per the service's `auth` scheme (`bearer`, `header`, or `query`). The
     secret value is **never** returned to the agent nor written to logs (it is
     redacted out of the response body before it is returned).
   - **Errors**: A non-2xx response still returns the response body (with
     `isError` set) so the agent can debug. A request to a service that is not in
     the `services` allow-list is refused with a clear error (boundary-control
     parity with SSH).

### HTTP Services (`call_service_api`)
In addition to SSH targets, the config may define an optional `services` map of
allow-listed HTTP APIs. Each service references a credential **by name** only —
the value lives in the local vault and is injected server-side:

```json
"services": {
  "cloudflare": {
    "base_url": "https://api.cloudflare.com/client/v4",
    "auth": "bearer",
    "secret_name": "CloudflareToken"
  },
  "resend": {
    "base_url": "https://api.resend.com",
    "auth": { "header": { "name": "Authorization" } },
    "secret_name": "ResendKey"
  }
}
```

- `auth` accepts `"bearer"` (sends `Authorization: Bearer <secret>`),
  `{ "header": { "name": "X-Api-Key" } }` (sends the secret as a named header),
  or `{ "query": { "name": "api_key" } }` (sends the secret as a query param).
- `secret_name` names a secret stored in the local vault (add it with
  `printf '<token>' | mcp_deploy secret add CloudflareToken`). Only the name
  appears in config; the value is never exposed to the agent.
- An optional `extra` object adds static (non-secret) headers to every request.
- The `services` block is optional and additive — existing `servers`-only
  configs continue to load unchanged.

### The Secret Vault (Encrypted at Rest in the macOS Keychain)
Secrets are stored in the **macOS Keychain**, so they are encrypted at rest and
access is gated by the operating system — values are never written to disk as
plaintext.

Manage the vault with the `secret` subcommand. Values are read from **stdin**,
never passed as arguments, so they don't leak into shell history or the process
table:

```bash
# Add or update a secret (the value is read from stdin)
printf 'sk_live_...' | mcp_deploy secret add StripeProdKey

# List the names stored in the vault (values are never printed)
mcp_deploy secret list

# Remove a secret
mcp_deploy secret remove StripeProdKey
```

Use `--server <alias_or_ip>` to target a server-specific vault when a
`secrets_path` is configured for that server; otherwise the shared default vault
is used.

**Migration**: if a legacy plaintext `~/.remote_connections/mcp_secrets.json`
file exists, it is imported into the Keychain automatically on first access and
the plaintext file is renamed to `*.json.migrated` (delete it once verified).

### Blind Secret Injection (Ultra-Secure)
This lets you manage production secrets without Claude ever seeing them:
1. Add your secret to the vault: `printf 'sk_live_...' | mcp_deploy secret add StripeProdKey`.
2. Tell Claude: *"Deploy the 'StripeProdKey' to the beta server as 'STRIPE_SECRET'."*
3. The MCP server fetches the value locally from the Keychain and pushes it to the server over SSH.
4. **The secret never appears in the Claude chat history or logs.**

### Command Allowlist (Optional)
Each server entry may define `allowed_command_prefixes`, an array of permitted
command prefixes. When present and non-empty, `run_command` will only execute
commands that begin with one of these prefixes (fail-closed), in addition to the
global secret-exfiltration denylist. Omit the field (or leave it empty) to allow
any non-denylisted command.

```json
"allowed_command_prefixes": ["ls", "tail -n", "systemctl status", "uptime"]
```

- **Agent Isolation**: Agents only provide the IP and the command. They never see the SSH keys or the usernames.
- **Boundary Control**: If an IP is not in the configuration file, the tool will refuse to connect, preventing unauthorized lateral movement.
- **Logging**: All logs are directed to `stderr`, keeping the MCP communication channel (`stdout`) clean and secure.

## Tamper-Evident Audit Log

Independently of the `stderr` `tracing` stream, the MCP server appends a record
of **every** tool call to an append-only, hash-chained audit log. Each entry
captures who (the OS user running the server), what (the tool and a value-free
description of the action), when (timestamp), the target server, the **names**
of any secrets involved (**never** their values), and whether the call
succeeded.

Each entry stores the SHA-256 hash of the previous entry plus a hash over its
own fields, forming a chain. Editing, removing, or reordering any entry breaks
the chain and is detected on verification — the log is an artifact for security
reviews and incident response, not a secret store.

### Location
By default the log lives next to the config file (e.g.
`~/.remote_connections/audit.log`).

### Inspecting the log

```bash
# Verify the hash chain is intact (exits non-zero on tampering)
mcp_deploy audit verify

# Print a human-readable summary of recorded tool calls
mcp_deploy audit show

# Point at a specific log file
mcp_deploy audit verify --path /path/to/audit.log
```

## License
MIT
