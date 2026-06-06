# Rust Patterns

## Project Structure
```
src/
├── main.rs              # CLI entry point, argument parsing
├── mcp/                 # MCP server implementation
├── ssh/                 # SSH connection and command execution
├── config/              # Configuration loading and validation
├── command_guard.rs     # Validates remote commands (secret denylist + allowlist)
└── error.rs             # Central error type using anyhow
```

## Error Handling Pattern
```rust
// Use anyhow for error handling with context
use anyhow::{Context, Result};

// For public APIs, return Result<T, anyhow::Error>
// Add context at each layer: config_path, ip_address, user
```

## Configuration Pattern
```rust
// Use serde for JSON config deserialization
#[derive(Debug, Deserialize)]
struct ServerConfig { ... }

// Validate on load; fail fast with clear errors
impl ServerConfig {
    fn from_path(path: &Path) -> Result<Self> { ... }
}
```

## SSH Handling Pattern
- Use `rust-ssh` or appropriate SSH crate
- Never log or expose private key paths in errors
- Validate IP addresses against whitelist before connection
- Use local SSH agent or keys from configured paths only

## Async Considerations
- Use `tokio` for async runtime if MCP requires async
- Use blocking SSH calls wrapped in `tokio::task::spawn_blocking` if needed
- Handle timeouts for SSH connections

## CLI Pattern
- Use `clap` for argument parsing
- Separate CLI mode vs MCP mode clearly
- Provide `--config` flag for custom config path
- Validate IP/alias arguments before processing

## Security Patterns
- Never expose private keys or credentials in logs
- Validate all IPs against configured whitelist
- Fail closed: deny by default if whitelist check fails
- Sanitize command output before returning to caller

### Command Guard Pattern (`src/command_guard.rs`)
- Validate every remote command with `command_guard::validate_command(command, allowed_prefixes)`
  before it reaches the network. Call it in BOTH entry points: the `Cli` arm in
  `main.rs` and the `run_command` handler in `mcp.rs`. MCP errors are returned as an
  `isError` result, not by propagating `?`.
- Two enforcement layers, applied in order:
  1. **Global denylist (always on, cannot be overridden by allowlist):**
     - Sensitive substrings matched case-insensitively anywhere in the command
       (catches pipes/chains like `cat ~/.ssh/id_rsa | base64`): `.env`, `.ssh/`,
       `id_rsa`/`id_ed25519`, `*.pem`/`*.ppk`, `.aws/credentials`, `.git-credentials`,
       `.kube/config`, `/etc/shadow`, pasted `-----begin` PEM blocks, etc.
     - Environment-dumping programs (`env`, `printenv`) matched as whole tokens after
       normalizing shell separators (`| & ; \`( ) < >`) to whitespace, so `ls && env`
       and `$(printenv)` are caught while `environment.txt` is NOT falsely flagged.
  2. **Optional per-server allowlist:** `ServerInfo.allowed_command_prefixes`
     (`#[serde(default)]`, `Option<Vec<String>>`). When present and non-empty, the
     command must `starts_with` one of the prefixes (fail-closed); when absent/empty,
     only the denylist applies.
- When adding a new sensitive file/credential type, extend `DENY_SUBSTRINGS`; when
  adding an environment-dumping program, extend `DENY_COMMAND_WORDS`. Add a matching
  `#[cfg(test)]` case for both the blocked input and a benign near-miss.