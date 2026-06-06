# Rust Patterns

## Project Structure
```
src/
├── main.rs              # CLI entry point, argument parsing
├── mcp/                 # MCP server implementation
├── ssh/                 # SSH connection and command execution
├── config/              # Configuration loading and validation
├── command_guard.rs     # Validates remote commands (secret denylist + allowlist)
├── scrubber.rs          # Redacts secrets from tool output before returning to the agent
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

### Output Scrubber Pattern (`src/scrubber.rs`)
- Every tool that returns remote *data* must pass its output through
  `scrubber::scrub_output(text, known_secrets)` before it reaches the agent. This
  is the egress counterpart to `command_guard` (which guards ingress): commands are
  validated before they run, and their output is scrubbed before it is returned.
  Wired in at both entry points — the `Cli` arm in `main.rs` and the data-bearing
  tool arms in `mcp.rs` (`run_command`, `read_remote_file`, `query_database`,
  `list_db_tables`) via the `scrub_for_target` helper. Outputs that only echo
  caller-supplied or non-secret data (`list_allowed_servers`, write/deploy success
  messages, `list_local_secret_names`) are intentionally not scrubbed.
- Two layers, applied in order:
  1. **Known vault values:** literal secret values for the target server (loaded
     via `config::known_secret_values`) are replaced wherever they appear. Values
     shorter than `MIN_LITERAL_SECRET_LEN` are skipped to avoid over-redaction.
  2. **Pattern matches:** common secret formats (Stripe `sk_live_`, AWS `AKIA`,
     PEM blocks, JWTs, GitHub/Google/Slack tokens) compiled once into `PATTERNS`.
  Both replace with the `[REDACTED]` placeholder.
- When adding a new secret format, extend `PATTERNS`; add a `#[cfg(test)]` case for
  both a matching secret and a benign near-miss that must NOT be redacted.