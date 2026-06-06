# Rust Patterns

## Project Structure
```
src/
├── main.rs              # CLI entry point, argument parsing
├── mcp/                 # MCP server implementation
├── ssh/                 # SSH connection and command execution
├── config/              # Configuration loading and validation
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

## Remote Write Safety (Dry-Run / Confirm)
Destructive remote writes (`write_remote_file`, `deploy_secret_to_server`) are
two-phase: a preview call returns a unified diff plus a deterministic
`confirm_token`; the write only executes on a second call carrying that token.
- Derive the token from `(target, path, new_content)` via a stable hash
  (`diff::change_token`) so a confirm only matches the exact change previewed —
  if the remote file changed in between, the recomputed token won't match and a
  fresh preview is forced.
- Track previewed-but-unapplied tokens in an in-memory `Arc<Mutex<HashSet>>`;
  remove a token once its write succeeds.
- Compute new file content with pure, I/O-free helpers (`compute_env_update`)
  so the preview and the eventual write share identical logic and are unit
  testable without SSH.
- Use `read_remote_file_if_exists` (returns `Ok(None)` for a missing file) to
  distinguish "create new file" from "modify existing" in the preview, while
  genuine errors (permissions, connectivity) still surface.
- **Never reveal secret values in a diff.** Redact env values to `<redacted>`
  before rendering (`diff::redact_env_value`), and match env keys exactly (not
  by substring) so `MY_API_KEY` is never treated as `API_KEY`.