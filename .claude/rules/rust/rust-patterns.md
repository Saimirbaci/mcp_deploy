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

## Tamper-Evident Audit Log (`src/audit.rs`)
Every `tools/call` handled by the MCP server is appended to an append-only,
SHA-256 hash-chained log that lives in a file separate from the stderr
`tracing` stream (default: `audit.log` alongside the config). It is a security
artifact, never a secret store.
- **Record names, never values.** Audit entries carry secret *names* and a
  value-free `action` description; secret values must never be passed to
  `AuditLog::record`. Build entry fields with `describe_tool_call` in `mcp.rs`,
  which knows each tool's value-free shape — extend it when adding a tool.
- **Audit every tool call, success or failure.** Record once at the single
  call site after the tool result is computed; derive success from
  `is_success` (no JSON-RPC error and no `isError` flag).
- **Auditing must never break the request.** A failed log append is logged via
  `error!` and swallowed — the tool result is still returned to the caller.
- **Hash chain = tamper evidence.** Each entry stores `prev_hash` plus a hash
  over its own fields; the first entry chains from `GENESIS_HASH`. Keep
  `compute_hash` pure and I/O-free so the writer and `verify_chain` share
  identical logic, and mix the `SEP` byte between fields so adjacent fields
  can't collide into the same digest input.
- **Continue the chain across restarts.** `AuditLog::open` reads existing
  entries and resumes from the last hash/seq; guard mutable chain state
  (`last_hash`, `next_seq`) behind a single `Mutex` so concurrent records stay
  ordered and correctly linked.
- **Fail loud on corruption.** `read_entries` treats a missing file as empty
  but a present-but-unparseable line as a hard error, so corruption surfaces
  instead of being silently skipped. `verify_chain` checks contiguous seq from
  0, `prev_hash` linkage, and recomputed hashes; expose it via
  `mcp_deploy audit verify` / `show`.

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
