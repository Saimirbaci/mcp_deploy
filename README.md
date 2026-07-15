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
     the `services` allow-list — or that violates a per-service method/path
     guardrail — is refused with a clear error (boundary-control parity with
     SSH). Error text is stripped of the request URL and the injected secret, so
     a credential can never leak through an error message or log line.
   - **No redirects**: The HTTP client does **not** follow redirects; a 3xx is
     returned to the agent as a normal status. This prevents an open redirect on
     an allow-listed host from forwarding the injected credential (header or
     query) to an attacker-controlled origin.

### HTTP Services (`call_service_api`)
In addition to SSH targets, the config may define an optional `services` map of
allow-listed HTTP APIs. Each service references a credential **by name** only —
the value lives in the local vault and is injected server-side:

```json
"services": {
  "cloudflare": {
    "base_url": "https://api.cloudflare.com/client/v4",
    "auth": "bearer",
    "secret_name": "CloudflareToken",
    "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
    "allowed_path_prefixes": ["/zones", "/user/tokens/verify"]
  },
  "resend": {
    "base_url": "https://api.resend.com",
    "auth": "bearer",
    "secret_name": "ResendSendKey",
    "allowed_methods": ["GET", "POST"],
    "allowed_path_prefixes": ["/emails"]
  }
}
```

- `auth` accepts `"bearer"` (sends `Authorization: Bearer <secret>`),
  `{ "header": { "name": "X-Api-Key" } }` (sends the secret as a named header),
  or `{ "query": { "name": "api_key" } }` (sends the secret as a query param).
  **Prefer header- or bearer-based schemes**: the `query` scheme puts the secret
  in the URL, which upstream servers, proxies, and load balancers commonly log —
  the local response/error output is redacted, but the credential is still
  exposed to the upstream's own logs.
- `secret_name` names a secret stored in the local vault (add it with
  `printf '<token>' | mcp_deploy secret add CloudflareToken`). Only the name
  appears in config; the value is never exposed to the agent.
- `allowed_methods` (optional) is a fail-closed allowlist of HTTP verbs for the
  service, the HTTP analogue of `allowed_command_prefixes`. Pin a service to
  read-only access with `["GET"]`. Omit it to permit any global verb.
- `allowed_path_prefixes` (optional) is a fail-closed allowlist confining the
  agent to a subset of the service's API surface; the request `path` must start
  with one of the prefixes. Regardless of this setting, paths containing `..`
  traversal segments are always rejected.
- An optional `extra` object adds static (non-secret) headers to every request.
- The `services` block is optional and additive — existing `servers`-only
  configs continue to load unchanged.

#### Cloudflare (DNS, zones, cache purge, WAF)

The shipped `cloudflare` service entry (see `sample_config.json`) lets the agent
manage Cloudflare through `call_service_api` without ever seeing the token:

```json
"cloudflare": {
  "base_url": "https://api.cloudflare.com/client/v4",
  "auth": "bearer",
  "secret_name": "CloudflareToken",
  "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
  "allowed_path_prefixes": ["/zones", "/user/tokens/verify"]
}
```

The `/zones` prefix covers the full surface this ticket targets — DNS records
(`/zones/{id}/dns_records`), cache purge (`/zones/{id}/purge_cache`), and
firewall/WAF rules (`/zones/{id}/rulesets`, `/zones/{id}/firewall/...`) — while
`/user/tokens/verify` permits the token sanity check. For **read-only** access,
narrow `allowed_methods` to `["GET"]`.

**Token (use a scoped API token, NOT the global API key).** Create a scoped
token at <https://dash.cloudflare.com/profile/api-tokens> with, for the relevant
zone(s):

- `Zone : DNS : Edit`
- `Zone : Cache Purge : Purge`
- `Zone : Read`
- *(optional, for WAF/firewall)* `Zone : Firewall Services : Edit`

Recommended hardening on the token itself: restrict it to specific zones, set an
**IP allowlist**, and give it a **TTL/expiry**. The global API key is
account-wide and must never be used here.

Store the token in the local vault under the name `CloudflareToken` (the value is
read via a no-echo prompt or piped from stdin — never passed as an argument):

```bash
# Interactive (no-echo prompt)
mcp_deploy secret add CloudflareToken

# Or piped for scripted use
printf '<scoped-cloudflare-token>' | mcp_deploy secret add CloudflareToken

# Confirm it is present by name only (the value is never printed)
mcp_deploy secret list
```

**Recipes** (the agent only ever names the service; the token is injected
server-side and redacted out of every response):

```jsonc
// 1. Verify the token is active
{ "service": "cloudflare", "method": "GET", "path": "/user/tokens/verify" }

// 2. Find your zone id (lists zones; filter by name with a query param)
{ "service": "cloudflare", "method": "GET", "path": "/zones",
  "query": { "name": "example.com" } }

// 3. List DNS records in a zone
{ "service": "cloudflare", "method": "GET",
  "path": "/zones/{zone_id}/dns_records" }

// 4. Add an A record
{ "service": "cloudflare", "method": "POST",
  "path": "/zones/{zone_id}/dns_records",
  "body": { "type": "A", "name": "test.example.com",
            "content": "203.0.113.10", "ttl": 120, "proxied": false } }

// 5. Update (PATCH) an existing record
{ "service": "cloudflare", "method": "PATCH",
  "path": "/zones/{zone_id}/dns_records/{record_id}",
  "body": { "content": "203.0.113.20", "ttl": 300 } }

// 6. Delete a record
{ "service": "cloudflare", "method": "DELETE",
  "path": "/zones/{zone_id}/dns_records/{record_id}" }

// 7. Purge the entire cache for a zone
{ "service": "cloudflare", "method": "POST",
  "path": "/zones/{zone_id}/purge_cache",
  "body": { "purge_everything": true } }

// 7b. Or purge only specific URLs
{ "service": "cloudflare", "method": "POST",
  "path": "/zones/{zone_id}/purge_cache",
  "body": { "files": ["https://example.com/style.css"] } }
```

Cloudflare returns `{"success": true, "result": ...}` on success and a non-2xx
status with an `errors` array on failure; on a non-2xx the body is still returned
to the agent (flagged `isError`) for debugging. Replace `{zone_id}` and
`{record_id}` with values discovered via recipes 2–3. See the
[Cloudflare API token permissions reference](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

#### Resend (email sending + domains/keys/audiences management)

Resend offers **two API-key scopes**, and this server ships a service alias for
each so the agent never holds a broader privilege than the task requires:

| Alias           | Secret name     | Key scope        | Use for                                   |
|-----------------|-----------------|------------------|-------------------------------------------|
| `resend`        | `ResendSendKey` | `sending_access` | Single/batch/scheduled email sends only.  |
| `resend_admin`  | `ResendAdminKey`| `full_access`    | Domains, API keys, audiences, broadcasts, webhooks (and sending). |

Both use `bearer` auth — the server injects `Authorization: Bearer <key>` from
the vault and redacts the value from every response. Define both in
`sample_config.json` (mirroring what ships in this repo):

```json
"services": {
  "resend": {
    "base_url": "https://api.resend.com",
    "auth": "bearer",
    "secret_name": "ResendSendKey",
    "allowed_methods": ["GET", "POST"],
    "allowed_path_prefixes": ["/emails"]
  },
  "resend_admin": {
    "base_url": "https://api.resend.com",
    "auth": "bearer",
    "secret_name": "ResendAdminKey",
    "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
    "allowed_path_prefixes": ["/emails", "/domains", "/api-keys", "/audiences", "/broadcasts", "/webhooks"]
  }
}
```

The allowlists are enforced **fail-closed**: a request to `POST /domains` via
the `resend` (sending-only) alias is refused before the key is ever loaded from
the vault, so a leak of `ResendSendKey` cannot mutate your account.

**Create the two keys** at <https://resend.com/api-keys> — one scoped to
`sending_access`, one to `full_access` — and store each under its name (value is
read via a no-echo prompt or piped; never as an argument):

```bash
mcp_deploy secret add ResendSendKey    # sending_access
mcp_deploy secret add ResendAdminKey   # full_access
mcp_deploy secret list                 # confirms names only; values never printed
```

**Send + domain-verify recipes** (the agent only ever names the service; the key
is injected server-side and redacted from responses):

```jsonc
// 1. Send a single email (uses the sending-only key)
{ "service": "resend", "method": "POST", "path": "/emails",
  "body": { "from": "you@yourdomain.com", "to": "user@example.com",
            "subject": "Hello", "text": "from Secure Deploy" },
  "headers": { "X-Idempotency-Key": "send-123" } }

// 2. Batch send (up to 100 messages per request)
{ "service": "resend", "method": "POST", "path": "/emails/batch",
  "body": [
    { "from": "you@yourdomain.com", "to": "a@example.com",
      "subject": "Batch 1", "text": "hi" },
    { "from": "you@yourdomain.com", "to": "b@example.com",
      "subject": "Batch 2", "html": "<p>hi</p>" }
  ] }

// 3. Scheduled send — Resend accepts a `scheduled_at` ISO-8601 field in the body.
//    Attachments are passed as an `attachments` array (base64 `content` + filename);
//    the body is passed through verbatim, so the agent controls the full JSON shape.
{ "service": "resend", "method": "POST", "path": "/emails",
  "body": {
    "from": "you@yourdomain.com", "to": "user@example.com",
    "subject": "Report", "html": "<b>See attached</b>",
    "scheduled_at": "2025-01-31T10:00:00Z",
    "attachments": [
      { "filename": "report.pdf", "content": "<base64-encoded-bytes>" }
    ]
  } }

// 4. List domains (admin key) — discover a domain id for verify/delete
{ "service": "resend_admin", "method": "GET", "path": "/domains" }

// 5. Create + verify a domain (admin key)
{ "service": "resend_admin", "method": "POST", "path": "/domains",
  "body": { "name": "yourdomain.com", "region": "us-east-1" } }

// 5b. Trigger verification once the DNS records Resend returns are in place
{ "service": "resend_admin", "method": "POST", "path": "/domains/{domain_id}/verify" }

// 6. Retrieve (GET) and remove (DELETE) a domain
{ "service": "resend_admin", "method": "GET",    "path": "/domains/{domain_id}" }
{ "service": "resend_admin", "method": "DELETE", "path": "/domains/{domain_id}" }

// 7. API keys (admin key) — list existing keys, then create a new scoped one
{ "service": "resend_admin", "method": "GET",  "path": "/api-keys" }
{ "service": "resend_admin", "method": "POST", "path": "/api-keys",
  "body": { "name": "ci-send-only", "permission": "sending_access",
            "domain_id": "{domain_id}" } }

// 8. Audiences + contacts (admin key)
{ "service": "resend_admin", "method": "GET",  "path": "/audiences" }
{ "service": "resend_admin", "method": "POST", "path": "/audiences/{audience_id}/contacts",
  "body": { "email": "subscriber@example.com", "first_name": "Jane",
            "unsubscribed": false } }
```

Notes:
- The `X-Idempotency-Key` header (recipe 1) is passed through to Resend so a
  retried send will not duplicate the email.
- Replace `{domain_id}` / `{audience_id}` with ids discovered via the list
  recipes above.
- On a non-2xx, the error body is still returned to the agent (flagged
  `isError`) for debugging. See the
  [Resend REST API reference](https://resend.rest/) and the
  [Create API key docs](https://resend.com/docs/api-reference/api-keys/create-api-key).

### The Secret Vault (Encrypted at Rest by Default, Selectable Backend)
The local secret vault holds the API keys and tokens that the MCP server injects
into SSH `.env` deploys and outbound `call_service_api` requests. The agent only
ever sees secret **names** — values are read internally for injection and never
returned to the chat or logs.

The storage backend is chosen by the top-level **`secret_backend`** config field:

| `secret_backend`      | Where secrets live | Encrypted at rest? |
|-----------------------|--------------------|--------------------|
| `keychain` (default)  | The **macOS Keychain** under the service namespace `mcp_deploy_vault`, namespaced per vault by `secrets_path` | Yes — gated and encrypted by the OS |
| `json`                | A plaintext JSON map at `secrets_path` (default `~/.remote_connections/mcp_secrets.json`), written atomically with `0600` permissions | No — protected only by file permissions |

```json
{
  "secret_backend": "keychain",
  "servers": { "...": { "...": "..." } }
}
```

`secret_backend` defaults to **`keychain`**, so secrets are encrypted at rest by
default and a config that omits the field keeps reading the encrypted vault — this
preserves the behavior of the keychain-only build for anyone who already migrated.
A legacy plaintext file is auto-migrated into the keychain on first load (see
below). Set `"secret_backend": "json"` to **explicitly opt out** into plaintext
JSON storage (back-compat / non-macOS); the MCP server logs a warning at startup
whenever the plaintext backend is active so the weaker at-rest posture is never
silent.

> ⚠️ **Upgrade / breaking-change note (default flipped to `keychain`).** Earlier
> builds that supported a plaintext JSON vault treated the **omitted** field as
> plaintext JSON; it now defaults to `keychain`. Two consequences for existing
> configs that omit `secret_backend`:
> - **First load auto-migrates** any existing plaintext `mcp_secrets.json` into
>   the OS keychain and renames the original to `*.json.migrated` (a full
>   plaintext copy left on disk — **delete it once verified**). To keep the old
>   behavior and skip migration entirely, set `"secret_backend": "json"`.
> - **On non-macOS / headless / SSH / CI hosts** the OS keyring may be
>   unavailable, in which case keychain load/save fails hard where the old
>   plaintext default would have succeeded. The error explicitly points you at
>   `"secret_backend": "json"`; set it to restore plaintext-vault behavior on
>   hosts without a usable keyring.

Manage the vault with the `secret` subcommand (`set`/`rm` are accepted as aliases
for `add`/`remove`). The value is **never** taken from a command-line argument:
in an interactive terminal it is read with a **no-echo prompt** (the typed value
is not shown), and when stdin is piped it is read from stdin so scripting still
works. The value is never echoed, printed, or logged:

```bash
# Add or update a secret — prompts without echoing when run interactively
mcp_deploy secret add StripeProdKey

# Or pipe the value in for scripted/CI use (no TTY → reads stdin)
printf 'sk_live_...' | mcp_deploy secret add StripeProdKey

# List the names stored in the vault (values are never printed)
mcp_deploy secret list

# Remove a secret
mcp_deploy secret remove StripeProdKey   # alias: secret rm
```

Use `--server <alias_or_ip>` to target a server-specific vault when a
`secrets_path` is configured for that server; otherwise the shared default vault
is used. The same `secrets_path` is honored by both backends (as the file path
for `json`, and as the keychain account namespace for `keychain`).

**Migration to the keychain**: with the default `keychain` backend, if no
keychain entry exists yet but a legacy plaintext file is present at the vault
path, its contents are imported into the Keychain automatically on first access
and the plaintext file is renamed to `*.json.migrated`. **Delete that backup once
verified** — it is a full plaintext copy of every secret and is left in place
only to avoid destroying data outright. Users who explicitly opt into the `json`
backend are never touched by this migration.

> The Foundation `call_service_api` tool reads its credentials through this same
> vault (by the service's configured `secret_name`), so switching `secret_backend`
> transparently changes where those credentials are stored too.

### Blind Secret Injection (Ultra-Secure)
This lets you manage production secrets without Claude ever seeing them:
1. Add your secret to the vault: `printf 'sk_live_...' | mcp_deploy secret add StripeProdKey`.
2. Tell Claude: *"Deploy the 'StripeProdKey' to the beta server as 'STRIPE_SECRET'."*
3. The MCP server fetches the value locally from the configured vault backend (JSON file or Keychain) and pushes it to the server over SSH.
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
