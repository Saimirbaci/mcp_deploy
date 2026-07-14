use crate::audit::AuditLog;
use crate::config::{self, Config, SecretStore};
use crate::diff;
use crate::http;
use crate::scrubber;
use crate::ssh;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use tracing::error;

/// In-memory set of confirmation tokens for write operations that have been
/// previewed (dry-run) but not yet applied. A write is only carried out when a
/// caller supplies a token present in this set, which guarantees the change was
/// previewed before it touches a remote server.
type PendingStore = Arc<Mutex<HashSet<String>>>;

/// Build a successful text tool result.
fn text_result(text: String) -> (Option<Value>, Option<Value>) {
    (
        Some(json!({ "content": [{ "type": "text", "text": text }] })),
        None,
    )
}

/// Build a tool result flagged as an error (MCP `isError`).
fn error_result(text: String) -> (Option<Value>, Option<Value>) {
    (
        Some(json!({ "isError": true, "content": [{ "type": "text", "text": text }] })),
        None,
    )
}

/// Scrubs secret material out of a tool's textual output before it is returned
/// to the agent. Combines the target's known vault values with format-based
/// pattern matching (see [`crate::scrubber`]).
fn scrub_for_target(config: &Config, target: &str, output: &str) -> String {
    let known_secrets = config::known_secret_values(config, target);
    scrubber::scrub_output(output, &known_secrets)
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
    id: Value,
}

use notify::{EventKind, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

pub fn run_server(initial_config: Config, config_path: String, audit_path: String) -> Result<()> {
    // Surface a clear warning when the vault is configured for plaintext storage
    // so operators don't unknowingly run with secrets unencrypted at rest. The
    // secure default (Keychain) stays silent.
    if initial_config.secret_backend() == config::SecretBackend::JsonFile {
        error!(
            "Secret vault backend is 'json': secrets are stored UNENCRYPTED on \
             disk (0600 file permissions only). Set \"secret_backend\": \
             \"keychain\" in the config to encrypt them at rest."
        );
    }

    let config = Arc::new(RwLock::new(initial_config));
    let pending: PendingStore = Arc::new(Mutex::new(HashSet::new()));
    let audit = Arc::new(AuditLog::open(&audit_path)?);
    error!("Audit log active at {}", audit_path);

    let config_for_watcher = Arc::clone(&config);
    let path_for_watcher = PathBuf::from(&config_path);

    // Setup file watcher
    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(event) => {
                if let EventKind::Modify(_) = event.kind {
                    match Config::load(&path_for_watcher) {
                        Ok(new_config) => {
                            if let Ok(mut w) = config_for_watcher.write() {
                                *w = new_config;
                                error!(
                                    "Config reloaded successfully from {}",
                                    path_for_watcher.display()
                                );
                            }
                        }
                        Err(e) => error!("Failed to reload config: {}", e),
                    }
                }
            }
            Err(e) => error!("Watch error: {:?}", e),
        })?;

    let watch_path = PathBuf::from(&config_path);
    let watch_dir = watch_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    watcher.watch(watch_dir, RecursiveMode::NonRecursive)?;

    error!("MCP Server is ready and listening on stdin");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        error!("Received line: {}", line);

        match serde_json::from_str::<JsonRpcRequest>(&line) {
            Ok(req) => {
                // Notifications don't have an ID and don't expect a response
                if req.id.is_none() {
                    error!("Received notification: {}", req.method);
                    continue;
                }

                error!("Handling request: {} (id: {:?})", req.method, req.id);

                let current_config = config
                    .read()
                    .map_err(|e| anyhow::anyhow!("Lock error: {}", e))?
                    .clone();
                let response = handle_request(req, &current_config, &pending, &audit);
                let response_json = serde_json::to_string(&response)?;

                error!("Sending response for id {:?}", response.id);
                writeln!(stdout, "{}", response_json)?;
                stdout.flush()?;
            }
            Err(e) => {
                error!("Failed to parse JSON-RPC request: {}. Line: {}", e, line);
            }
        }
    }

    Ok(())
}

/// Extract value-free audit fields (target, action description, secret names)
/// for a tool call. Secret *names* may appear here; secret *values* must never
/// be included.
fn describe_tool_call(tool_name: &str, arguments: &Value) -> (String, String, Vec<String>) {
    let target = arguments["target"].as_str().unwrap_or("").to_string();
    let dry_run_phase = |args: &Value| {
        if args["confirm_token"].as_str().unwrap_or("").is_empty() {
            "preview"
        } else {
            "apply"
        }
    };

    let (action, secret_names): (String, Vec<String>) = match tool_name {
        "run_command" => (
            format!(
                "run_command: {}",
                arguments["command"].as_str().unwrap_or("")
            ),
            vec![],
        ),
        "read_remote_file" => (
            format!(
                "read_remote_file: {}",
                arguments["path"].as_str().unwrap_or("")
            ),
            vec![],
        ),
        "write_remote_file" => (
            format!(
                "write_remote_file ({}): {}",
                dry_run_phase(arguments),
                arguments["path"].as_str().unwrap_or("")
            ),
            vec![],
        ),
        "query_database" => (
            format!(
                "query_database: {}",
                arguments["query"].as_str().unwrap_or("")
            ),
            vec![],
        ),
        "list_db_tables" => ("list_db_tables".to_string(), vec![]),
        "list_local_secret_names" => ("list_local_secret_names".to_string(), vec![]),
        "list_allowed_servers" => ("list_allowed_servers".to_string(), vec![]),
        "list_allowed_services" => ("list_allowed_services".to_string(), vec![]),
        "call_service_api" => (
            // Value-free: method, service name, and path only. The credential
            // name lives in service config, not in the call arguments.
            format!(
                "call_service_api: {} {} {}",
                arguments["method"].as_str().unwrap_or(""),
                arguments["service"].as_str().unwrap_or(""),
                arguments["path"].as_str().unwrap_or("")
            ),
            vec![],
        ),
        "deploy_secret_to_server" => {
            let env_key = arguments["env_key"].as_str().unwrap_or("");
            let secret_name = arguments["local_secret_name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            (
                format!(
                    "deploy_secret_to_server ({}): env_key={}",
                    dry_run_phase(arguments),
                    env_key
                ),
                if secret_name.is_empty() {
                    vec![]
                } else {
                    vec![secret_name]
                },
            )
        }
        other => (other.to_string(), vec![]),
    };

    (target, action, secret_names)
}

/// Determine whether a tool result represents success: no JSON-RPC error and no
/// `isError` flag on the tool result payload.
fn is_success(result: &Option<Value>, error: &Option<Value>) -> bool {
    if error.is_some() {
        return false;
    }
    match result {
        Some(v) => !v.get("isError").and_then(|b| b.as_bool()).unwrap_or(false),
        None => true,
    }
}

fn handle_request(
    req: JsonRpcRequest,
    config: &Config,
    pending: &PendingStore,
    audit: &AuditLog,
) -> JsonRpcResponse {
    let id = req.id.unwrap_or(Value::Null);
    let (result, error) = match req.method.as_str() {
        "initialize" => (
            Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "mcp-deploy-server",
                    "version": "0.1.0"
                }
            })),
            None,
        ),
        "tools/list" => (
            Some(json!({
                "tools": [
                    {
                        "name": "list_allowed_servers",
                        "description": "Returns a list of servers (IP and Alias) that this server is allowed to connect to.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    },
                    {
                        "name": "list_allowed_services",
                        "description": "Returns the list of allow-listed HTTP services (name and base_url) that can be driven via call_service_api. Secret names and values are never returned.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    },
                    {
                        "name": "call_service_api",
                        "description": "Performs an authenticated HTTP request against an allow-listed service (see list_allowed_services). BLIND-CREDENTIAL MODEL: you only name the service; the MCP server injects the configured credential from the local vault and the secret value is NEVER returned to you or written to logs. On a non-2xx response the body is still returned (with isError set) so you can debug.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "service": {
                                    "type": "string",
                                    "description": "The name of the allow-listed service (e.g. 'cloudflare')."
                                },
                                "method": {
                                    "type": "string",
                                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                                    "description": "The HTTP method to use."
                                },
                                "path": {
                                    "type": "string",
                                    "description": "The request path appended to the service base_url (e.g. '/user/tokens/verify')."
                                },
                                "query": {
                                    "type": "object",
                                    "description": "Optional query-string parameters as a flat object of string/number/bool values."
                                },
                                "headers": {
                                    "type": "object",
                                    "description": "Optional caller-supplied request headers as a flat object of string/number/bool values. Only 'X-Idempotency-Key' and 'Idempotency-Key' are passed through; all other headers (including 'Authorization') are dropped so injected credentials cannot be overridden."
                                },
                                "body": {
                                    "description": "Optional request body for write methods. If the value is a JSON string it is sent as a raw body; otherwise it is sent as a JSON document (objects, arrays, numbers, bools)."
                                }
                            },
                            "required": ["service", "method", "path"]
                        }
                    },
                    {
                        "name": "run_command",
                        "description": "Executes a command on a remote server via SSH. IMPORTANT: This tool is NON-INTERACTIVE and NON-STREAMING. Do not use commands that require user input (e.g. sudo without -n) or commands that run indefinitely (e.g. tail -f). Use bounded commands like 'tail -n 100' instead.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "The IP address or Alias of the server to connect to."
                                },
                                "command": {
                                    "type": "string",
                                    "description": "The command to execute (e.g. 'ls -la', 'uptime', 'tail -n 50 /var/log/syslog')."
                                }
                            },
                            "required": ["target", "command"]
                        }
                    },
                    {
                        "name": "read_remote_file",
                        "description": "Reads the content of a file from a remote server using SFTP.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "The IP address or Alias of the server."
                                },
                                "path": {
                                    "type": "string",
                                    "description": "The absolute path to the file on the remote server."
                                }
                            },
                            "required": ["target", "path"]
                        }
                    },
                    {
                        "name": "write_remote_file",
                        "description": "Writes content to a file on a remote server using SFTP, overwriting any existing file. SAFETY: This is a two-step operation. Call it FIRST without 'confirm_token' to get a DRY-RUN unified diff of exactly what would change (no data is written). Then call it AGAIN with the SAME target/path/content plus the 'confirm_token' returned by the dry run to actually apply the write.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "The IP address or Alias of the server."
                                },
                                "path": {
                                    "type": "string",
                                    "description": "The absolute path where the file should be written on the remote server."
                                },
                                "content": {
                                    "type": "string",
                                    "description": "The text content to write to the file."
                                },
                                "confirm_token": {
                                    "type": "string",
                                    "description": "Optional. Leave empty for a dry-run preview. To apply the change, pass back the token returned by the preview along with identical target/path/content."
                                }
                            },
                            "required": ["target", "path", "content"]
                        }
                    },
                    {
                        "name": "query_database",
                        "description": "Executes a SQL query on the server's Postgres database via psql. Safety: Production servers are strictly read-only (SELECT only). Beta servers may allow data modification.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "The IP address or Alias of the server."
                                },
                                "query": {
                                    "type": "string",
                                    "description": "The SQL query to execute."
                                }
                            },
                            "required": ["target", "query"]
                        }
                    },
                    {
                        "name": "list_db_tables",
                        "description": "Lists all tables in the remote database to help explore the schema.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "The IP address or Alias of the server."
                                }
                            },
                            "required": ["target"]
                        }
                    },
                    {
                        "name": "list_local_secret_names",
                        "description": "Lists the names of secrets available in the local vault associated with a specific server. Claude only sees the names, not the values.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "The IP address or Alias of the server to check secrets for."
                                }
                            },
                            "required": ["target"]
                        }
                    },
                    {
                        "name": "deploy_secret_to_server",
                        "description": "Takes a secret from your local vault and injects it into a remote .env file. The secret value never leaves the MCP server's process except to travel over the secure SSH tunnel. SAFETY: This is a two-step operation. Call it FIRST without 'confirm_token' to get a DRY-RUN diff showing whether the key will be added or updated (the secret value is redacted and never shown). Then call it AGAIN with identical arguments plus the returned 'confirm_token' to actually apply the change.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "The IP address or Alias of the server."
                                },
                                "remote_env_path": {
                                    "type": "string",
                                    "description": "Optional: The absolute path to the .env file. If omitted, the server's default_env_path will be used."
                                },
                                "env_key": {
                                    "type": "string",
                                    "description": "The key name to set in the remote .env file (e.g. STRIPE_API_KEY)."
                                },
                                "local_secret_name": {
                                    "type": "string",
                                    "description": "The name of the secret in your local mcp_secrets.json vault."
                                },
                                "confirm_token": {
                                    "type": "string",
                                    "description": "Optional. Leave empty for a dry-run preview. To apply the change, pass back the token returned by the preview along with identical arguments."
                                }
                            },
                            "required": ["target", "env_key", "local_secret_name"]
                        }
                    }
                ]
            })),
            None,
        ),
        "tools/call" => {
            let params = req.params.unwrap_or(Value::Null);
            let tool_name = params["name"].as_str().unwrap_or("");
            let arguments = &params["arguments"];

            let (call_result, call_error) = match tool_name {
                "list_allowed_servers" => {
                    let servers = config.allowed_servers();
                    (
                        Some(json!({
                            "content": [
                                {
                                    "type": "text",
                                    "text": format!("Allowed Servers: {:?}", servers)
                                }
                            ]
                        })),
                        None,
                    )
                }
                "list_allowed_services" => {
                    let services = config.allowed_services();
                    (
                        Some(json!({
                            "content": [
                                {
                                    "type": "text",
                                    "text": format!("Allowed Services: {:?}", services)
                                }
                            ]
                        })),
                        None,
                    )
                }
                "call_service_api" => {
                    let service = arguments["service"].as_str().unwrap_or("");
                    let method = arguments["method"].as_str().unwrap_or("");
                    let path = arguments["path"].as_str().unwrap_or("");
                    let query = arguments.get("query").filter(|v| !v.is_null());
                    let headers = arguments.get("headers").filter(|v| !v.is_null());
                    let body = arguments.get("body").filter(|v| !v.is_null());

                    match http::call_service(service, method, path, query, headers, body, config) {
                        Ok(resp) => {
                            // Defense-in-depth: the http layer already redacts the
                            // injected secret; run the body through the pattern
                            // scrubber as well before returning it to the agent.
                            let scrubbed = scrubber::scrub_output(&resp.render(), &[]);
                            if resp.is_success() {
                                text_result(scrubbed)
                            } else {
                                // Non-2xx: still return the body so the agent can
                                // debug, but flag it as an error.
                                error_result(scrubbed)
                            }
                        }
                        Err(e) => {
                            // The http layer already strips the request URL and
                            // redacts the injected secret from error text; run the
                            // message through the pattern scrubber as well so no
                            // data-bearing output reaches the agent unscrubbed.
                            let scrubbed = scrubber::scrub_output(
                                &format!("Error calling service: {}", e),
                                &[],
                            );
                            error_result(scrubbed)
                        }
                    }
                }
                "run_command" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    let command = arguments["command"].as_str().unwrap_or("");

                    // Block secret/credential exfiltration and enforce any
                    // per-server command allowlist before touching the network.
                    let allowed_prefixes = config
                        .get_server_by_target(target)
                        .and_then(|(_ip, info)| info.allowed_command_prefixes.clone());
                    if let Err(e) =
                        crate::command_guard::validate_command(command, allowed_prefixes.as_deref())
                    {
                        return JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: Some(json!({
                                "isError": true,
                                "content": [
                                    {
                                        "type": "text",
                                        "text": format!("{}", e)
                                    }
                                ]
                            })),
                            error: None,
                            id,
                        };
                    }

                    match ssh::run_ssh_command(target, command, config) {
                        Ok(output) => (
                            Some(json!({
                                "content": [
                                    {
                                        "type": "text",
                                        "text": scrub_for_target(config, target, &output)
                                    }
                                ]
                            })),
                            None,
                        ),
                        Err(e) => (
                            Some(json!({
                                "isError": true,
                                "content": [
                                    {
                                        "type": "text",
                                        "text": format!("Error: {}", e)
                                    }
                                ]
                            })),
                            None,
                        ),
                    }
                }
                "read_remote_file" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    let path = arguments["path"].as_str().unwrap_or("");

                    if path.contains(".env") {
                        (
                            Some(json!({
                                "isError": true,
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Security Error: Reading .env files is prohibited for safety reasons. Use the deploy_secret tools instead."
                                    }
                                ]
                            })),
                            None,
                        )
                    } else {
                        match ssh::read_remote_file(target, path, config) {
                            Ok(content) => (
                                Some(json!({
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": scrub_for_target(config, target, &content)
                                        }
                                    ]
                                })),
                                None,
                            ),
                            Err(e) => (
                                Some(json!({
                                    "isError": true,
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": format!("Error reading file: {}", e)
                                        }
                                    ]
                                })),
                                None,
                            ),
                        }
                    }
                }
                "write_remote_file" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    let path = arguments["path"].as_str().unwrap_or("");
                    let content = arguments["content"].as_str().unwrap_or("");
                    let confirm_token = arguments["confirm_token"].as_str().unwrap_or("");

                    let token = diff::change_token(target, path, content);

                    if confirm_token.is_empty() {
                        // Dry run: read the current file (if any) and show what would change.
                        match ssh::read_remote_file_if_exists(target, path, config) {
                            Ok(existing) => {
                                let old = existing.clone().unwrap_or_default();
                                let preview = diff::unified_diff(&old, content, path);
                                if preview.is_empty() {
                                    text_result(format!(
                                        "No changes: {} already contains exactly this content. Nothing to write.",
                                        path
                                    ))
                                } else {
                                    if let Ok(mut p) = pending.lock() {
                                        p.insert(token.clone());
                                    }
                                    let label = if existing.is_some() {
                                        "Modify existing file"
                                    } else {
                                        "Create new file"
                                    };
                                    text_result(format!(
                                        "DRY RUN — no changes written.\n{}: {}\n\n{}\nTo apply this exact change, call write_remote_file again with the same target/path/content plus confirm_token=\"{}\".",
                                        label, path, preview, token
                                    ))
                                }
                            }
                            Err(e) => error_result(format!("Error previewing write: {}", e)),
                        }
                    } else {
                        // Confirmation: only proceed if this exact change was previewed.
                        let known = pending.lock().map(|p| p.contains(&token)).unwrap_or(false);
                        if confirm_token != token || !known {
                            error_result(
                                "No matching preview for this write. Call write_remote_file without confirm_token first to review the diff, then confirm with the token it returns."
                                    .to_string(),
                            )
                        } else {
                            match ssh::write_remote_file(target, path, content, config) {
                                Ok(_) => {
                                    if let Ok(mut p) = pending.lock() {
                                        p.remove(&token);
                                    }
                                    text_result(format!("Successfully wrote to {}", path))
                                }
                                Err(e) => error_result(format!("Error writing file: {}", e)),
                            }
                        }
                    }
                }
                "query_database" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    let query = arguments["query"].as_str().unwrap_or("");

                    match ssh::query_database(target, query, config) {
                        Ok(output) => (
                            Some(json!({
                                "content": [
                                    {
                                        "type": "text",
                                        "text": scrub_for_target(config, target, &output)
                                    }
                                ]
                            })),
                            None,
                        ),
                        Err(e) => (
                            Some(json!({
                                "isError": true,
                                "content": [
                                    {
                                        "type": "text",
                                        "text": format!("Database error: {}", e)
                                    }
                                ]
                            })),
                            None,
                        ),
                    }
                }
                "list_db_tables" => {
                    let target = arguments["target"].as_str().unwrap_or("");

                    match ssh::list_db_tables(target, config) {
                        Ok(output) => (
                            Some(json!({
                                "content": [
                                    {
                                        "type": "text",
                                        "text": scrub_for_target(config, target, &output)
                                    }
                                ]
                            })),
                            None,
                        ),
                        Err(e) => (
                            Some(json!({
                                "isError": true,
                                "content": [
                                    {
                                        "type": "text",
                                        "text": format!("Database error: {}", e)
                                    }
                                ]
                            })),
                            None,
                        ),
                    }
                }
                "list_local_secret_names" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    match config.get_server_by_target(target) {
                        Some((_ip, info)) => {
                            let home = std::env::var("HOME").unwrap_or_default();
                            let secrets_path = info.secrets_path.clone().unwrap_or_else(|| {
                                format!("{}/.remote_connections/mcp_secrets.json", home)
                            });

                            match SecretStore::load(config.secret_backend(), &secrets_path) {
                                Ok(s) => {
                                    let names = s.list_names();
                                    (
                                        Some(json!({
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": format!("Available Secrets for {}: {:?}", target, names)
                                                }
                                            ]
                                        })),
                                        None,
                                    )
                                }
                                Err(e) => (
                                    Some(json!({
                                        "isError": true,
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": format!("Failed to load secrets from {}: {}", secrets_path, e)
                                            }
                                        ]
                                    })),
                                    None,
                                ),
                            }
                        }
                        None => (
                            Some(json!({
                                "isError": true,
                                "content": [
                                    {
                                        "type": "text",
                                        "text": format!("Target {} not found", target)
                                    }
                                ]
                            })),
                            None,
                        ),
                    }
                }
                "deploy_secret_to_server" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    let remote_env_path = arguments["remote_env_path"].as_str().unwrap_or("");
                    let env_key = arguments["env_key"].as_str().unwrap_or("");
                    let local_secret_name = arguments["local_secret_name"].as_str().unwrap_or("");
                    let confirm_token = arguments["confirm_token"].as_str().unwrap_or("");

                    match config.get_server_by_target(target) {
                        None => error_result(format!("Target {} not found", target)),
                        Some((_ip, info)) => {
                            let path_opt = if remote_env_path.is_empty() {
                                info.default_env_path.clone()
                            } else {
                                Some(remote_env_path.to_string())
                            };

                            match path_opt {
                                None => (
                                    None,
                                    Some(json!({
                                        "code": -32602,
                                        "message": "No remote_env_path provided and no default_env_path configured for this server."
                                    })),
                                ),
                                Some(path_to_use) => {
                                    let home = std::env::var("HOME").unwrap_or_default();
                                    let secrets_path =
                                        info.secrets_path.clone().unwrap_or_else(|| {
                                            format!("{}/.remote_connections/mcp_secrets.json", home)
                                        });

                                    let secret_value = match SecretStore::load(
                                        config.secret_backend(),
                                        &secrets_path,
                                    ) {
                                        Err(e) => {
                                            return JsonRpcResponse {
                                                jsonrpc: "2.0".to_string(),
                                                result: error_result(format!(
                                                    "Failed to load secrets: {}",
                                                    e
                                                ))
                                                .0,
                                                error: None,
                                                id,
                                            };
                                        }
                                        Ok(s) => s.get(local_secret_name),
                                    };

                                    let secret_value = match secret_value {
                                        None => {
                                            return JsonRpcResponse {
                                                jsonrpc: "2.0".to_string(),
                                                result: error_result(format!(
                                                    "Secret '{}' not found in {}",
                                                    local_secret_name, secrets_path
                                                ))
                                                .0,
                                                error: None,
                                                id,
                                            };
                                        }
                                        Some(v) => v,
                                    };

                                    // Compute the resulting env contents so we can preview and
                                    // tokenize the change without revealing the secret value.
                                    match ssh::read_remote_file_if_exists(
                                        target,
                                        &path_to_use,
                                        config,
                                    ) {
                                        Err(e) => error_result(format!(
                                            "Failed to read remote env file: {}",
                                            e
                                        )),
                                        Ok(existing) => {
                                            let old = existing.unwrap_or_default();
                                            let (new_content, updated) = ssh::compute_env_update(
                                                &old,
                                                env_key,
                                                &secret_value,
                                            );
                                            let token = diff::change_token(
                                                target,
                                                &path_to_use,
                                                &new_content,
                                            );

                                            if confirm_token.is_empty() {
                                                let red_old = diff::redact_env_value(
                                                    &old, env_key, "current",
                                                );
                                                let red_new = diff::redact_env_value(
                                                    &new_content,
                                                    env_key,
                                                    "new secret value",
                                                );
                                                let preview = diff::unified_diff(
                                                    &red_old,
                                                    &red_new,
                                                    &path_to_use,
                                                );
                                                if let Ok(mut p) = pending.lock() {
                                                    p.insert(token.clone());
                                                }
                                                let action = if updated { "Update" } else { "Add" };
                                                text_result(format!(
                                                    "DRY RUN — no changes written.\n{} key '{}' in {} (secret value redacted).\n\n{}\nTo apply, call deploy_secret_to_server again with identical arguments plus confirm_token=\"{}\".",
                                                    action, env_key, path_to_use, preview, token
                                                ))
                                            } else {
                                                let known = pending
                                                    .lock()
                                                    .map(|p| p.contains(&token))
                                                    .unwrap_or(false);
                                                if confirm_token != token || !known {
                                                    error_result(
                                                        "No matching preview for this secret deployment (the remote file or secret may have changed). Call deploy_secret_to_server without confirm_token first to review the diff, then confirm with the token it returns."
                                                            .to_string(),
                                                    )
                                                } else {
                                                    match ssh::update_remote_env_file(
                                                        target,
                                                        &path_to_use,
                                                        env_key,
                                                        &secret_value,
                                                        config,
                                                    ) {
                                                        Ok(_) => {
                                                            if let Ok(mut p) = pending.lock() {
                                                                p.remove(&token);
                                                            }
                                                            text_result(format!(
                                                                "Successfully deployed secret '{}' to {} on {}",
                                                                local_secret_name, env_key, target
                                                            ))
                                                        }
                                                        Err(e) => error_result(format!(
                                                            "Failed to deploy secret: {}",
                                                            e
                                                        )),
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => (
                    None,
                    Some(json!({
                        "code": -32601,
                        "message": format!("Tool not found: {}", tool_name)
                    })),
                ),
            };

            // Append a tamper-evident audit record for every tool call. A
            // failure to write the audit log is logged but never fails the
            // request itself.
            let (target, action, secret_names) = describe_tool_call(tool_name, arguments);
            let success = is_success(&call_result, &call_error);
            if let Err(e) = audit.record(tool_name, &target, &action, &secret_names, success) {
                error!("Failed to write audit log entry for {}: {}", tool_name, e);
            }

            (call_result, call_error)
        }
        _ => (
            None,
            Some(json!({
                "code": -32601,
                "message": "Method not found"
            })),
        ),
    };

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result,
        error,
        id,
    }
}
