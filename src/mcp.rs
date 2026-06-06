use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use crate::config::{self, Config, Secrets};
use crate::scrubber;
use crate::ssh;
use anyhow::Result;
use tracing::error;

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

use std::sync::{Arc, RwLock};
use notify::{Watcher, RecursiveMode, EventKind};
use std::path::PathBuf;

pub fn run_server(initial_config: Config, config_path: String) -> Result<()> {
    let config = Arc::new(RwLock::new(initial_config));
    
    let config_for_watcher = Arc::clone(&config);
    let path_for_watcher = PathBuf::from(&config_path);

    // Setup file watcher
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        match res {
            Ok(event) => {
                if let EventKind::Modify(_) = event.kind {
                    match Config::load(&path_for_watcher) {
                        Ok(new_config) => {
                            if let Ok(mut w) = config_for_watcher.write() {
                                *w = new_config;
                                error!("Config reloaded successfully from {}", path_for_watcher.display());
                            }
                        }
                        Err(e) => error!("Failed to reload config: {}", e),
                    }
                }
            }
            Err(e) => error!("Watch error: {:?}", e),
        }
    })?;

    let watch_path = PathBuf::from(&config_path);
    let watch_dir = watch_path.parent().unwrap_or_else(|| std::path::Path::new("."));
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

                let current_config = config.read().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?.clone();
                let response = handle_request(req, &current_config);
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

fn handle_request(req: JsonRpcRequest, config: &Config) -> JsonRpcResponse {
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
            None
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
                        "description": "Writes content to a file on a remote server using SFTP. If the file exists, it will be overwritten.",
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
                        "description": "Takes a secret from your local vault and injects it into a remote .env file. The secret value never leaves the MCP server's process except to travel over the secure SSH tunnel.",
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
                                }
                            },
                            "required": ["target", "env_key", "local_secret_name"]
                        }
                    }
                ]
            })),
            None
        ),
        "tools/call" => {
            let params = req.params.unwrap_or(Value::Null);
            let tool_name = params["name"].as_str().unwrap_or("");
            let arguments = &params["arguments"];

            match tool_name {
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
                        None
                    )
                }
                "run_command" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    let command = arguments["command"].as_str().unwrap_or("");

                    // Block secret/credential exfiltration and enforce any
                    // per-server command allowlist before touching the network.
                    let allowed_prefixes = config
                        .get_server_by_target(target)
                        .and_then(|(_ip, info)| info.allowed_command_prefixes.clone());
                    if let Err(e) = crate::command_guard::validate_command(
                        command,
                        allowed_prefixes.as_deref(),
                    ) {
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
                            None
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
                            None
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
                            None
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
                                None
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
                                None
                            ),
                        }
                    }
                }
                "write_remote_file" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    let path = arguments["path"].as_str().unwrap_or("");
                    let content = arguments["content"].as_str().unwrap_or("");
                    
                    match ssh::write_remote_file(target, path, content, config) {
                        Ok(_) => (
                            Some(json!({
                                "content": [
                                    {
                                        "type": "text",
                                        "text": format!("Successfully wrote to {}", path)
                                    }
                                ]
                            })),
                            None
                        ),
                        Err(e) => (
                            Some(json!({
                                "isError": true,
                                "content": [
                                    {
                                        "type": "text",
                                        "text": format!("Error writing file: {}", e)
                                    }
                                ]
                            })),
                            None
                        ),
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
                            None
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
                            None
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
                            None
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
                            None
                        ),
                    }
                }
                "list_local_secret_names" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    match config.get_server_by_target(target) {
                        Some((_ip, info)) => {
                            let home = std::env::var("HOME").unwrap_or_default();
                            let secrets_path = info.secrets_path.clone().unwrap_or_else(|| format!("{}/.remote_connections/mcp_secrets.json", home));
                            
                            match Secrets::load(&secrets_path) {
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
                                        None
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
                                    None
                                )
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
                            None
                        ),
                    }
                }
                "deploy_secret_to_server" => {
                    let target = arguments["target"].as_str().unwrap_or("");
                    let remote_env_path = arguments["remote_env_path"].as_str().unwrap_or("");
                    let env_key = arguments["env_key"].as_str().unwrap_or("");
                    let local_secret_name = arguments["local_secret_name"].as_str().unwrap_or("");
                    
                    match config.get_server_by_target(target) {
                        Some((_ip, info)) => {
                            let path_opt = if remote_env_path.is_empty() {
                                info.default_env_path.clone()
                            } else {
                                Some(remote_env_path.to_string())
                            };

                            match path_opt {
                                Some(path_to_use) => {
                                    let home = std::env::var("HOME").unwrap_or_default();
                                    let secrets_path = info.secrets_path.clone().unwrap_or_else(|| format!("{}/.remote_connections/mcp_secrets.json", home));
                                    
                                    match Secrets::load(&secrets_path) {
                                        Ok(s) => {
                                            match s.get(local_secret_name) {
                                                Some(secret_value) => {
                                                    match ssh::update_remote_env_file(target, &path_to_use, env_key, &secret_value, config) {
                                                        Ok(_) => (
                                                            Some(json!({
                                                                "content": [
                                                                    {
                                                                        "type": "text",
                                                                        "text": format!("Successfully deployed secret '{}' to {} on {}", local_secret_name, env_key, target)
                                                                    }
                                                                ]
                                                            })),
                                                            None
                                                        ),
                                                        Err(e) => (
                                                            Some(json!({
                                                                "isError": true,
                                                                "content": [
                                                                    {
                                                                        "type": "text",
                                                                        "text": format!("Failed to deploy secret: {}", e)
                                                                    }
                                                                ]
                                                            })),
                                                            None
                                                        ),
                                                    }
                                                }
                                                None => (
                                                    Some(json!({
                                                        "isError": true,
                                                        "content": [
                                                            {
                                                                "type": "text",
                                                                "text": format!("Secret '{}' not found in {}", local_secret_name, secrets_path)
                                                            }
                                                        ]
                                                    })),
                                                    None
                                                )
                                            }
                                        }
                                        Err(e) => (
                                            Some(json!({
                                                "isError": true,
                                                "content": [
                                                    {
                                                        "type": "text",
                                                        "text": format!("Failed to load secrets: {}", e)
                                                    }
                                                ]
                                            })),
                                            None
                                        )
                                    }
                                }
                                None => (
                                    None,
                                    Some(json!({
                                        "code": -32602,
                                        "message": "No remote_env_path provided and no default_env_path configured for this server."
                                    }))
                                )
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
                            None
                        ),
                    }
                }
                _ => (
                    None,
                    Some(json!({
                        "code": -32601,
                        "message": format!("Tool not found: {}", tool_name)
                    }))
                ),
            }
        }
        _ => (
            None,
            Some(json!({
                "code": -32601,
                "message": "Method not found"
            }))
        ),
    };

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result,
        error,
        id,
    }
}
