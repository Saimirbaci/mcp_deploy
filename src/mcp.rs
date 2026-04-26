use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use crate::config::Config;
use crate::ssh;
use anyhow::Result;
use tracing::error;

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
                    
                    match ssh::run_ssh_command(target, command, config) {
                        Ok(output) => (
                            Some(json!({
                                "content": [
                                    {
                                        "type": "text",
                                        "text": output
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
