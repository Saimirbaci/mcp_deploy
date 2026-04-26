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
    id: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<Value>,
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

    watcher.watch(PathBuf::from(&config_path).parent().unwrap_or(&PathBuf::from(".")), RecursiveMode::NonRecursive)?;

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

        match serde_json::from_str::<JsonRpcRequest>(&line) {
            Ok(req) => {
                let current_config = config.read().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?.clone();
                let response = handle_request(req, &current_config);
                let response_json = serde_json::to_string(&response)?;
                writeln!(stdout, "{}", response_json)?;
                stdout.flush()?;
            }
            Err(e) => {
                error!("Failed to parse JSON-RPC request: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_request(req: JsonRpcRequest, config: &Config) -> JsonRpcResponse {
    let result = match req.method.as_str() {
        "initialize" => Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "mcp-deploy-server",
                "version": "0.1.0"
            }
        })),
        "tools/list" => Some(json!({
            "tools": [
                {
                    "name": "list_allowed_servers",
                    "description": "Returns a list of IP addresses that this server is allowed to connect to.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "run_command",
                    "description": "Executes a command on a remote server via SSH. The IP must be in the allowed list.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "ip": {
                                "type": "string",
                                "description": "The IP address of the server to connect to."
                            },
                            "command": {
                                "type": "string",
                                "description": "The command to execute."
                            }
                        },
                        "required": ["ip", "command"]
                    }
                }
            ]
        })),
        "tools/call" => {
            let params = req.params.unwrap_or(Value::Null);
            let tool_name = params["name"].as_str().unwrap_or("");
            let arguments = &params["arguments"];

            match tool_name {
                "list_allowed_servers" => {
                    let ips = config.allowed_ips();
                    Some(json!({
                        "content": [
                            {
                                "type": "text",
                                "text": format!("Allowed IPs: {:?}", ips)
                            }
                        ]
                    }))
                }
                "run_command" => {
                    let ip = arguments["ip"].as_str().unwrap_or("");
                    let command = arguments["command"].as_str().unwrap_or("");
                    
                    match ssh::run_ssh_command(ip, command, config) {
                        Ok(output) => Some(json!({
                            "content": [
                                {
                                    "type": "text",
                                    "text": output
                                }
                            ]
                        })),
                        Err(e) => Some(json!({
                            "isError": true,
                            "content": [
                                {
                                    "type": "text",
                                    "text": format!("Error: {}", e)
                                }
                            ]
                        })),
                    }
                }
                _ => {
                    return JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(json!({
                            "code": -32601,
                            "message": format!("Tool not found: {}", tool_name)
                        })),
                        id: req.id,
                    };
                }
            }
        }
        _ => Some(json!({
            "code": -32601,
            "message": "Method not found"
        })),
    };

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result,
        error: None,
        id: req.id,
    }
}
