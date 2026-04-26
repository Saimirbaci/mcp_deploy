use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use crate::config::Config;
use crate::ssh;
use anyhow::Result;
use tracing::{info, error};

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
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

pub fn run_server(config: Config) -> Result<()> {
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
                let response = handle_request(req, &config);
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
