use crate::config::Config;
use anyhow::{Context, Result, anyhow};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;

pub fn run_ssh_command(target: &str, command: &str, config: &Config) -> Result<String> {
    let (ip, server_info) = config.get_server_by_target(target).ok_or_else(|| {
        anyhow!(
            "Target {} (IP or Alias) is not in the allowed servers list",
            target
        )
    })?;

    let tcp = TcpStream::connect(format!("{}:22", ip))
        .with_context(|| format!("Failed to connect to {} ({})", target, ip))?;

    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake().context("SSH handshake failed")?;

    sess.userauth_pubkey_file(
        &server_info.user,
        None,
        Path::new(&server_info.key_path),
        None,
    )
    .context("SSH authentication failed")?;

    let mut channel = sess
        .channel_session()
        .context("Failed to open SSH channel")?;
    channel.exec(command).context("Failed to execute command")?;

    let mut output = String::new();
    channel
        .read_to_string(&mut output)
        .context("Failed to read command output")?;

    // We can also read stderr if needed, but for now we'll just return stdout.
    // To be more thorough, we could return a struct with status, stdout, and stderr.

    channel.wait_close().ok();

    Ok(output)
}
pub fn read_remote_file(target: &str, remote_path: &str, config: &Config) -> Result<String> {
    let (ip, server_info) = config
        .get_server_by_target(target)
        .ok_or_else(|| anyhow!("Target {} not found", target))?;

    let tcp = TcpStream::connect(format!("{}:22", ip))?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_pubkey_file(
        &server_info.user,
        None,
        Path::new(&server_info.key_path),
        None,
    )?;

    let sftp = sess.sftp().context("Failed to start SFTP session")?;
    let mut file = sftp
        .open(Path::new(remote_path))
        .context("Failed to open remote file")?;

    let mut content = String::new();
    file.read_to_string(&mut content)
        .context("Failed to read remote file content")?;

    Ok(content)
}

/// Read a remote file, returning `Ok(None)` when the file does not exist.
///
/// Used to build a diff preview for `write_remote_file`: a missing file is a
/// valid "create new file" case rather than an error, while genuine failures
/// (permissions, connectivity) still surface as errors.
pub fn read_remote_file_if_exists(
    target: &str,
    remote_path: &str,
    config: &Config,
) -> Result<Option<String>> {
    let (ip, server_info) = config
        .get_server_by_target(target)
        .ok_or_else(|| anyhow!("Target {} not found", target))?;

    let tcp = TcpStream::connect(format!("{}:22", ip))?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_pubkey_file(
        &server_info.user,
        None,
        Path::new(&server_info.key_path),
        None,
    )?;

    let sftp = sess.sftp().context("Failed to start SFTP session")?;
    match sftp.stat(Path::new(remote_path)) {
        Ok(_) => {}
        Err(_) => return Ok(None),
    }

    let mut file = sftp
        .open(Path::new(remote_path))
        .context("Failed to open remote file")?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .context("Failed to read remote file content")?;
    Ok(Some(content))
}

pub fn write_remote_file(
    target: &str,
    remote_path: &str,
    content: &str,
    config: &Config,
) -> Result<()> {
    let (ip, server_info) = config
        .get_server_by_target(target)
        .ok_or_else(|| anyhow!("Target {} not found", target))?;

    let tcp = TcpStream::connect(format!("{}:22", ip))?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_pubkey_file(
        &server_info.user,
        None,
        Path::new(&server_info.key_path),
        None,
    )?;

    let sftp = sess.sftp().context("Failed to start SFTP session")?;
    let mut file = sftp
        .create(Path::new(remote_path))
        .context("Failed to create remote file")?;

    use std::io::Write;
    file.write_all(content.as_bytes())
        .context("Failed to write to remote file")?;
    file.flush()?;

    Ok(())
}
pub fn query_database(target: &str, query: &str, config: &Config) -> Result<String> {
    let (_ip, server_info) = config
        .get_server_by_target(target)
        .ok_or_else(|| anyhow!("Target {} not found", target))?;

    let db_config = server_info
        .db_config
        .as_ref()
        .ok_or_else(|| anyhow!("Database is not configured for target {}", target))?;

    // Basic security check for readonly servers
    if db_config.readonly {
        let q = query.trim().to_lowercase();
        if !q.starts_with("select") {
            return Err(anyhow!(
                "Permission denied: Only SELECT queries are allowed on this server ({})",
                target
            ));
        }
        let destructive = [
            "drop", "delete", "truncate", "update", "insert", "alter", "create", "grant",
        ];
        for keyword in destructive {
            if q.contains(keyword) {
                // Check if the keyword is not just part of a column name (simple check)
                if q.contains(&format!(" {} ", keyword)) || q.contains(&format!("{};", keyword)) {
                    return Err(anyhow!(
                        "Permission denied: destructive keyword '{}' detected in readonly mode",
                        keyword
                    ));
                }
            }
        }
    }

    let password_env = if let Some(pw) = &db_config.password {
        format!("PGPASSWORD='{}' ", pw)
    } else {
        String::new()
    };

    // psql -h localhost -U user -d db -c "query"
    // Use --csv for clean parsing or -P pager=off for raw table
    let psql_cmd = format!(
        "{}psql -h localhost -U {} -d {} -c \"{}\"",
        password_env,
        db_config.user,
        db_config.name,
        query.replace("\"", "\\\"")
    );

    run_ssh_command(target, &psql_cmd, config)
}

pub fn list_db_tables(target: &str, config: &Config) -> Result<String> {
    let (_ip, server_info) = config
        .get_server_by_target(target)
        .ok_or_else(|| anyhow!("Target {} not found", target))?;

    let db_config = server_info
        .db_config
        .as_ref()
        .ok_or_else(|| anyhow!("Database is not configured for target {}", target))?;

    let password_env = if let Some(pw) = &db_config.password {
        format!("PGPASSWORD='{}' ", pw)
    } else {
        String::new()
    };

    let psql_cmd = format!(
        "{}psql -h localhost -U {} -d {} -c \"\\dt\"",
        password_env, db_config.user, db_config.name
    );

    run_ssh_command(target, &psql_cmd, config)
}
/// Compute the new contents of an env file after setting `key` to `value`,
/// without performing any I/O. An existing assignment for `key` is replaced in
/// place; otherwise the assignment is appended. Returns the new content and
/// whether an existing key was updated (`true`) versus added (`false`).
pub fn compute_env_update(content: &str, key: &str, value: &str) -> (String, bool) {
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut found = false;
    let new_line = format!("{}={}", key, value);

    for line in &mut lines {
        if line.trim().starts_with(key) && line.contains('=') {
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts[0].trim() == key {
                *line = new_line.clone();
                found = true;
                break;
            }
        }
    }

    if !found {
        lines.push(new_line);
    }

    (lines.join("\n"), found)
}

pub fn update_remote_env_file(
    target: &str,
    remote_path: &str,
    key: &str,
    value: &str,
    config: &Config,
) -> Result<()> {
    let content = read_remote_file_if_exists(target, remote_path, config)?.unwrap_or_default();
    let (new_content, _updated) = compute_env_update(&content, key, value);
    write_remote_file(target, remote_path, &new_content, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_env_update_replaces_existing_key_in_place() {
        let content = "FOO=1\nAPI_KEY=old\nBAR=2";
        let (new_content, updated) = compute_env_update(content, "API_KEY", "new");
        assert!(updated);
        assert_eq!(new_content, "FOO=1\nAPI_KEY=new\nBAR=2");
    }

    #[test]
    fn compute_env_update_appends_missing_key() {
        let content = "FOO=1";
        let (new_content, updated) = compute_env_update(content, "API_KEY", "new");
        assert!(!updated);
        assert_eq!(new_content, "FOO=1\nAPI_KEY=new");
    }

    #[test]
    fn compute_env_update_does_not_match_key_prefix() {
        // API_KEY_EXTRA must not be mistaken for API_KEY.
        let content = "API_KEY_EXTRA=keep";
        let (new_content, updated) = compute_env_update(content, "API_KEY", "new");
        assert!(!updated);
        assert_eq!(new_content, "API_KEY_EXTRA=keep\nAPI_KEY=new");
    }
}
