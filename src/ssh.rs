use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use ssh2::Session;
use anyhow::{anyhow, Result, Context};
use crate::config::Config;

pub fn run_ssh_command(ip: &str, command: &str, config: &Config) -> Result<String> {
    let server_info = config.get_server(ip)
        .ok_or_else(|| anyhow!("IP {} is not in the allowed servers list", ip))?;

    let tcp = TcpStream::connect(format!("{}:22", ip))
        .with_context(|| format!("Failed to connect to {}", ip))?;
    
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake().context("SSH handshake failed")?;

    sess.userauth_pubkey_file(
        &server_info.user,
        None,
        Path::new(&server_info.key_path),
        None,
    ).context("SSH authentication failed")?;

    let mut channel = sess.channel_session().context("Failed to open SSH channel")?;
    channel.exec(command).context("Failed to execute command")?;

    let mut output = String::new();
    channel.read_to_string(&mut output).context("Failed to read command output")?;
    
    // We can also read stderr if needed, but for now we'll just return stdout.
    // To be more thorough, we could return a struct with status, stdout, and stderr.
    
    channel.wait_close().ok();
    
    Ok(output)
}
