use anyhow::{anyhow, Result};

/// Substrings that indicate an attempt to read secrets, private keys, or
/// credential stores. Matched case-insensitively anywhere in the command so
/// that chained or piped invocations (e.g. `cat ~/.ssh/id_rsa | base64`) are
/// also caught.
const DENY_SUBSTRINGS: &[&str] = &[
    // Environment / secret files
    ".env",
    ".netrc",
    // SSH / private keys
    ".ssh/",
    "/.ssh",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".pem",
    ".ppk",
    "private_key",
    "-----begin", // pasted PEM blocks
    // Cloud / tooling credential stores
    ".aws/credentials",
    ".aws/config",
    ".git-credentials",
    ".kube/config",
    ".docker/config.json",
    "gcloud/credentials",
    "credentials.json",
    // System credential databases
    "/etc/shadow",
    "/etc/gshadow",
];

/// Command words (the actual program being invoked) that dump the process
/// environment, which routinely contains injected secrets. These are matched as
/// whole tokens so that names like `environment` are not falsely flagged.
const DENY_COMMAND_WORDS: &[&str] = &["env", "printenv"];

/// Validates a command before it is executed on a remote server.
///
/// Two layers of protection are applied:
/// 1. A denylist that blocks reads of `.env` files, SSH/private key material,
///    and credential directories regardless of any allowlist configuration.
/// 2. An optional per-server allowlist of permitted command prefixes. When
///    configured, the command must start with one of the allowed prefixes
///    (fail-closed); when absent, only the denylist is enforced.
pub fn validate_command(command: &str, allowed_prefixes: Option<&[String]>) -> Result<()> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Security Error: empty command is not permitted"));
    }

    let lowered = trimmed.to_lowercase();

    // Layer 1a: deny sensitive path/file substrings.
    for pattern in DENY_SUBSTRINGS {
        if lowered.contains(pattern) {
            return Err(anyhow!(
                "Security Error: command references a protected pattern ('{}'). \
                 Reading secrets, private keys, or credentials is prohibited. \
                 Use the deploy_secret tools to manage secrets instead.",
                pattern
            ));
        }
    }

    // Layer 1b: deny commands that dump the environment. Normalize shell
    // separators and substitution syntax to whitespace so each program token
    // can be inspected on its own.
    let normalized: String = lowered
        .chars()
        .map(|c| match c {
            '|' | '&' | ';' | '`' | '(' | ')' | '\n' | '\t' | '<' | '>' => ' ',
            other => other,
        })
        .collect();
    for token in normalized.split_whitespace() {
        for word in DENY_COMMAND_WORDS {
            if token == *word || token.ends_with(&format!("/{}", word)) {
                return Err(anyhow!(
                    "Security Error: the '{}' command is blocked because it can \
                     expose injected secrets from the process environment.",
                    word
                ));
            }
        }
    }

    // Layer 2: optional per-server allowlist of command prefixes.
    if let Some(prefixes) = allowed_prefixes
        && !prefixes.is_empty()
        && !prefixes.iter().any(|prefix| trimmed.starts_with(prefix.trim()))
    {
        return Err(anyhow!(
            "Security Error: command is not in the allowed command prefix \
             list for this server. Permitted prefixes: {:?}",
            prefixes
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_cat_env_file() {
        assert!(validate_command("cat .env", None).is_err());
        assert!(validate_command("cat /srv/app/.env.production", None).is_err());
    }

    #[test]
    fn test_blocks_env_dump_commands() {
        assert!(validate_command("env", None).is_err());
        assert!(validate_command("printenv", None).is_err());
        assert!(validate_command("printenv DATABASE_URL", None).is_err());
        assert!(validate_command("/usr/bin/env", None).is_err());
        assert!(validate_command("ls && env", None).is_err());
        assert!(validate_command("echo hi | printenv", None).is_err());
    }

    #[test]
    fn test_blocks_ssh_and_private_keys() {
        assert!(validate_command("cat ~/.ssh/id_rsa", None).is_err());
        assert!(validate_command("cat /home/deploy/.ssh/id_ed25519", None).is_err());
        assert!(validate_command("cat server.pem", None).is_err());
    }

    #[test]
    fn test_blocks_credential_stores() {
        assert!(validate_command("cat ~/.aws/credentials", None).is_err());
        assert!(validate_command("cat ~/.git-credentials", None).is_err());
        assert!(validate_command("cat /etc/shadow", None).is_err());
    }

    #[test]
    fn test_blocks_command_substitution() {
        assert!(validate_command("echo $(printenv)", None).is_err());
        assert!(validate_command("echo `env`", None).is_err());
    }

    #[test]
    fn test_allows_benign_commands() {
        assert!(validate_command("ls -la", None).is_ok());
        assert!(validate_command("uptime", None).is_ok());
        assert!(validate_command("tail -n 100 /var/log/syslog", None).is_ok());
        // 'environment' must not be flagged as the 'env' command.
        assert!(validate_command("cat /opt/app/environment.txt", None).is_ok());
    }

    #[test]
    fn test_allowlist_enforced_when_configured() {
        let prefixes = vec!["ls".to_string(), "tail ".to_string(), "systemctl status".to_string()];
        assert!(validate_command("ls -la", Some(&prefixes)).is_ok());
        assert!(validate_command("systemctl status nginx", Some(&prefixes)).is_ok());
        assert!(validate_command("rm -rf /", Some(&prefixes)).is_err());
        assert!(validate_command("cat /etc/hosts", Some(&prefixes)).is_err());
    }

    #[test]
    fn test_allowlist_does_not_override_denylist() {
        // Even if a prefix would permit it, the denylist still blocks secrets.
        let prefixes = vec!["cat".to_string()];
        assert!(validate_command("cat .env", Some(&prefixes)).is_err());
        assert!(validate_command("cat ~/.ssh/id_rsa", Some(&prefixes)).is_err());
    }

    #[test]
    fn test_empty_allowlist_falls_back_to_denylist_only() {
        let prefixes: Vec<String> = vec![];
        assert!(validate_command("ls -la", Some(&prefixes)).is_ok());
        assert!(validate_command("cat .env", Some(&prefixes)).is_err());
    }
}
