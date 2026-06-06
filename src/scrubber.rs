use std::sync::LazyLock;

use regex::Regex;

/// The placeholder substituted in place of any detected secret material.
pub const REDACTED: &str = "[REDACTED]";

/// Minimum length for a known vault value to be eligible for literal scrubbing.
/// Very short values (e.g. "1", "db") would match huge amounts of benign output
/// and produce useless, over-redacted results, so they are skipped.
const MIN_LITERAL_SECRET_LEN: usize = 6;

/// Regex patterns for common secret formats. Each is matched anywhere in the
/// output and replaced with [`REDACTED`]. Patterns are compiled once on first
/// use and reused for the lifetime of the process.
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let sources = [
        // Stripe live/test secret & restricted keys (e.g. sk_live_..., rk_live_...).
        r"(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{8,}",
        // AWS access key IDs (AKIA / ASIA followed by 16 base32 chars).
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        // PEM-encoded key/certificate blocks (private keys, certs, etc.).
        r"(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----",
        // JSON Web Tokens (three base64url segments separated by dots).
        r"\beyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\b",
        // GitHub personal access / app tokens.
        r"\bgh[pousr]_[0-9A-Za-z]{20,}\b",
        // Google API keys.
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        // Slack tokens.
        r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
    ];

    sources
        .iter()
        .map(|src| Regex::new(src).expect("scrubber pattern must be a valid regex"))
        .collect()
});

/// Scrubs secret material out of tool output before it is returned to the agent.
///
/// Two layers are applied, in order:
/// 1. **Known vault values** — any literal secret value from the local vault
///    (passed in `known_secrets`) is replaced wherever it appears. This catches
///    secrets that have no recognizable format. Values shorter than
///    [`MIN_LITERAL_SECRET_LEN`] are skipped to avoid over-redaction.
/// 2. **Pattern matches** — common secret formats (Stripe keys, AWS access key
///    IDs, PEM blocks, JWTs, etc.) are replaced even if they are not in the vault.
///
/// The result is safe to place in chat history and logs.
pub fn scrub_output(text: &str, known_secrets: &[String]) -> String {
    let mut scrubbed = text.to_string();

    // Layer 1: redact exact known vault values.
    for secret in known_secrets {
        let secret = secret.trim();
        if secret.len() < MIN_LITERAL_SECRET_LEN {
            continue;
        }
        if scrubbed.contains(secret) {
            scrubbed = scrubbed.replace(secret, REDACTED);
        }
    }

    // Layer 2: redact known secret formats by pattern.
    for pattern in PATTERNS.iter() {
        scrubbed = pattern.replace_all(&scrubbed, REDACTED).into_owned();
    }

    scrubbed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacts_known_vault_value() {
        let secrets = vec!["super-secret-password-123".to_string()];
        let out = scrub_output("DB_PASS=super-secret-password-123 here", &secrets);
        assert!(!out.contains("super-secret-password-123"));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn test_skips_short_vault_values() {
        // A short value must not nuke every occurrence in benign output.
        let secrets = vec!["db".to_string()];
        let out = scrub_output("the db is up", &secrets);
        assert_eq!(out, "the db is up");
    }

    #[test]
    fn test_redacts_stripe_key() {
        let out = scrub_output("key=sk_live_abcdEF1234567890ghij", &[]);
        assert!(!out.contains("sk_live_"));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn test_redacts_aws_access_key() {
        let out = scrub_output("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", &[]);
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn test_redacts_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let out = scrub_output(&format!("token: {}", jwt), &[]);
        assert!(!out.contains(jwt));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn test_redacts_pem_block() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc123\n-----END RSA PRIVATE KEY-----";
        let out = scrub_output(&format!("contents:\n{}\n", pem), &[]);
        assert!(!out.contains("MIIEowIBAAKCAQEA"));
        assert!(!out.contains("BEGIN RSA PRIVATE KEY"));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn test_redacts_github_token() {
        let out = scrub_output("ghp_0123456789abcdefghijABCDEFGHIJ012345", &[]);
        assert!(out.contains(REDACTED));
        assert!(!out.contains("ghp_0123456789"));
    }

    #[test]
    fn test_leaves_benign_output_untouched() {
        let text = "total 8\ndrwxr-xr-x  2 deploy deploy 4096 Jan  1 00:00 logs\nuptime: 3 days";
        assert_eq!(scrub_output(text, &[]), text);
    }

    #[test]
    fn test_redacts_multiple_secrets_in_one_output() {
        let text = "id=AKIAIOSFODNN7EXAMPLE secret=sk_live_abcdEF1234567890ghij";
        let out = scrub_output(text, &[]);
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!out.contains("sk_live_"));
        assert_eq!(out.matches(REDACTED).count(), 2);
    }
}
