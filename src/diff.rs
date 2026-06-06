//! Dry-run / diff preview support for remote write operations.
//!
//! Before a write actually touches a remote server, the MCP layer generates a
//! unified diff of what would change and hands the caller a deterministic
//! confirmation token. The write is only performed when the same operation is
//! requested a second time with that token, which prevents an agent from
//! silently clobbering a file it never previewed.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use similar::TextDiff;

/// Placeholder used to mask secret values in env-file diff previews so that a
/// secret is never revealed to the caller while still showing that a line
/// changed.
pub const REDACTED: &str = "<redacted>";

/// Render a unified diff between `old` and `new` content for `path`.
///
/// When the two inputs are identical the returned string is empty, which the
/// caller can use to detect a no-op write.
pub fn unified_diff(old: &str, new: &str, path: &str) -> String {
    let diff = TextDiff::from_lines(old, new);
    diff.unified_diff()
        .header(&format!("a{}", path), &format!("b{}", path))
        .to_string()
}

/// Compute the deterministic confirmation token for a write operation.
///
/// The token is derived from the target, path, and the exact bytes that would
/// be written, so a confirming call only succeeds when it describes the same
/// change that was previewed. If the remote file (and therefore the resulting
/// content) changed between preview and confirm, the recomputed token no longer
/// matches and a fresh preview is required.
pub fn change_token(target: &str, path: &str, new_content: &str) -> String {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    path.hash(&mut hasher);
    new_content.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Returns true when `line` is an assignment for `key` in an env file
/// (e.g. `KEY=value`, possibly surrounded by whitespace).
fn is_env_key_line(line: &str, key: &str) -> bool {
    let trimmed = line.trim_start();
    match trimmed.split_once('=') {
        Some((lhs, _)) => lhs.trim() == key,
        None => false,
    }
}

/// Produce a copy of env-file `content` in which the value assigned to `key`
/// is masked. `label` lets callers distinguish the "before" and "after"
/// versions so the masked lines still differ in the rendered diff.
pub fn redact_env_value(content: &str, key: &str, label: &str) -> String {
    let out: Vec<String> = content
        .lines()
        .map(|line| {
            if is_env_key_line(line, key) {
                format!("{}={} ({})", key, REDACTED, label)
            } else {
                line.to_string()
            }
        })
        .collect();
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_diff_is_empty_for_identical_content() {
        assert!(unified_diff("a\nb\n", "a\nb\n", "/etc/app.conf").is_empty());
    }

    #[test]
    fn unified_diff_shows_added_and_removed_lines() {
        let diff = unified_diff("one\ntwo\n", "one\nTWO\nthree\n", "/srv/file.txt");
        assert!(diff.contains("-two"));
        assert!(diff.contains("+TWO"));
        assert!(diff.contains("+three"));
        assert!(diff.contains("a/srv/file.txt"));
        assert!(diff.contains("b/srv/file.txt"));
    }

    #[test]
    fn change_token_is_stable_and_sensitive_to_inputs() {
        let a = change_token("prod", "/srv/x", "hello");
        assert_eq!(a, change_token("prod", "/srv/x", "hello"));
        assert_ne!(a, change_token("prod", "/srv/x", "hello!"));
        assert_ne!(a, change_token("prod", "/srv/y", "hello"));
        assert_ne!(a, change_token("beta", "/srv/x", "hello"));
    }

    #[test]
    fn redact_env_value_masks_only_target_key() {
        let content = "OTHER=keepme\nAPI_KEY=supersecret\n# comment";
        let redacted = redact_env_value(content, "API_KEY", "new");
        assert!(redacted.contains("OTHER=keepme"));
        assert!(redacted.contains("# comment"));
        assert!(!redacted.contains("supersecret"));
        assert!(redacted.contains("API_KEY=<redacted> (new)"));
    }

    #[test]
    fn redact_env_value_ignores_substring_key_matches() {
        // MY_API_KEY must not be treated as API_KEY.
        let content = "MY_API_KEY=other";
        let redacted = redact_env_value(content, "API_KEY", "new");
        assert!(redacted.contains("MY_API_KEY=other"));
    }
}
