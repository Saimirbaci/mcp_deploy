//! Tamper-evident audit log of tool calls.
//!
//! Every tool invocation handled by the MCP server is appended to an
//! append-only, hash-chained log that lives in a file separate from the stderr
//! `tracing` stream. Each entry records who/what/when/target, the names (never
//! the values) of any secrets involved, and whether the call succeeded.
//!
//! Tamper-evidence comes from a SHA-256 hash chain: every entry stores the hash
//! of the previous entry plus a hash over its own fields. Removing, reordering,
//! or editing any entry breaks the chain, which `verify_chain` detects. The log
//! is an artifact for security reviews and incident response, not a secret
//! store — values are deliberately kept out of it.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hash recorded as the `prev_hash` of the very first entry. 64 hex zeros so it
/// is the same width as a real SHA-256 digest.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Field separator mixed into the hash so that, e.g., `("ab", "c")` and
/// `("a", "bc")` cannot collide into the same digest input.
const SEP: &[u8] = b"\x1f";

/// A single append-only audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number, starting at 0.
    pub seq: u64,
    /// Milliseconds since the Unix epoch (when the call was recorded).
    pub timestamp_ms: u128,
    /// OS user operating the MCP server process ("who").
    pub actor: String,
    /// Tool name that was invoked ("what").
    pub tool: String,
    /// Server alias or IP the call targeted ("target"); empty when not applicable.
    pub target: String,
    /// Human-readable, value-free description of the action.
    pub action: String,
    /// Names (never values) of secrets referenced by the call.
    pub secret_names: Vec<String>,
    /// "success" or "failure".
    pub outcome: String,
    /// Hash of the previous entry, linking the chain.
    pub prev_hash: String,
    /// SHA-256 over this entry's fields plus `prev_hash`.
    pub hash: String,
}

/// Compute the chained hash for an entry's fields. Pure and I/O-free so the
/// writer and `verify_chain` share identical logic.
#[allow(clippy::too_many_arguments)]
fn compute_hash(
    prev_hash: &str,
    seq: u64,
    timestamp_ms: u128,
    actor: &str,
    tool: &str,
    target: &str,
    action: &str,
    secret_names: &[String],
    outcome: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(SEP);
    hasher.update(seq.to_le_bytes());
    hasher.update(SEP);
    hasher.update(timestamp_ms.to_le_bytes());
    hasher.update(SEP);
    hasher.update(actor.as_bytes());
    hasher.update(SEP);
    hasher.update(tool.as_bytes());
    hasher.update(SEP);
    hasher.update(target.as_bytes());
    hasher.update(SEP);
    hasher.update(action.as_bytes());
    hasher.update(SEP);
    for name in secret_names {
        hasher.update(name.as_bytes());
        hasher.update(SEP);
    }
    hasher.update(outcome.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Mutable chain state guarded behind a single lock so concurrent records stay
/// correctly ordered and chained.
struct ChainState {
    last_hash: String,
    next_seq: u64,
}

/// An append-only, hash-chained audit log persisted as JSON lines.
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<ChainState>,
}

impl AuditLog {
    /// Open (or prepare to create) the audit log at `path`.
    ///
    /// Any existing log is read so new entries continue the chain from the last
    /// recorded hash and sequence number. A genuinely missing file starts a
    /// fresh chain from [`GENESIS_HASH`].
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| "Failed to create audit log directory".to_string())?;
        }

        let entries = read_entries(&path)?;
        let (last_hash, next_seq) = match entries.last() {
            Some(last) => (last.hash.clone(), last.seq + 1),
            None => (GENESIS_HASH.to_string(), 0),
        };

        Ok(AuditLog {
            path,
            state: Mutex::new(ChainState {
                last_hash,
                next_seq,
            }),
        })
    }

    /// Append one record describing a tool call. Returns the entry that was
    /// written so callers can log it if desired.
    ///
    /// `secret_names` must contain only secret *names*; values must never be
    /// passed here.
    pub fn record(
        &self,
        tool: &str,
        target: &str,
        action: &str,
        secret_names: &[String],
        success: bool,
    ) -> Result<AuditEntry> {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let actor = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let outcome = if success { "success" } else { "failure" };

        let mut state = self
            .state
            .lock()
            .map_err(|e| anyhow::anyhow!("Audit log lock poisoned: {}", e))?;

        let hash = compute_hash(
            &state.last_hash,
            state.next_seq,
            timestamp_ms,
            &actor,
            tool,
            target,
            action,
            secret_names,
            outcome,
        );

        let entry = AuditEntry {
            seq: state.next_seq,
            timestamp_ms,
            actor,
            tool: tool.to_string(),
            target: target.to_string(),
            action: action.to_string(),
            secret_names: secret_names.to_vec(),
            outcome: outcome.to_string(),
            prev_hash: state.last_hash.clone(),
            hash: hash.clone(),
        };

        let line = serde_json::to_string(&entry).context("Failed to serialize audit entry")?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| "Failed to open audit log for appending".to_string())?;
        writeln!(file, "{}", line).context("Failed to append to audit log")?;

        state.last_hash = hash;
        state.next_seq += 1;

        Ok(entry)
    }
}

/// Read and parse every entry from a JSON-lines audit log. A missing file
/// yields an empty vector; a present-but-unparseable line is a hard error so
/// corruption surfaces rather than being silently skipped.
pub fn read_entries<P: AsRef<Path>>(path: P) -> Result<Vec<AuditEntry>> {
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("Failed to read audit log"),
    };

    let mut entries = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line)
            .with_context(|| format!("Failed to parse audit log line {}", i + 1))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Verify the integrity of a chain of entries.
///
/// Checks that sequence numbers are contiguous from 0, that each entry's
/// `prev_hash` matches the prior entry's hash, and that each recomputed hash
/// matches the stored one. Returns the number of verified entries on success,
/// or a description of the first break on failure.
pub fn verify_chain(entries: &[AuditEntry]) -> std::result::Result<usize, String> {
    let mut prev_hash = GENESIS_HASH.to_string();
    for (i, e) in entries.iter().enumerate() {
        let expected_seq = i as u64;
        if e.seq != expected_seq {
            return Err(format!(
                "entry {} has seq {} but expected {}",
                i, e.seq, expected_seq
            ));
        }
        if e.prev_hash != prev_hash {
            return Err(format!(
                "entry {} (seq {}) prev_hash does not match the previous entry's hash — log was reordered or an entry was removed",
                i, e.seq
            ));
        }
        let recomputed = compute_hash(
            &e.prev_hash,
            e.seq,
            e.timestamp_ms,
            &e.actor,
            &e.tool,
            &e.target,
            &e.action,
            &e.secret_names,
            &e.outcome,
        );
        if recomputed != e.hash {
            return Err(format!(
                "entry {} (seq {}) hash mismatch — its contents were tampered with",
                i, e.seq
            ));
        }
        prev_hash = e.hash.clone();
    }
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64, prev: &str) -> AuditEntry {
        let hash = compute_hash(
            prev,
            seq,
            1000 + seq as u128,
            "alice",
            "run_command",
            "prod",
            "run_command: uptime",
            &[],
            "success",
        );
        AuditEntry {
            seq,
            timestamp_ms: 1000 + seq as u128,
            actor: "alice".to_string(),
            tool: "run_command".to_string(),
            target: "prod".to_string(),
            action: "run_command: uptime".to_string(),
            secret_names: vec![],
            outcome: "success".to_string(),
            prev_hash: prev.to_string(),
            hash,
        }
    }

    fn valid_chain(n: u64) -> Vec<AuditEntry> {
        let mut prev = GENESIS_HASH.to_string();
        let mut out = Vec::new();
        for seq in 0..n {
            let e = entry(seq, &prev);
            prev = e.hash.clone();
            out.push(e);
        }
        out
    }

    #[test]
    fn empty_chain_verifies() {
        assert_eq!(verify_chain(&[]).unwrap(), 0);
    }

    #[test]
    fn well_formed_chain_verifies() {
        let chain = valid_chain(3);
        assert_eq!(verify_chain(&chain).unwrap(), 3);
    }

    #[test]
    fn editing_an_entry_breaks_the_chain() {
        let mut chain = valid_chain(3);
        // Tamper with the action but leave the stored hash alone.
        chain[1].action = "run_command: rm -rf /".to_string();
        assert!(verify_chain(&chain).is_err());
    }

    #[test]
    fn removing_an_entry_breaks_the_chain() {
        let mut chain = valid_chain(3);
        chain.remove(1);
        // Sequence numbers are now 0,2 — the gap is detected.
        assert!(verify_chain(&chain).is_err());
    }

    #[test]
    fn reordering_entries_breaks_the_chain() {
        let mut chain = valid_chain(3);
        chain.swap(1, 2);
        assert!(verify_chain(&chain).is_err());
    }

    /// Build a unique temp path without external crates.
    fn temp_log_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("mcp_deploy_audit_{}_{}.log", tag, nanos))
    }

    #[test]
    fn writes_append_and_reopen_continues_the_chain() {
        let path = temp_log_path("roundtrip");
        {
            let log = AuditLog::open(&path).unwrap();
            log.record("run_command", "prod", "run_command: uptime", &[], true)
                .unwrap();
            log.record(
                "deploy_secret_to_server",
                "prod",
                "deploy_secret_to_server (apply): env_key=STRIPE_KEY",
                &["StripeProdKey".to_string()],
                true,
            )
            .unwrap();
        }
        // Reopen and append more — the chain must continue from disk state.
        {
            let log = AuditLog::open(&path).unwrap();
            log.record(
                "read_remote_file",
                "prod",
                "read_remote_file: /etc/hosts",
                &[],
                false,
            )
            .unwrap();
        }

        let entries = read_entries(&path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].seq, 2);
        assert_eq!(entries[2].outcome, "failure");
        // Secret name is recorded; the value never appears anywhere.
        assert_eq!(entries[1].secret_names, vec!["StripeProdKey".to_string()]);
        assert_eq!(verify_chain(&entries).unwrap(), 3);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn tampering_with_the_written_file_is_detected() {
        let path = temp_log_path("tamper");
        {
            let log = AuditLog::open(&path).unwrap();
            log.record("run_command", "prod", "run_command: uptime", &[], true)
                .unwrap();
            log.record("run_command", "prod", "run_command: whoami", &[], true)
                .unwrap();
        }

        // Rewrite the first line's action without recomputing its hash.
        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        lines[0] = lines[0].replace("uptime", "rm -rf /");
        fs::write(&path, lines.join("\n")).unwrap();

        let entries = read_entries(&path).unwrap();
        assert!(verify_chain(&entries).is_err());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn secret_names_are_hashed_but_never_values() {
        // The action/secret_names carry names only; this test documents that the
        // hash binds the recorded names so they cannot be altered undetected.
        let h1 = compute_hash(
            GENESIS_HASH,
            0,
            1,
            "a",
            "deploy_secret_to_server",
            "prod",
            "deploy",
            &["StripeKey".to_string()],
            "success",
        );
        let h2 = compute_hash(
            GENESIS_HASH,
            0,
            1,
            "a",
            "deploy_secret_to_server",
            "prod",
            "deploy",
            &["OtherKey".to_string()],
            "success",
        );
        assert_ne!(h1, h2);
    }
}
