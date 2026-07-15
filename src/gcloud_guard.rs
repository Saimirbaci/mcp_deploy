use anyhow::{Result, anyhow};

/// First-token subcommand groups that are always denied, regardless of the
/// allow-list below. These would let the agent print/rotate credentials,
/// manage billing/IAM/projects, or repoint the pinned identity/project.
const DENY_FIRST_TOKENS: &[&str] = &[
    "auth",
    "iam",
    "billing",
    "projects",
    "kms",
    "secrets",
    "resource-manager",
    "organizations",
    "config",
];

/// Flags that could pivot off the pinned, pre-authenticated service-account
/// identity or project (impersonation, alternate credential files, a
/// different gcloud "configuration"/account, or an unpinned `--project`).
/// Denied anywhere in argv regardless of subcommand. Matched as an exact
/// token or a `--flag=value` prefix so `--account=x` is caught without
/// falsely flagging unrelated flags. `--project` is caller-supplied-only
/// forbidden here; the server injects its own `--project=<configured>` in
/// `gcloud::build_gcloud_argv` after this validation passes.
const DENY_FLAGS: &[&str] = &[
    "--account",
    "--configuration",
    "--impersonate-service-account",
    "--key-file",
    "--credential-file-override",
    "--project",
];

/// Resource-group prefixes (first two tokens) permitted by the allow-list.
/// Only Compute Engine resources in scope for instance/disk/network
/// management; everything else is refused fail-closed.
const ALLOWED_RESOURCE_GROUPS: &[[&str; 2]] = &[
    ["compute", "instances"],
    ["compute", "disks"],
    ["compute", "firewall-rules"],
    ["compute", "snapshots"],
    ["compute", "images"],
    ["compute", "networks"],
];

/// Returns whether `arg` is (or sets) the given long flag, matching both the
/// `--flag value` and `--flag=value` forms.
fn matches_flag(arg: &str, flag: &str) -> bool {
    arg == flag || arg.starts_with(&format!("{}=", flag))
}

/// Validates a `gcloud` argv before it is executed locally.
///
/// Two layers of protection, mirroring `command_guard::validate_command` but
/// operating on a structured argv (not a shell string), which sidesteps shell
/// injection entirely:
/// 1. A denylist that always blocks credential-affecting subcommands
///    (`auth`, `iam`, `billing`, `projects`, `kms`, `secrets`,
///    `resource-manager`, `organizations`, `config`) and identity-pivoting
///    flags (`--account`, `--impersonate-service-account`, etc.), regardless
///    of the allow-list.
/// 2. A fail-closed allow-list: the first two tokens must match one of the
///    permitted Compute Engine resource groups (instances, disks,
///    firewall-rules, snapshots, images, networks).
pub fn validate_gcloud_args(args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(anyhow!(
            "Security Error: empty gcloud command is not permitted"
        ));
    }

    // Layer 1a: deny credential/identity-affecting subcommands by first token.
    let first = args[0].to_lowercase();
    if DENY_FIRST_TOKENS.contains(&first.as_str()) {
        return Err(anyhow!(
            "Security Error: gcloud subcommand '{}' is not permitted. This tool is \
             pre-authenticated and scoped to Compute Engine resource management; \
             credential, IAM, billing, and project administration are blocked.",
            first
        ));
    }

    // Layer 1b: deny identity-pivoting flags anywhere in argv.
    for arg in args {
        let lowered = arg.to_lowercase();
        for flag in DENY_FLAGS {
            if matches_flag(&lowered, flag) {
                return Err(anyhow!(
                    "Security Error: the '{}' flag is not permitted because it can \
                     pivot off the pinned service-account identity.",
                    flag
                ));
            }
        }
    }

    // Layer 2: fail-closed allow-list on the first two tokens.
    if args.len() < 2
        || !ALLOWED_RESOURCE_GROUPS
            .iter()
            .any(|[a, b]| first == *a && args[1].to_lowercase() == *b)
    {
        return Err(anyhow!(
            "Security Error: gcloud command is not in the allowed resource-group \
             list. Permitted: compute instances|disks|firewall-rules|snapshots|images|networks."
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_allows_compute_instances_verbs() {
        for verb in [
            "list", "start", "stop", "reset", "create", "delete", "describe",
        ] {
            assert!(
                validate_gcloud_args(&args(&["compute", "instances", verb])).is_ok(),
                "expected 'compute instances {}' to be allowed",
                verb
            );
        }
    }

    #[test]
    fn test_allows_other_compute_resource_groups() {
        assert!(validate_gcloud_args(&args(&["compute", "disks", "list"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "firewall-rules", "list"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "snapshots", "list"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "images", "list"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "networks", "list"])).is_ok());
    }

    #[test]
    fn test_denies_iam_billing_projects_auth() {
        assert!(validate_gcloud_args(&args(&["iam", "service-accounts", "list"])).is_err());
        assert!(validate_gcloud_args(&args(&["billing", "accounts", "list"])).is_err());
        assert!(validate_gcloud_args(&args(&["auth", "print-access-token"])).is_err());
        assert!(validate_gcloud_args(&args(&["auth", "print-identity-token"])).is_err());
        assert!(validate_gcloud_args(&args(&["auth", "login"])).is_err());
        assert!(validate_gcloud_args(&args(&["auth", "revoke"])).is_err());
        assert!(validate_gcloud_args(&args(&["projects", "list"])).is_err());
        assert!(validate_gcloud_args(&args(&["kms", "keys", "list"])).is_err());
        assert!(validate_gcloud_args(&args(&["secrets", "list"])).is_err());
        assert!(
            validate_gcloud_args(&args(&["resource-manager", "org-policies", "list"])).is_err()
        );
        assert!(validate_gcloud_args(&args(&["organizations", "list"])).is_err());
        assert!(validate_gcloud_args(&args(&["config", "set", "project", "other"])).is_err());
    }

    #[test]
    fn test_denies_identity_pivoting_flags_even_on_allowed_subcommand() {
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "describe",
                "my-vm",
                "--account=other@x.iam.gserviceaccount.com"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--impersonate-service-account=x@y.iam.gserviceaccount.com"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--configuration=other"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--key-file=/tmp/key.json"
            ]))
            .is_err()
        );
    }

    #[test]
    fn test_denies_caller_supplied_project_flag_so_it_stays_pinned() {
        // The configured project_id must be the only project ever targeted;
        // a caller-supplied --project (even matching the real project) is
        // refused so pinning can never be bypassed by convention alone.
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--project=other-project"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--project=my-project"
            ]))
            .is_err()
        );
    }

    #[test]
    fn test_denies_resource_group_outside_allowlist() {
        assert!(validate_gcloud_args(&args(&["compute", "routers", "list"])).is_err());
        assert!(validate_gcloud_args(&args(&["container", "clusters", "list"])).is_err());
        assert!(validate_gcloud_args(&args(&["storage", "ls"])).is_err());
        assert!(validate_gcloud_args(&args(&["compute"])).is_err());
    }

    #[test]
    fn test_benign_near_miss_resource_named_like_denylist_is_not_falsely_flagged() {
        // A resource literally named 'iam-server' passed as an argument value
        // (not the first token / a subcommand) must not be denied.
        assert!(
            validate_gcloud_args(&args(&["compute", "instances", "describe", "iam-server"]))
                .is_ok()
        );
    }

    #[test]
    fn test_empty_args_rejected() {
        assert!(validate_gcloud_args(&[]).is_err());
    }

    #[test]
    fn test_denylist_checked_before_allowlist_ordering_does_not_bypass() {
        // Even though 'auth' fails the allow-list too, this test documents
        // that the specific, actionable denylist error fires first.
        let err = validate_gcloud_args(&args(&["auth", "print-access-token"])).unwrap_err();
        assert!(err.to_string().contains("is not permitted"));
    }
}
