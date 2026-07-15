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
/// different gcloud "configuration"/account, an unpinned `--project`, or a
/// caller-chosen local write destination such as `compute instances export
/// --destination=<path>`). Denied anywhere in argv regardless of subcommand.
/// Matched against the flag *name* (the portion of the argument before `=`),
/// so `--account=x` is caught without falsely flagging unrelated flags.
/// `--project` is caller-supplied-only forbidden here; the server injects
/// its own `--project=<configured>` in `gcloud::build_gcloud_argv` after
/// this validation passes.
const DENY_FLAGS: &[&str] = &[
    "--account",
    "--configuration",
    "--impersonate-service-account",
    "--key-file",
    "--credential-file-override",
    "--project",
    "--destination",
];

/// Per-resource-group verb allow-lists (the third argv token). The resource
/// group alone is not a sufficient boundary: several verbs available under
/// an otherwise in-scope group are far more privileged than plain instance
/// lifecycle management and are excluded even though the group is listed,
/// most importantly:
/// - `compute instances add-metadata` / `remove-metadata` / `update`, which
///   let the caller inject an SSH key or startup-script into ANY existing
///   instance in the project (not just ones behind this tool), bypassing the
///   SSH IP/alias whitelist entirely.
/// - `compute instances export` / `import`, which read/write an
///   attacker-chosen local file path.
/// - any mutating verb on `firewall-rules`/`networks` (e.g. `create
///   --allow=tcp:22 --source-ranges=0.0.0.0/0`), which can expose any
///   instance in the project to the public internet; these two groups are
///   confined to read-only inspection.
const ALLOWED_VERBS: &[(&str, &str, &[&str])] = &[
    (
        "compute",
        "instances",
        &[
            "list",
            "describe",
            "start",
            "stop",
            "reset",
            "delete",
            "create",
            "set-machine-type",
        ],
    ),
    (
        "compute",
        "disks",
        &["list", "describe", "create", "delete", "resize"],
    ),
    ("compute", "firewall-rules", &["list", "describe"]),
    (
        "compute",
        "snapshots",
        &["list", "describe", "create", "delete"],
    ),
    ("compute", "images", &["list", "describe"]),
    ("compute", "networks", &["list", "describe"]),
];

/// Returns the flag *name* portion of an argv element: everything before an
/// `=`, e.g. `--metadata-from-file=leak=/tmp/x` -> `--metadata-from-file`.
/// Positional (non-flag) arguments are returned unchanged, which is safe
/// since callers only compare the result against `--`-prefixed names.
fn flag_name(arg: &str) -> &str {
    arg.split('=').next().unwrap_or(arg)
}

/// Returns whether `name` (already lowercased, flag-name-only) loads content
/// from an arbitrary local file path. gcloud exposes many such flags
/// (`--metadata-from-file`, `--flags-file`, per-resource `*-from-file`
/// variants, …) and enumerating every one by name would always be
/// incomplete, so the whole class is denied: any of them can be used to read
/// a local secret file's bytes into a resource (e.g. instance metadata) that
/// a subsequent allowed `describe`/`list` call then echoes back through the
/// (pattern-only-scrubbed) tool result, defeating the "secrets are never
/// exposed to the agent" model the same way reading `~/.ssh/id_rsa` would on
/// the SSH path.
fn is_local_file_flag(name: &str) -> bool {
    name.ends_with("-file") || name.contains("-from-file")
}

/// Validates a `gcloud` argv before it is executed locally.
///
/// Three layers of protection, mirroring `command_guard::validate_command`
/// but operating on a structured argv (not a shell string), which sidesteps
/// shell injection entirely:
/// 1. A denylist that always blocks credential-affecting subcommands
///    (`auth`, `iam`, `billing`, `projects`, `kms`, `secrets`,
///    `resource-manager`, `organizations`, `config`), identity/project
///    pivoting flags (`--account`, `--impersonate-service-account`,
///    `--project`, etc.), and any flag that reads from or writes to an
///    arbitrary local file path (`--metadata-from-file`, `--flags-file`,
///    `--destination`, …) — regardless of the allow-list.
/// 2. A fail-closed allow-list on the resource group (first two tokens):
///    only `compute instances|disks|firewall-rules|snapshots|images|networks`.
/// 3. A fail-closed allow-list on the *verb* (third token) within that
///    group, since the group alone is not a sufficient boundary — see
///    [`ALLOWED_VERBS`].
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

    // Layer 1b: deny identity/project-pivoting flags and local-file-reading
    // flags anywhere in argv.
    for arg in args {
        let lowered = arg.to_lowercase();
        let name = flag_name(&lowered);
        if DENY_FLAGS.contains(&name) {
            return Err(anyhow!(
                "Security Error: the '{}' flag is not permitted because it can \
                 pivot off the pinned service-account identity or project.",
                name
            ));
        }
        if is_local_file_flag(name) {
            return Err(anyhow!(
                "Security Error: the '{}' flag is not permitted because it reads \
                 from or writes to an arbitrary local file path, which could leak \
                 local secrets or write untrusted data to disk.",
                name
            ));
        }
    }

    // Layer 2/3: fail-closed allow-list on resource group AND verb.
    if args.len() < 3 {
        return Err(anyhow!(
            "Security Error: gcloud command must specify a resource group and a verb \
             (e.g. 'compute instances list')."
        ));
    }
    let group1 = args[1].to_lowercase();
    let verb = args[2].to_lowercase();
    let allowed = ALLOWED_VERBS
        .iter()
        .find(|(a, b, _)| first == *a && group1 == *b)
        .map(|(_, _, verbs)| verbs.contains(&verb.as_str()))
        .unwrap_or(false);
    if !allowed {
        return Err(anyhow!(
            "Security Error: gcloud command is not in the allowed resource-group/verb \
             list. Permitted: compute instances {{list,describe,start,stop,reset,delete,\
             create,set-machine-type}}; compute disks {{list,describe,create,delete,resize}}; \
             compute firewall-rules|images|networks {{list,describe}}; compute snapshots \
             {{list,describe,create,delete}}."
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
            "list",
            "start",
            "stop",
            "reset",
            "create",
            "delete",
            "describe",
            "set-machine-type",
        ] {
            assert!(
                validate_gcloud_args(&args(&["compute", "instances", verb])).is_ok(),
                "expected 'compute instances {}' to be allowed",
                verb
            );
        }
    }

    #[test]
    fn test_allows_other_compute_resource_groups_read_only_verbs() {
        assert!(validate_gcloud_args(&args(&["compute", "disks", "list"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "firewall-rules", "list"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "snapshots", "list"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "images", "list"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "networks", "list"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "disks", "resize", "d1"])).is_ok());
        assert!(validate_gcloud_args(&args(&["compute", "snapshots", "delete", "s1"])).is_ok());
    }

    #[test]
    fn test_denies_metadata_mutation_verbs_on_instances() {
        // add-metadata/remove-metadata/update let a caller inject an SSH key
        // or startup-script into ANY existing instance in the project,
        // bypassing the SSH IP/alias whitelist entirely — must stay denied
        // even though 'compute instances' is otherwise an allowed group.
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "add-metadata",
                "victim-vm",
                "--metadata=ssh-keys=attacker:ssh-rsa AAAA"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "remove-metadata",
                "victim-vm"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&["compute", "instances", "update", "victim-vm"])).is_err()
        );
    }

    #[test]
    fn test_denies_export_import_verbs_on_instances() {
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "export",
                "my-vm",
                "--destination=/tmp/out.yaml"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "import",
                "my-vm",
                "--source=/tmp/in.yaml"
            ]))
            .is_err()
        );
    }

    #[test]
    fn test_denies_mutating_verbs_on_firewall_rules_and_networks() {
        // Read-only inspection is permitted; creating/updating/deleting
        // firewall rules or networks could expose any instance in the
        // project to the public internet and must stay denied.
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "firewall-rules",
                "create",
                "allow-ssh",
                "--allow=tcp:22",
                "--source-ranges=0.0.0.0/0"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&["compute", "firewall-rules", "update", "allow-ssh"]))
                .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&["compute", "firewall-rules", "delete", "allow-ssh"]))
                .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&["compute", "networks", "create", "evil-net"])).is_err()
        );
    }

    #[test]
    fn test_denies_local_file_reading_flags_even_on_allowed_verb() {
        // The primary secret-exfiltration vector: read an arbitrary local
        // file's bytes into instance metadata at creation time, then read
        // them back via an otherwise-allowed 'describe' call.
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "create",
                "new-vm",
                "--metadata-from-file=leak=/Users/someone/.remote_connections/mcp_secrets.json"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--flags-file=/tmp/flags.yaml"
            ]))
            .is_err()
        );
    }

    #[test]
    fn test_allows_inline_metadata_on_create_but_not_mutation_verbs() {
        // Setting metadata as part of creating a NEW instance (the agent's
        // own resource) is normal instance-management usage and stays
        // allowed; only mutating an EXISTING instance's metadata via
        // add-metadata/remove-metadata/update is denied (see above).
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "create",
                "new-vm",
                "--metadata=startup-script=echo hi"
            ]))
            .is_ok()
        );
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
        assert!(validate_gcloud_args(&args(&["compute", "instances"])).is_err());
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
