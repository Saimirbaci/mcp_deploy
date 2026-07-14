# PI Core — progress

## Core memory
[pi_core working memory — carry this forward]
Deliverables to satisfy:
  - Resend service definitions in config
  - Bearer auth integration in call_service_api
  - README documentation
  - E2E test suite for endpoints
Files changed so far: sample_config.json, src/http.rs, src/mcp.rs, src/config.rs, README.md
Files already read: .pi_core/plan.md, src/config.rs, src/http.rs, sample_config.json, README.md, src/mcp.rs
Guidance: do NOT re-write a file that already has the intended content, and do not re-read your own writes to 'check' them. Work the next unmet deliverable, verify with the build/test command, and call submit_work once all deliverables pass.

## Narrative (summarized history)
[earlier progress — summarized, may be lossy]
- **Files created/modified:** None in this window; the agent only read `src/http.rs` and `README.md` to match existing patterns for pending work.
- **Key discoveries:** The config definitively contains `resend` and `resend_admin` service definitions with bearer auth, backed by `keychain`.
- **Key discoveries:** `src/http.rs` handles outbound service calls, applies auth via `auth_application` (Header, Query), and redacts injected secrets from response bodies.
- **Key discoveries:** README.md already documents the secret injection and redaction mechanisms based on `bearer`, `header`, or `query` auth schemes.
- **Key discoveries:** Steps 1-4 (config entries, bearer auth, path/method allowlists, idempotency-key passthrough allowlist) are fully implemented on disk.
- **Decisions made:** Dismissed a system reminder claiming "Resend service definitions" was unmet, as direct verification proved it was stale.
- **Decisions made:** Ceased further codebase exploration immediately due to a budget notice warning that ~70% of the iteration budget was used.
- **Decisions made:** Decided to focus solely on producing the two remaining deliverables: an E2E test suite and README documentation updates.
- **Errors hit:** A stale reminder indicated an incomplete task, but this was resolved by reading the config and verifying the service definitions were already present.
- **Work pending:** Create the E2E test suite.
- **Work pending:** Complete the README documentation updates.
- **Work pending:** Call `submit_work` once the deliverables are met.
- **Key Discovery**: `sample_config.json` already contains `resend` and `resend_admin` service definitions (bearer auth, correct secret names) at lines 46-57.
- **Key Discovery**: `src/config.rs` contains tests for Resend configuration around lines 572-573.
- **Key Discovery**: The README Resend section is currently outdated, referencing a single `ResendKey` and a wrong auth format.
- **Key Discovery**: The README Cloudflare section includes token permission recommendations (Cache Purge, Read, Firewall Services) and global API key hardening advice.
- **Action Taken**: Read `README.md` (offset 205) to locate the end of the Cloudflare configuration section.
- **Action Taken**: Read `sample_config.json` (offset 40) to retrieve exact Resend config entries to align README updates.
- **Action Taken**: Ran a grep for "resend" in `.rs` files to find existing test patterns.
- **Decision Made**: Dismissed a stale reminder regarding missing Resend config entries, as their existence was verified multiple times on disk.
- **Decision Made**: Prioritized the genuinely pending deliverables: the E2E test suite (Step 5) followed by the README update (Step 6).
- **Work Pending**: Write/update the E2E test suite.
- **Work Pending**: Update the README Resend section to reflect the correct bearer auth format and existing `sample_config.json` entries.
- **Files modified:** 
  - `src/http.rs`: Added a new test `call_service_rejects_non_allowlisted_service` that verifies non-allowlisted services are rejected before any network or vault access is attempted.
- **Key discoveries about the codebase:**
  - `src/config.rs` contains test patterns like `test_services_block_parses_each_auth_scheme` which parse JSON configurations for services such as Cloudflare.
  - The `Config` struct is instantiated with `servers` (HashMap), `services`, and a `secret_backend`.
  - The `call_service` function in `src/http.rs` handles service routing and can error out (e.g., rejecting a "confined" service), returning results that can be tested with `unwrap_err()`.
  - Service configurations include fields like `base_url`, `auth` (e.g., `AuthScheme::Bearer`), `secret_name`, and `allowed_methods`.
- **Decisions made:**
  - Proceeded to write the E2E test suite directly, matching existing Cloudflare test patterns in the codebase.
- **Errors hit:**
  - Encountered repeated, stale system reminders about a missing Resend configuration. This was resolved by verifying the config existed on disk multiple times and safely ignoring the reminder.
- **Work still pending:**
  - Finish writing the E2E test suite (Step 5).
  - Write or update the README documentation (Step 6).
