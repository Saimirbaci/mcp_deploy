---
name: add-call-service-api-integration
description: Use when adding a new outbound HTTP service integration (like cloudflare, resend, resend_admin, openrouter) to be called via call_service_api. Applies when the task is "add support for managing <some SaaS API> via the MCP server" rather than SSH-based remote commands.
---

# Adding a new `call_service_api` service integration

This repo already has four services following one shape: `cloudflare`,
`resend`, `resend_admin`, `openrouter` (see `sample_config.json`). Adding a
fifth follows the same lockstep changes across five files — skipping any one
leaves either a security gap or a broken build.

## Steps

1. **`sample_config.json`** — add a `services.<name>` entry:
   `base_url`, `auth` (`bearer` / `header` / `query`), `secret_name` (the vault
   key name, never the value), `allowed_methods`, `allowed_path_prefixes`.
   Scope `allowed_path_prefixes` as tight as the credential's real capability
   (e.g. a provisioning key that can only manage keys/credits must never be
   allowlisted for `/chat/completions`-style inference paths, even if the
   upstream key happens to be able to call them).

2. **`src/config.rs`** — add a `#[cfg(test)]` case parsing that service (auth
   scheme, secret_name, both allowlists) and a second test asserting
   `sample_config.json` itself loads the entry and that `allowed_services()`
   exposes only `(name, base_url)` — never `secret_name` — for that service.

3. **`src/http.rs`** — add a test-only builder (mirror `resend_admin_service()`
   / `openrouter_service()`) and two test groups:
   - `validate_path_allowed`/`validate_method_allowed` cases: every intended
     prefix/method allowed, plus the out-of-scope surface (traversal,
     near-miss prefixes like `/keys2`, disallowed methods) rejected.
   - A `call_service` end-to-end test proving an out-of-allowlist path is
     rejected **before** any vault/secret access — the rejection error must
     mention "not within an allowed path prefix" (or the method equivalent),
     confirming fail-closed ordering.

4. **`src/scrubber.rs`** — if the service's API keys have a distinctive shape
   (e.g. `sk-or-v1-<hex>`), add a regex to `PATTERNS` plus two tests: the
   literal key gets redacted, and a near-miss (bare prefix without the full
   shape, e.g. mentioned in docs/catalog text) does NOT get redacted.

5. **`README.md`** — document the service section: config snippet, where to
   mint/store the credential (`mcp_deploy secret add <SecretName>`), the
   `call_service` recipes (JSON request shapes) for the intended operations,
   and explicitly call out any capability the allowlist deliberately excludes
   and why (defense-in-depth vs. what the upstream credential could otherwise
   do).

## Pitfalls

- Don't rely on the upstream provider's own key scoping as the only boundary —
  the local `allowed_path_prefixes`/`allowed_methods` allowlist must
  independently enforce the intended boundary (see openrouter: the
  provisioning key technically can't call completions, but the allowlist
  still explicitly excludes that path as defense-in-depth).
- Test near-misses, not just positive/negative extremes — e.g. `/keys2` must
  still be rejected by a `/keys` prefix allowlist (exact segment boundary, not
  raw `starts_with`); a scrubber regex near-miss (bare prefix without the full
  key shape) must NOT be redacted.
