use crate::config::{AuthScheme, Config, SecretStore, ServiceInfo};
use anyhow::{Context, Result, anyhow};
use std::time::Duration;

/// The outcome of an outbound service call: the HTTP status code plus the
/// response body. The body has already had the injected secret redacted out of
/// it, so it is safe to return to the agent. The status lets the dispatcher
/// decide whether to flag the result as an error (non-2xx).
#[derive(Debug)]
pub struct ServiceResponse {
    pub status: u16,
    pub body: String,
}

impl ServiceResponse {
    /// Whether the HTTP status is in the 2xx success range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// A status line + body suitable for returning to the agent.
    pub fn render(&self) -> String {
        format!("HTTP {}\n{}", self.status, self.body)
    }
}

/// How an authentication scheme is applied to a request, computed without any
/// network or I/O so it can be unit-tested directly.
#[derive(Debug, PartialEq)]
enum AuthApplication {
    /// Add a request header `name: value`.
    Header(String, String),
    /// Add a query-string parameter `name=value`.
    Query(String, String),
}

/// Join a service base URL with a request path, normalizing slashes so exactly
/// one separates them regardless of trailing/leading slashes on either side.
fn build_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base, path)
    }
}

/// Map a textual HTTP method onto a `reqwest::Method`, failing closed on any
/// verb outside the allowed read/write set.
fn parse_method(method: &str) -> Result<reqwest::Method> {
    match method.to_ascii_uppercase().as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PUT" => Ok(reqwest::Method::PUT),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "DELETE" => Ok(reqwest::Method::DELETE),
        other => Err(anyhow!(
            "HTTP method '{}' is not allowed (use GET, POST, PUT, PATCH, or DELETE)",
            other
        )),
    }
}

/// Enforce a service's optional per-method allowlist (fail-closed). When the
/// service declares a non-empty `allowed_methods`, the request method must match
/// one of them (case-insensitive); otherwise any globally-permitted verb is
/// allowed. This is the HTTP analogue of SSH's `allowed_command_prefixes`.
fn validate_method_allowed(service: &ServiceInfo, method: &str) -> Result<()> {
    if let Some(allowed) = &service.allowed_methods
        && !allowed.is_empty()
    {
        let m = method.to_ascii_uppercase();
        let ok = allowed.iter().any(|a| a.to_ascii_uppercase() == m);
        if !ok {
            return Err(anyhow!(
                "HTTP method '{}' is not permitted for this service (allowed: {:?})",
                m,
                allowed
            ));
        }
    }
    Ok(())
}

/// Enforce path confinement (fail-closed). Always rejects `..` traversal
/// segments so a caller cannot climb out of the intended API prefix. When the
/// service declares a non-empty `allowed_path_prefixes`, the request path must
/// start with one of them (leading slashes normalized on both sides).
fn validate_path_allowed(service: &ServiceInfo, path: &str) -> Result<()> {
    // Reject path traversal regardless of whether a prefix allowlist is set:
    // `..` segments let the caller escape the configured base path.
    if path.split('/').any(|seg| seg == "..") {
        return Err(anyhow!("Request path must not contain '..' segments"));
    }

    if let Some(prefixes) = &service.allowed_path_prefixes
        && !prefixes.is_empty()
    {
        let normalized = normalize_leading_slash(path);
        let ok = prefixes
            .iter()
            .any(|p| normalized.starts_with(&normalize_leading_slash(p)));
        if !ok {
            return Err(anyhow!(
                "Request path '{}' is not within an allowed path prefix for this service",
                path
            ));
        }
    }
    Ok(())
}

/// Ensure a path/prefix string starts with exactly one leading slash so prefix
/// comparison is not thrown off by a missing or doubled separator.
fn normalize_leading_slash(s: &str) -> String {
    format!("/{}", s.trim_start_matches('/'))
}

/// Compute how the credential is applied for a given auth scheme. Pure: takes
/// the scheme and secret value and returns the header/query modification to make.
fn auth_application(scheme: &AuthScheme, secret: &str) -> AuthApplication {
    match scheme {
        AuthScheme::Bearer => {
            AuthApplication::Header("Authorization".to_string(), format!("Bearer {}", secret))
        }
        AuthScheme::Header { name } => AuthApplication::Header(name.clone(), secret.to_string()),
        AuthScheme::Query { name } => AuthApplication::Query(name.clone(), secret.to_string()),
    }
}

/// Replace every occurrence of the injected secret in `text` with a redaction
/// placeholder so the credential can never reach the agent or chat history,
/// even if the upstream API echoes it back in an error body.
fn redact_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "[REDACTED]")
}

/// Turn a `reqwest::Error` into a safe, secret-free message. The error's
/// Display embeds the request URL, which for the Query auth scheme contains the
/// credential; `without_url()` strips it and `redact_secret` removes any residual
/// occurrence as belt-and-suspenders.
fn sanitize_request_error(err: reqwest::Error, secret: &str) -> String {
    redact_secret(&err.without_url().to_string(), secret)
}

/// Convert a caller-supplied JSON object of query parameters into string pairs.
/// Non-string scalar values are stringified; nested arrays/objects are skipped.
fn query_pairs(query: Option<&serde_json::Value>) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    if let Some(serde_json::Value::Object(map)) = query {
        for (k, v) in map {
            let value = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => continue,
                other if other.is_array() || other.is_object() => continue,
                other => other.to_string(),
            };
            pairs.push((k.clone(), value));
        }
    }
    pairs
}

/// Header names a caller is allowed to supply on a service call. This is an
/// explicit allowlist (rather than passing anything through) so the agent can
/// never override the injected `Authorization`/credential header or inject
/// low-level transport headers (`Host`, `Content-Length`, …). Idempotency keys
/// and Resend's `Idempotency-Key` are the main use case. Matching is
/// case-insensitive.
const ALLOWED_CALLER_HEADERS: &[&str] = &["x-idempotency-key", "idempotency-key"];

/// Convert a caller-supplied JSON object of header overrides into (name,
/// value) string pairs, restricted to the safe allowlist above. Non-string
/// scalars are stringified; nested arrays/objects are skipped. The original
/// header name casing from the caller is preserved on the wire.
fn caller_headers(headers: Option<&serde_json::Value>) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    if let Some(serde_json::Value::Object(map)) = headers {
        for (k, v) in map {
            if !ALLOWED_CALLER_HEADERS
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(k))
            {
                continue;
            }
            let value = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => continue,
                other if other.is_array() || other.is_object() => continue,
                other => other.to_string(),
            };
            pairs.push((k.clone(), value));
        }
    }
    pairs
}

/// Resolve the default vault path (`$HOME/.remote_connections/mcp_secrets.json`).
fn default_secrets_path() -> Result<String> {
    let home = std::env::var("HOME").context("Could not find HOME environment variable")?;
    Ok(format!("{}/.remote_connections/mcp_secrets.json", home))
}

/// Drive an authenticated HTTP API on behalf of the agent.
///
/// Mirrors the SSH execution layer's resolve → authorize → execute shape:
/// 1. Resolve the service from config (reject if not allow-listed).
/// 2. Load the credential value from the local vault by `secret_name`.
/// 3. Build the request URL/method, apply the auth scheme and any static extras
///    plus caller-supplied query params, and serialize the body for writes.
/// 4. Send via a blocking client and return the status + body.
///
/// The secret value never appears in the returned body (it is redacted) and is
/// never logged.
pub fn call_service(
    service_name: &str,
    method: &str,
    path: &str,
    query: Option<&serde_json::Value>,
    headers: Option<&serde_json::Value>,
    body: Option<&serde_json::Value>,
    config: &Config,
) -> Result<ServiceResponse> {
    let service = config.get_service(service_name).ok_or_else(|| {
        anyhow!(
            "Service {} is not in the allowed services list",
            service_name
        )
    })?;

    // Authorize the request BEFORE loading the credential: validate the verb
    // against the global set and the service's per-method/per-path allowlists
    // (fail-closed), analogous to SSH's allowed_command_prefixes and the DB
    // read-only guard. Failing fast here also avoids any keychain access for a
    // request that would be rejected anyway.
    let http_method = parse_method(method)?;
    validate_method_allowed(service, method)?;
    validate_path_allowed(service, path)?;
    let url = build_url(&service.base_url, path);

    // Load the credential value from the local vault. Never include the value in
    // any error message.
    let secrets_path = default_secrets_path()?;
    let secrets = SecretStore::load(config.secret_backend(), &secrets_path)
        .with_context(|| format!("Failed to load secret vault from {}", secrets_path))?;
    let secret = secrets.get(&service.secret_name).ok_or_else(|| {
        anyhow!(
            "Secret '{}' for service '{}' was not found in the local vault",
            service.secret_name,
            service_name
        )
    })?;

    // Do NOT follow redirects. reqwest strips Authorization/Cookie on cross-host
    // redirects but NOT custom headers (e.g. an `X-Api-Key` auth scheme) and not
    // query-string credentials, so an open redirect on the allow-listed host
    // could exfiltrate the injected secret to an attacker origin. A 3xx is
    // surfaced to the agent as a normal status instead.
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")?;

    let mut request = client.request(http_method.clone(), &url);

    // Static extra headers from the service config (never secret values).
    if let Some(extra) = &service.extra {
        for (name, value) in extra {
            request = request.header(name.as_str(), value.as_str());
        }
    }

    // Caller-supplied query parameters.
    let caller_query = query_pairs(query);
    if !caller_query.is_empty() {
        request = request.query(&caller_query);
    }

    // Caller-supplied headers, restricted to a safe allowlist so the injected
    // credential cannot be overridden (e.g. `X-Idempotency-Key` for Resend sends).
    for (name, value) in caller_headers(headers) {
        request = request.header(name.as_str(), value.as_str());
    }

    // Apply the credential per the configured auth scheme.
    match auth_application(&service.auth, &secret) {
        AuthApplication::Header(name, value) => {
            request = request.header(name.as_str(), value.as_str());
        }
        AuthApplication::Query(name, value) => {
            request = request.query(&[(name, value)]);
        }
    }

    // Serialize the body for write methods. A JSON string is sent as a raw body;
    // any other JSON value is sent as a JSON document.
    if let Some(body) = body {
        match body {
            serde_json::Value::Null => {}
            serde_json::Value::String(s) => {
                request = request.body(s.clone());
            }
            other => {
                request = request.json(other);
            }
        }
    }

    // CRITICAL: a reqwest error's Display includes the full request URL — for the
    // Query auth scheme that URL carries `?<name>=<secret>`. Strip the URL with
    // `without_url()` AND redact the secret value as defense-in-depth so the
    // credential can never reach the error string returned to the agent or logs.
    let response = match request.send() {
        Ok(r) => r,
        Err(e) => {
            let sanitized = sanitize_request_error(e, &secret);
            return Err(anyhow!(
                "Request to service '{}' failed: {}",
                service_name,
                sanitized
            ));
        }
    };

    let status = response.status().as_u16();
    let raw_body = match response.text() {
        Ok(b) => b,
        Err(e) => {
            let sanitized = sanitize_request_error(e, &secret);
            return Err(anyhow!(
                "Failed to read response body from service '{}': {}",
                service_name,
                sanitized
            ));
        }
    };

    // Redact the injected secret out of the body before it can reach the agent.
    let body = redact_secret(&raw_body, &secret);

    Ok(ServiceResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthScheme, Config, ServiceInfo};
    use std::collections::HashMap;

    /// Build a ServiceInfo with optional method/path allowlists for guardrail tests.
    fn service_with_guards(
        allowed_methods: Option<Vec<&str>>,
        allowed_path_prefixes: Option<Vec<&str>>,
    ) -> ServiceInfo {
        ServiceInfo {
            base_url: "https://api.example.com/v1".to_string(),
            auth: AuthScheme::Bearer,
            secret_name: "Token".to_string(),
            extra: None,
            allowed_methods: allowed_methods
                .map(|v| v.into_iter().map(|s| s.to_string()).collect()),
            allowed_path_prefixes: allowed_path_prefixes
                .map(|v| v.into_iter().map(|s| s.to_string()).collect()),
        }
    }

    #[test]
    fn validate_method_allowed_enforces_allowlist_fail_closed() {
        // No allowlist → any globally-permitted verb is fine.
        let open = service_with_guards(None, None);
        assert!(validate_method_allowed(&open, "DELETE").is_ok());

        // Read-only service: only GET permitted (case-insensitive).
        let ro = service_with_guards(Some(vec!["GET"]), None);
        assert!(validate_method_allowed(&ro, "get").is_ok());
        assert!(validate_method_allowed(&ro, "POST").is_err());
        assert!(validate_method_allowed(&ro, "DELETE").is_err());
    }

    #[test]
    fn validate_path_allowed_rejects_traversal_and_enforces_prefix() {
        // `..` is rejected even with no prefix allowlist configured.
        let open = service_with_guards(None, None);
        assert!(validate_path_allowed(&open, "/zones/123").is_ok());
        assert!(validate_path_allowed(&open, "/zones/../../etc").is_err());

        // Prefix allowlist confines the agent (slash normalization on both sides).
        let confined = service_with_guards(None, Some(vec!["/zones"]));
        assert!(validate_path_allowed(&confined, "/zones/123/dns_records").is_ok());
        assert!(validate_path_allowed(&confined, "zones/123").is_ok());
        assert!(validate_path_allowed(&confined, "/user/tokens").is_err());
    }

    #[test]
    fn call_service_rejects_disallowed_method_before_vault_access() {
        // A read-only service must refuse a DELETE without touching the keychain
        // or the network (validation happens before secret load).
        let mut services = HashMap::new();
        services.insert(
            "ro".to_string(),
            service_with_guards(Some(vec!["GET"]), None),
        );
        let config = Config {
            servers: HashMap::new(),
            services,
            secret_backend: crate::config::SecretBackend::default(),
        };
        let err = call_service("ro", "DELETE", "/zones", None, None, None, &config).unwrap_err();
        assert!(err.to_string().contains("not permitted"));
    }

    /// Build a ServiceInfo shaped like the shipped cloudflare entry: bearer auth,
    /// full-lifecycle methods, and the /zones + /user/tokens/verify path allowlist.
    fn cloudflare_service() -> ServiceInfo {
        ServiceInfo {
            base_url: "https://api.cloudflare.com/client/v4".to_string(),
            auth: AuthScheme::Bearer,
            secret_name: "CloudflareToken".to_string(),
            extra: None,
            allowed_methods: Some(
                ["GET", "POST", "PUT", "PATCH", "DELETE"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            ),
            allowed_path_prefixes: Some(
                ["/zones", "/user/tokens/verify"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            ),
        }
    }

    #[test]
    fn cloudflare_guards_allow_dns_cache_waf_and_verify_paths() {
        let cf = cloudflare_service();

        // The full DNS/cache/WAF lifecycle surface lives under /zones, and the
        // token sanity check under /user/tokens/verify — all must be permitted.
        for path in [
            "/zones",
            "/zones/abc123",
            "/zones/abc123/dns_records",
            "/zones/abc123/dns_records/rec456",
            "/zones/abc123/purge_cache",
            "/zones/abc123/rulesets",
            "/zones/abc123/firewall/rules",
            "/user/tokens/verify",
        ] {
            assert!(
                validate_path_allowed(&cf, path).is_ok(),
                "expected {} to be allowed",
                path
            );
        }

        // Anything outside the confined surface is refused fail-closed, and a
        // traversal segment is rejected even though it textually starts with /zones.
        assert!(validate_path_allowed(&cf, "/accounts/abc/tokens").is_err());
        assert!(validate_path_allowed(&cf, "/zones/../accounts").is_err());

        // The full lifecycle of verbs is permitted (case-insensitive).
        for method in ["GET", "post", "Put", "PATCH", "delete"] {
            assert!(
                validate_method_allowed(&cf, method).is_ok(),
                "expected {} to be allowed",
                method
            );
        }
    }

    #[test]
    fn cloudflare_read_only_narrowing_rejects_writes() {
        // Operators wanting read-only access narrow allowed_methods to ["GET"];
        // verify that fail-closes against every write verb.
        let mut ro = cloudflare_service();
        ro.allowed_methods = Some(vec!["GET".to_string()]);

        assert!(validate_method_allowed(&ro, "GET").is_ok());
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(
                validate_method_allowed(&ro, method).is_err(),
                "expected {} to be rejected by a read-only cloudflare entry",
                method
            );
        }
    }

    #[test]
    fn call_service_rejects_cloudflare_path_outside_allowlist_before_vault_access() {
        // A request to a cloudflare path outside the /zones + verify allowlist must
        // be refused before any keychain access or network call.
        let mut services = HashMap::new();
        services.insert("cloudflare".to_string(), cloudflare_service());
        let config = Config {
            servers: HashMap::new(),
            services,
            secret_backend: crate::config::SecretBackend::default(),
        };
        let err =
            call_service("cloudflare", "GET", "/accounts/abc", None, None, None, &config).unwrap_err();
        assert!(
            err.to_string()
                .contains("not within an allowed path prefix")
        );
    }

    #[test]
    fn call_service_rejects_disallowed_path_before_vault_access() {
        let mut services = HashMap::new();
        services.insert(
            "confined".to_string(),
            service_with_guards(None, Some(vec!["/zones"])),
        );
        let config = Config {
            servers: HashMap::new(),
            services,
            secret_backend: crate::config::SecretBackend::default(),
        };
        let err = call_service("confined", "GET", "/user/tokens", None, None, None, &config).unwrap_err();
        assert!(
            err.to_string()
                .contains("not within an allowed path prefix")
        );
    }

    #[test]
    fn build_url_normalizes_slashes() {
        assert_eq!(
            build_url("https://api.example.com/v1", "/users"),
            "https://api.example.com/v1/users"
        );
        assert_eq!(
            build_url("https://api.example.com/v1/", "/users"),
            "https://api.example.com/v1/users"
        );
        assert_eq!(
            build_url("https://api.example.com/v1", "users"),
            "https://api.example.com/v1/users"
        );
        assert_eq!(
            build_url("https://api.example.com/v1/", "users"),
            "https://api.example.com/v1/users"
        );
        assert_eq!(
            build_url("https://api.example.com", ""),
            "https://api.example.com"
        );
    }

    #[test]
    fn parse_method_accepts_known_verbs_and_rejects_others() {
        assert_eq!(parse_method("get").unwrap(), reqwest::Method::GET);
        assert_eq!(parse_method("POST").unwrap(), reqwest::Method::POST);
        assert_eq!(parse_method("Patch").unwrap(), reqwest::Method::PATCH);
        assert!(parse_method("TRACE").is_err());
        assert!(parse_method("CONNECT").is_err());
    }

    #[test]
    fn auth_application_places_secret_per_scheme() {
        assert_eq!(
            auth_application(&AuthScheme::Bearer, "tok123"),
            AuthApplication::Header("Authorization".to_string(), "Bearer tok123".to_string())
        );
        assert_eq!(
            auth_application(
                &AuthScheme::Header {
                    name: "X-Api-Key".to_string()
                },
                "tok123"
            ),
            AuthApplication::Header("X-Api-Key".to_string(), "tok123".to_string())
        );
        assert_eq!(
            auth_application(
                &AuthScheme::Query {
                    name: "api_key".to_string()
                },
                "tok123"
            ),
            AuthApplication::Query("api_key".to_string(), "tok123".to_string())
        );
    }

    #[test]
    fn redact_secret_removes_value_and_keeps_near_miss() {
        let body = "token is sk_live_realsecret and ok";
        let redacted = redact_secret(body, "sk_live_realsecret");
        assert!(!redacted.contains("sk_live_realsecret"));
        assert!(redacted.contains("[REDACTED]"));
        // A benign near-miss (different value) is untouched.
        assert_eq!(
            redact_secret("sk_live_other value", "sk_live_realsecret"),
            "sk_live_other value"
        );
    }

    #[test]
    fn query_pairs_stringifies_scalars_and_skips_complex() {
        let q = serde_json::json!({
            "name": "abc",
            "count": 5,
            "flag": true,
            "nested": {"x": 1},
            "list": [1, 2],
            "skip": null
        });
        let mut pairs = query_pairs(Some(&q));
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("count".to_string(), "5".to_string()),
                ("flag".to_string(), "true".to_string()),
                ("name".to_string(), "abc".to_string()),
            ]
        );
        assert!(query_pairs(None).is_empty());
    }

    #[test]
    fn call_service_rejects_non_allowlisted_service() {
        // Resolution fails before any network or vault access is attempted.
        let config = Config {
            servers: HashMap::new(),
            services: HashMap::new(),
            secret_backend: crate::config::SecretBackend::default(),
        };
        let err = call_service("nope", "GET", "/", None, None, None, &config).unwrap_err();
        assert!(err.to_string().contains("not in the allowed services list"));
    }

    /// Resend sending-only service: bearer auth, GET+POST only, confined to /emails.
    fn resend_send_service() -> ServiceInfo {
        ServiceInfo {
            base_url: "https://api.resend.com".to_string(),
            auth: AuthScheme::Bearer,
            secret_name: "ResendSendKey".to_string(),
            extra: None,
            allowed_methods: Some(["GET", "POST"].into_iter().map(String::from).collect()),
            allowed_path_prefixes: Some(["/emails"].into_iter().map(String::from).collect()),
        }
    }

    /// Resend full-access (admin) service: bearer auth, full verb set, spans the
    /// entire Resend management surface — domains, keys, audiences, broadcasts,
    /// webhooks — in addition to sending.
    fn resend_admin_service() -> ServiceInfo {
        ServiceInfo {
            base_url: "https://api.resend.com".to_string(),
            auth: AuthScheme::Bearer,
            secret_name: "ResendAdminKey".to_string(),
            extra: None,
            allowed_methods: Some(
                ["GET", "POST", "PUT", "PATCH", "DELETE"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            ),
            allowed_path_prefixes: Some(
                ["/emails", "/domains", "/api-keys", "/audiences", "/broadcasts", "/webhooks"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            ),
        }
    }

    #[test]
    fn resend_send_service_confines_to_emails_and_rejects_admin_paths() {
        let send = resend_send_service();

        // Single send, batch send, and (read-side) retrieval all live under /emails.
        for path in ["/emails", "/emails/batch"] {
            assert!(
                validate_path_allowed(&send, path).is_ok(),
                "expected {path} to be allowed for the sending-only key"
            );
        }

        // Administrative surfaces must be refused when using the sending-only key.
        for path in [
            "/domains",
            "/domains/abc/verify",
            "/api-keys",
            "/audiences",
            "/audiences/abc/contacts",
            "/broadcasts",
            "/webhooks",
        ] {
            assert!(
                validate_path_allowed(&send, path).is_err(),
                "expected {path} to be DENIED for the sending-only key"
            );
        }

        // Only GET/POST are permitted for the sending-only alias.
        assert!(validate_method_allowed(&send, "get").is_ok());
        assert!(validate_method_allowed(&send, "POST").is_ok());
        assert!(validate_method_allowed(&send, "DELETE").is_err());
        assert!(validate_method_allowed(&send, "PUT").is_err());
    }

    #[test]
    fn resend_admin_service_covers_full_lifecycle_surface() {
        let admin = resend_admin_service();

        // The full management lifecycle lives under these prefixes.
        for path in [
            "/emails",
            "/emails/batch",
            "/domains",
            "/domains/abc",
            "/domains/abc/verify",
            "/api-keys",
            "/api-keys/key_123",
            "/audiences",
            "/audiences/aud_123",
            "/audiences/aud_123/contacts",
            "/broadcasts",
            "/broadcasts/bc_123",
            "/webhooks",
            "/webhooks/wh_123",
        ] {
            assert!(
                validate_path_allowed(&admin, path).is_ok(),
                "expected {path} to be allowed for the admin key"
            );
        }

        // Anything outside the allowlisted surface is refused fail-closed.
        assert!(validate_path_allowed(&admin, "/accounts").is_err());
        assert!(validate_path_allowed(&admin, "/domains/../../accounts").is_err());

        // The full set of verbs is permitted (case-insensitive).
        for method in ["GET", "post", "Put", "PATCH", "delete"] {
            assert!(
                validate_method_allowed(&admin, method).is_ok(),
                "expected {method} to be allowed for the admin key"
            );
        }
    }

    #[test]
    fn call_service_refuses_admin_endpoint_with_send_key_before_vault_access() {
        // A request to create a domain via POST /domains must be refused by the
        // sending-only service without ever touching the keychain or network:
        // path validation happens before secret load.
        let mut services = HashMap::new();
        services.insert("resend".to_string(), resend_send_service());
        let config = Config {
            servers: HashMap::new(),
            services,
            secret_backend: crate::config::SecretBackend::default(),
        };
        let err = call_service(
            "resend",
            "POST",
            "/domains",
            None,
            None,
            None,
            &config,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not within an allowed path prefix"),
            "expected path-prefix rejection, got: {err}"
        );
    }

    #[test]
    fn resend_send_service_rejects_destructive_verb_for_emails() {
        // Even on the allowed /emails prefix, the sending-only alias must not
        // permit DELETE — validation fails closed on the verb before any I/O.
        let send = resend_send_service();
        assert!(validate_method_allowed(&send, "DELETE").is_err());
    }
}
