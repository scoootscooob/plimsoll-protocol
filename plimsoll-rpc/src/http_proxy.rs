//! plimsoll-rpc/src/http_proxy.rs — Web2 Egress Gateway (TLS Interceptor).
//!
//! HTTP/HTTPS Forward Proxy on port `:8080` that intercepts outgoing
//! HTTP requests from AI agents and applies CapitalVelocity PID
//! enforcement to API charges.
//!
//! Enterprises configure `HTTP_PROXY=http://127.0.0.1:8080` in their
//! agent's Docker container.
//!
//! Phase 4.1 of the v2.0 roadmap.

use serde::{Deserialize, Serialize};

// ── Cost rule ────────────────────────────────────────────────────

/// Maps an API endpoint to its USD cost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCostRule {
    /// Domain to match (e.g. "api.stripe.com").
    pub domain: String,
    /// Path prefix to match (e.g. "/v1/charges").
    pub path_prefix: String,
    /// Fixed per-request cost in USD (used if `cost_field` is None).
    pub cost_usd: f64,
    /// JSON body field containing the amount (e.g. "amount").
    pub cost_field: Option<String>,
    /// Divisor to convert the field value to USD (e.g. 100 for cents).
    pub cost_divisor: f64,
}

/// Default cost rules for well-known APIs.
pub fn default_cost_rules() -> Vec<ApiCostRule> {
    vec![
        ApiCostRule {
            domain: "api.stripe.com".into(),
            path_prefix: "/v1/charges".into(),
            cost_usd: 0.0,
            cost_field: Some("amount".into()),
            cost_divisor: 100.0, // Stripe uses cents
        },
        ApiCostRule {
            domain: "api.stripe.com".into(),
            path_prefix: "/v1/payment_intents".into(),
            cost_usd: 0.0,
            cost_field: Some("amount".into()),
            cost_divisor: 100.0,
        },
        ApiCostRule {
            domain: "api.openai.com".into(),
            path_prefix: "/v1/chat/completions".into(),
            cost_usd: 0.03, // Approximate per-request cost
            cost_field: None,
            cost_divisor: 1.0,
        },
        ApiCostRule {
            domain: "api.anthropic.com".into(),
            path_prefix: "/v1/messages".into(),
            cost_usd: 0.05, // Approximate per-request cost
            cost_field: None,
            cost_divisor: 1.0,
        },
    ]
}

// ── Cost extraction ──────────────────────────────────────────────

/// Extract the USD cost from an HTTP request.
///
/// Returns `Some(cost_usd)` if a matching rule is found, `None` otherwise.
pub fn extract_cost(
    domain: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    rules: &[ApiCostRule],
) -> Option<f64> {
    for rule in rules {
        if domain != rule.domain || !path.starts_with(&rule.path_prefix) {
            continue;
        }

        // If there's a cost field, extract from body
        if let Some(ref field) = rule.cost_field {
            if let Some(body) = body {
                if let Some(val) = body.get(field) {
                    let amount = val.as_f64().unwrap_or(0.0);
                    return Some(amount / rule.cost_divisor);
                }
            }
            // Field specified but not found in body — return fixed cost
            return Some(rule.cost_usd);
        }

        // No field — use fixed per-request cost
        return Some(rule.cost_usd);
    }

    None // No matching rule — ungoverned domain
}

// ── Analysis result ──────────────────────────────────────────────

/// Result of HTTP request cost analysis.
#[derive(Debug, Clone, Serialize)]
pub struct HttpAnalysisResult {
    pub allowed: bool,
    pub reason: String,
    pub cost_usd: f64,
    pub domain: String,
    pub path: String,
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_charge_cost_extraction() {
        let rules = default_cost_rules();
        let body = serde_json::json!({ "amount": 5000, "currency": "usd" });
        let cost = extract_cost("api.stripe.com", "/v1/charges", Some(&body), &rules);
        assert_eq!(cost, Some(50.0)); // 5000 cents = $50
    }

    #[test]
    fn test_stripe_payment_intent() {
        let rules = default_cost_rules();
        let body = serde_json::json!({ "amount": 10000 });
        let cost = extract_cost("api.stripe.com", "/v1/payment_intents", Some(&body), &rules);
        assert_eq!(cost, Some(100.0));
    }

    #[test]
    fn test_openai_fixed_cost() {
        let rules = default_cost_rules();
        let body = serde_json::json!({ "model": "gpt-4", "messages": [] });
        let cost = extract_cost("api.openai.com", "/v1/chat/completions", Some(&body), &rules);
        assert_eq!(cost, Some(0.03));
    }

    #[test]
    fn test_ungoverned_domain_returns_none() {
        let rules = default_cost_rules();
        let cost = extract_cost("api.example.com", "/v1/data", None, &rules);
        assert_eq!(cost, None);
    }

    #[test]
    fn test_default_cost_rules_not_empty() {
        let rules = default_cost_rules();
        assert!(rules.len() >= 3);
    }

    #[test]
    fn test_body_field_missing_returns_fixed() {
        let rules = default_cost_rules();
        let body = serde_json::json!({ "currency": "usd" }); // no "amount"
        let cost = extract_cost("api.stripe.com", "/v1/charges", Some(&body), &rules);
        assert_eq!(cost, Some(0.0)); // falls back to cost_usd=0.0
    }
}
