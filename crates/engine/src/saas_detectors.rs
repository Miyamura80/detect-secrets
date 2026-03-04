//! SaaS service secret detectors.
//!
//! Ports of the following Python detect-secrets plugins:
//! - [`MailchimpDetector`] — Mailchimp API access keys
//! - [`NpmDetector`] — NPM authentication tokens
//! - [`OpenAIDetector`] — OpenAI API tokens
//! - [`PypiTokenDetector`] — PyPI upload tokens
//! - [`SendGridDetector`] — SendGrid API keys
//! - [`SlackDetector`] — Slack tokens and webhook URLs
//! - [`SquareOAuthDetector`] — Square OAuth secrets
//! - [`StripeDetector`] — Stripe live API keys
//! - [`TelegramBotTokenDetector`] — Telegram Bot API tokens
//! - [`TwilioKeyDetector`] — Twilio account SIDs and auth tokens
//! - [`IpPublicDetector`] — Public IPv4 addresses

use once_cell::sync::Lazy;
use regex::Regex;

use crate::plugin::{regex_analyze_string, RegexBasedDetector, SecretDetector};

// ---------------------------------------------------------------------------
// Cached compiled regex denylists
// ---------------------------------------------------------------------------

static MAILCHIMP_DENYLIST: Lazy<Vec<Regex>> =
    Lazy::new(|| vec![Regex::new(r"[0-9a-z]{32}-us[0-9]{1,2}").unwrap()]);

static NPM_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"//.+/:_authToken=\s*((?:npm_.+)|(?:[A-Fa-f0-9-]{36}))").unwrap()]
});

static OPENAI_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"sk-[A-Za-z0-9\-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}").unwrap()]
});

static PYPI_TOKEN_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // pypi.org token
        Regex::new(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{70,}").unwrap(),
        // test.pypi.org token
        Regex::new(r"pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9\-_]{70,}").unwrap(),
    ]
});

static SENDGRID_DENYLIST: Lazy<Vec<Regex>> =
    Lazy::new(|| vec![Regex::new(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}").unwrap()]);

static SLACK_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Slack tokens (xoxa, xoxb, xoxp, xoxo, xoxs, xoxr) -- case insensitive
        Regex::new(r"(?i)xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+").unwrap(),
        // Slack webhook URLs
        Regex::new(
            r"(?i)https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        )
        .unwrap(),
    ]
});

static SQUARE_OAUTH_DENYLIST: Lazy<Vec<Regex>> =
    Lazy::new(|| vec![Regex::new(r"sq0csp-[0-9A-Za-z\\\-_]{43}").unwrap()]);

static STRIPE_DENYLIST: Lazy<Vec<Regex>> =
    Lazy::new(|| vec![Regex::new(r"(?:r|s)k_live_[0-9a-zA-Z]{24}").unwrap()]);

static TELEGRAM_BOT_TOKEN_DENYLIST: Lazy<Vec<Regex>> =
    Lazy::new(|| vec![Regex::new(r"^\d{8,10}:[0-9A-Za-z_-]{35}$").unwrap()]);

static TWILIO_KEY_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Account SID
        Regex::new(r"AC[a-z0-9]{32}").unwrap(),
        // Auth token
        Regex::new(r"SK[a-z0-9]{32}").unwrap(),
    ]
});

static IP_PUBLIC_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(?::\d{1,5})?"
    ).unwrap()
});

// ---------------------------------------------------------------------------
// MailchimpDetector
// ---------------------------------------------------------------------------

/// Detects Mailchimp API access keys.
///
/// Matches Python's `detect_secrets.plugins.mailchimp.MailchimpDetector`.
#[derive(Clone)]
pub struct MailchimpDetector {
    patterns: Vec<Regex>,
}

impl MailchimpDetector {
    pub fn new() -> Self {
        Self {
            patterns: MAILCHIMP_DENYLIST.clone(),
        }
    }
}

impl Default for MailchimpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for MailchimpDetector {
    fn secret_type(&self) -> &str {
        "Mailchimp Access Key"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "MailchimpDetector" })
    }
}

impl RegexBasedDetector for MailchimpDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// NpmDetector
// ---------------------------------------------------------------------------

/// Detects NPM authentication tokens.
///
/// Matches Python's `detect_secrets.plugins.npm.NpmDetector`.
#[derive(Clone)]
pub struct NpmDetector {
    patterns: Vec<Regex>,
}

impl NpmDetector {
    pub fn new() -> Self {
        Self {
            patterns: NPM_DENYLIST.clone(),
        }
    }
}

impl Default for NpmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for NpmDetector {
    fn secret_type(&self) -> &str {
        "NPM tokens"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "NpmDetector" })
    }
}

impl RegexBasedDetector for NpmDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// OpenAIDetector
// ---------------------------------------------------------------------------

/// Detects OpenAI API tokens.
///
/// Matches Python's `detect_secrets.plugins.openai.OpenAIDetector`.
#[derive(Clone)]
pub struct OpenAIDetector {
    patterns: Vec<Regex>,
}

impl OpenAIDetector {
    pub fn new() -> Self {
        Self {
            patterns: OPENAI_DENYLIST.clone(),
        }
    }
}

impl Default for OpenAIDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for OpenAIDetector {
    fn secret_type(&self) -> &str {
        "OpenAI Token"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "OpenAIDetector" })
    }
}

impl RegexBasedDetector for OpenAIDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// PypiTokenDetector
// ---------------------------------------------------------------------------

/// Detects PyPI upload tokens.
///
/// Matches Python's `detect_secrets.plugins.pypi_token.PypiTokenDetector`.
#[derive(Clone)]
pub struct PypiTokenDetector {
    patterns: Vec<Regex>,
}

impl PypiTokenDetector {
    pub fn new() -> Self {
        Self {
            patterns: PYPI_TOKEN_DENYLIST.clone(),
        }
    }
}

impl Default for PypiTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for PypiTokenDetector {
    fn secret_type(&self) -> &str {
        "PyPI Token"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "PypiTokenDetector" })
    }
}

impl RegexBasedDetector for PypiTokenDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// SendGridDetector
// ---------------------------------------------------------------------------

/// Detects SendGrid API keys.
///
/// Matches Python's `detect_secrets.plugins.sendgrid.SendGridDetector`.
#[derive(Clone)]
pub struct SendGridDetector {
    patterns: Vec<Regex>,
}

impl SendGridDetector {
    pub fn new() -> Self {
        Self {
            patterns: SENDGRID_DENYLIST.clone(),
        }
    }
}

impl Default for SendGridDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for SendGridDetector {
    fn secret_type(&self) -> &str {
        "SendGrid API Key"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "SendGridDetector" })
    }
}

impl RegexBasedDetector for SendGridDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// SlackDetector
// ---------------------------------------------------------------------------

/// Detects Slack tokens and webhook URLs.
///
/// Matches Python's `detect_secrets.plugins.slack.SlackDetector`.
#[derive(Clone)]
pub struct SlackDetector {
    patterns: Vec<Regex>,
}

impl SlackDetector {
    pub fn new() -> Self {
        Self {
            patterns: SLACK_DENYLIST.clone(),
        }
    }
}

impl Default for SlackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for SlackDetector {
    fn secret_type(&self) -> &str {
        "Slack Token"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "SlackDetector" })
    }
}

impl RegexBasedDetector for SlackDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// SquareOAuthDetector
// ---------------------------------------------------------------------------

/// Detects Square OAuth secrets.
///
/// Matches Python's `detect_secrets.plugins.square_oauth.SquareOAuthDetector`.
#[derive(Clone)]
pub struct SquareOAuthDetector {
    patterns: Vec<Regex>,
}

impl SquareOAuthDetector {
    pub fn new() -> Self {
        Self {
            patterns: SQUARE_OAUTH_DENYLIST.clone(),
        }
    }
}

impl Default for SquareOAuthDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for SquareOAuthDetector {
    fn secret_type(&self) -> &str {
        "Square OAuth Secret"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "SquareOAuthDetector" })
    }
}

impl RegexBasedDetector for SquareOAuthDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// StripeDetector
// ---------------------------------------------------------------------------

/// Detects Stripe live API keys.
///
/// Matches Python's `detect_secrets.plugins.stripe.StripeDetector`.
#[derive(Clone)]
pub struct StripeDetector {
    patterns: Vec<Regex>,
}

impl StripeDetector {
    pub fn new() -> Self {
        Self {
            patterns: STRIPE_DENYLIST.clone(),
        }
    }
}

impl Default for StripeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for StripeDetector {
    fn secret_type(&self) -> &str {
        "Stripe Access Key"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "StripeDetector" })
    }
}

impl RegexBasedDetector for StripeDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// TelegramBotTokenDetector
// ---------------------------------------------------------------------------

/// Detects Telegram Bot API tokens.
///
/// Matches Python's `detect_secrets.plugins.telegram_token.TelegramBotTokenDetector`.
#[derive(Clone)]
pub struct TelegramBotTokenDetector {
    patterns: Vec<Regex>,
}

impl TelegramBotTokenDetector {
    pub fn new() -> Self {
        Self {
            patterns: TELEGRAM_BOT_TOKEN_DENYLIST.clone(),
        }
    }
}

impl Default for TelegramBotTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for TelegramBotTokenDetector {
    fn secret_type(&self) -> &str {
        "Telegram Bot Token"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "TelegramBotTokenDetector" })
    }
}

impl RegexBasedDetector for TelegramBotTokenDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// TwilioKeyDetector
// ---------------------------------------------------------------------------

/// Detects Twilio account SIDs and auth tokens.
///
/// Matches Python's `detect_secrets.plugins.twilio.TwilioKeyDetector`.
#[derive(Clone)]
pub struct TwilioKeyDetector {
    patterns: Vec<Regex>,
}

impl TwilioKeyDetector {
    pub fn new() -> Self {
        Self {
            patterns: TWILIO_KEY_DENYLIST.clone(),
        }
    }
}

impl Default for TwilioKeyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for TwilioKeyDetector {
    fn secret_type(&self) -> &str {
        "Twilio API Key"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "TwilioKeyDetector" })
    }
}

impl RegexBasedDetector for TwilioKeyDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// IpPublicDetector
// ---------------------------------------------------------------------------

/// Detects public IPv4 addresses (excludes private/reserved ranges).
///
/// Matches Python's `detect_secrets.plugins.ip_public.IPPublicDetector`.
///
/// Note: Python original uses lookbehinds and negative lookaheads which Rust
/// `regex` crate doesn't support. Instead we use a custom `analyze_string()`
/// that matches all IPv4 addresses then filters out private ranges and
/// checks word boundaries manually.
#[derive(Clone)]
pub struct IpPublicDetector {
    /// Matches any IPv4 address with optional port.
    ip_pattern: Regex,
}

impl IpPublicDetector {
    pub fn new() -> Self {
        Self {
            ip_pattern: IP_PUBLIC_PATTERN.clone(),
        }
    }

    /// Check whether the given IP (without port) is in a private/reserved range.
    fn is_private_ip(ip: &str) -> bool {
        ip.starts_with("192.168.")
            || ip.starts_with("127.")
            || ip.starts_with("10.")
            || ip.starts_with("169.254.")
            || {
                // 172.16.0.0 – 172.31.255.255
                if let Some(rest) = ip.strip_prefix("172.") {
                    if let Some(dot_pos) = rest.find('.') {
                        if let Ok(second_octet) = rest[..dot_pos].parse::<u32>() {
                            return (16..=31).contains(&second_octet);
                        }
                    }
                }
                false
            }
    }
}

impl Default for IpPublicDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for IpPublicDetector {
    fn secret_type(&self) -> &str {
        "Public IP (ipv4)"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        let mut results = Vec::new();
        for mat in self.ip_pattern.find_iter(input) {
            let full_match = mat.as_str();
            // Extract IP portion (without port)
            let ip = if let Some(colon_pos) = full_match.rfind(':') {
                // Only treat as port if the part after colon is all digits
                let after = &full_match[colon_pos + 1..];
                if after.chars().all(|c| c.is_ascii_digit()) {
                    &full_match[..colon_pos]
                } else {
                    full_match
                }
            } else {
                full_match
            };

            // Filter out private/reserved ranges
            if Self::is_private_ip(ip) {
                continue;
            }

            // Check word boundaries: the char before and after must NOT be a word
            // char or dot (matching Python's `(?<![\w.])` and `(?![\w.])`)
            let start = mat.start();
            let end = mat.end();
            if start > 0 {
                let prev = input.as_bytes()[start - 1];
                if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'.' {
                    continue;
                }
            }
            if end < input.len() {
                let next = input.as_bytes()[end];
                if next.is_ascii_alphanumeric() || next == b'_' || next == b'.' {
                    continue;
                }
            }

            results.push(full_match.to_string());
        }
        results
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "IPPublicDetector" })
    }
}

// IpPublicDetector does NOT implement RegexBasedDetector since it uses custom
// analyze_string logic instead of the standard regex denylist iteration.

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- MailchimpDetector --

    #[test]
    fn test_mailchimp_detects_api_key() {
        let d = MailchimpDetector::default();
        let key = ["a1b2c3d4e5f6a1b2", "c3d4e5f6a1b2c3d4-us12"].concat();
        let matches = d.analyze_string(&format!("key = {key}"));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], key);
    }

    #[test]
    fn test_mailchimp_no_match_wrong_suffix() {
        let d = MailchimpDetector::default();
        let matches = d.analyze_string("key = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-eu12");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_mailchimp_secret_type() {
        let d = MailchimpDetector::default();
        assert_eq!(d.secret_type(), "Mailchimp Access Key");
    }

    // -- NpmDetector --

    #[test]
    fn test_npm_detects_npm_token() {
        let d = NpmDetector::default();
        let matches =
            d.analyze_string("//registry.npmjs.org/:_authToken= npm_abcdefghij1234567890");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_npm_detects_uuid_token() {
        let d = NpmDetector::default();
        let matches = d.analyze_string(
            "//registry.npmjs.org/:_authToken=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        );
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_npm_no_match_without_prefix() {
        let d = NpmDetector::default();
        let matches = d.analyze_string("_authToken=npm_abc123");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_npm_secret_type() {
        let d = NpmDetector::default();
        assert_eq!(d.secret_type(), "NPM tokens");
    }

    // -- OpenAIDetector --

    #[test]
    fn test_openai_detects_token() {
        let d = OpenAIDetector::default();
        // Build a valid-looking OpenAI token: sk- + 20 alnum + T3BlbkFJ + 20 alnum
        let token = format!("sk-{}T3BlbkFJ{}", "A".repeat(20), "B".repeat(20));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], token);
    }

    #[test]
    fn test_openai_no_match_without_marker() {
        let d = OpenAIDetector::default();
        let matches = d.analyze_string("sk-somethingWithoutTheMarkerHere");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_openai_secret_type() {
        let d = OpenAIDetector::default();
        assert_eq!(d.secret_type(), "OpenAI Token");
    }

    // -- PypiTokenDetector --

    #[test]
    fn test_pypi_detects_production_token() {
        let d = PypiTokenDetector::default();
        let token = format!("pypi-AgEIcHlwaS5vcmc{}", "A".repeat(70));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pypi_detects_test_token() {
        let d = PypiTokenDetector::default();
        let token = format!("pypi-AgENdGVzdC5weXBpLm9yZw{}", "B".repeat(70));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pypi_no_match_short_token() {
        let d = PypiTokenDetector::default();
        let token = format!("pypi-AgEIcHlwaS5vcmc{}", "A".repeat(10));
        let matches = d.analyze_string(&token);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_pypi_secret_type() {
        let d = PypiTokenDetector::default();
        assert_eq!(d.secret_type(), "PyPI Token");
    }

    // -- SendGridDetector --

    #[test]
    fn test_sendgrid_detects_key() {
        let d = SendGridDetector::default();
        // Build proper key: SG. + 22-char + . + 43-char
        let key = format!(
            "SG.{}.{}",
            "abcdefghij1234567890AB", "abcdefghij1234567890ABCDEFGHIJklmnopqrstuvwx"
        );
        let matches = d.analyze_string(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sendgrid_no_match_wrong_prefix() {
        let d = SendGridDetector::default();
        let matches = d.analyze_string(
            "XG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        assert!(matches.is_empty());
    }

    #[test]
    fn test_sendgrid_secret_type() {
        let d = SendGridDetector::default();
        assert_eq!(d.secret_type(), "SendGrid API Key");
    }

    // -- SlackDetector --

    #[test]
    fn test_slack_detects_bot_token() {
        let d = SlackDetector::default();
        let matches = d.analyze_string("token = xoxb-123456-789012-abcdef123456");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_slack_detects_webhook() {
        let d = SlackDetector::default();
        let matches = d.analyze_string(
            "url = https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop",
        );
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_slack_case_insensitive() {
        let d = SlackDetector::default();
        let matches = d.analyze_string("XOXB-123456-789012-ABCDEF123456");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_slack_no_match_random() {
        let d = SlackDetector::default();
        let matches = d.analyze_string("just some random text");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_slack_secret_type() {
        let d = SlackDetector::default();
        assert_eq!(d.secret_type(), "Slack Token");
    }

    // -- SquareOAuthDetector --

    #[test]
    fn test_square_detects_oauth_secret() {
        let d = SquareOAuthDetector::default();
        let secret = format!("sq0csp-{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V");
        let matches = d.analyze_string(&secret);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_square_no_match_wrong_prefix() {
        let d = SquareOAuthDetector::default();
        let matches = d.analyze_string("sq0atp-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_square_secret_type() {
        let d = SquareOAuthDetector::default();
        assert_eq!(d.secret_type(), "Square OAuth Secret");
    }

    // -- StripeDetector --

    #[test]
    fn test_stripe_detects_secret_key() {
        let d = StripeDetector::default();
        let key = format!("sk_live_{}", "a1B2c3D4e5F6g7H8i9J0k1L2");
        let matches = d.analyze_string(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_stripe_detects_restricted_key() {
        let d = StripeDetector::default();
        let key = format!("rk_live_{}", "a1B2c3D4e5F6g7H8i9J0k1L2");
        let matches = d.analyze_string(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_stripe_no_match_test_key() {
        let d = StripeDetector::default();
        let key = ["sk_test_", "a1B2c3D4e5F6g7H8i9J0k1L2"].concat();
        let matches = d.analyze_string(&key);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_stripe_secret_type() {
        let d = StripeDetector::default();
        assert_eq!(d.secret_type(), "Stripe Access Key");
    }

    // -- TelegramBotTokenDetector --

    #[test]
    fn test_telegram_detects_bot_token() {
        let d = TelegramBotTokenDetector::default();
        let token = format!("12345678:{}", "ABCDEfghij1234567890ABCDEfghij12345");
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_telegram_no_match_too_short_id() {
        let d = TelegramBotTokenDetector::default();
        let token = format!("1234567:{}", "ABCDEfghij1234567890ABCDEfghij12345");
        let matches = d.analyze_string(&token);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_telegram_no_match_embedded_in_text() {
        let d = TelegramBotTokenDetector::default();
        // Has ^ and $ anchors, shouldn't match embedded
        let token = format!(
            "prefix 12345678:{} suffix",
            "ABCDEfghij1234567890ABCDEfghij12345"
        );
        let matches = d.analyze_string(&token);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_telegram_secret_type() {
        let d = TelegramBotTokenDetector::default();
        assert_eq!(d.secret_type(), "Telegram Bot Token");
    }

    // -- TwilioKeyDetector --

    #[test]
    fn test_twilio_detects_account_sid() {
        let d = TwilioKeyDetector::default();
        let sid = format!("AC{}", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
        let matches = d.analyze_string(&sid);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_twilio_detects_auth_token() {
        let d = TwilioKeyDetector::default();
        let token = format!("SK{}", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_twilio_no_match_uppercase() {
        let d = TwilioKeyDetector::default();
        // Python's pattern uses [a-z0-9], no uppercase
        let matches = d.analyze_string("ACABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_twilio_secret_type() {
        let d = TwilioKeyDetector::default();
        assert_eq!(d.secret_type(), "Twilio API Key");
    }

    // -- IpPublicDetector --

    #[test]
    fn test_ip_detects_public_ip() {
        let d = IpPublicDetector::default();
        let matches = d.analyze_string("server at 8.8.8.8 is down");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "8.8.8.8");
    }

    #[test]
    fn test_ip_detects_public_ip_with_port() {
        let d = IpPublicDetector::default();
        let matches = d.analyze_string("connect to 203.0.113.1:8080");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "203.0.113.1:8080");
    }

    #[test]
    fn test_ip_ignores_private_192_168() {
        let d = IpPublicDetector::default();
        let matches = d.analyze_string("host = 192.168.1.1");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ip_ignores_private_10() {
        let d = IpPublicDetector::default();
        let matches = d.analyze_string("host = 10.0.0.1");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ip_ignores_localhost() {
        let d = IpPublicDetector::default();
        let matches = d.analyze_string("host = 127.0.0.1");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ip_ignores_link_local() {
        let d = IpPublicDetector::default();
        let matches = d.analyze_string("host = 169.254.1.1");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ip_ignores_private_172_range() {
        let d = IpPublicDetector::default();
        let matches = d.analyze_string("host = 172.16.0.1");
        assert!(matches.is_empty());
        let matches = d.analyze_string("host = 172.31.255.255");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ip_allows_172_outside_range() {
        let d = IpPublicDetector::default();
        let matches = d.analyze_string("host = 172.32.0.1");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ip_no_match_word_boundary() {
        let d = IpPublicDetector::default();
        // Should not match when embedded in word chars
        let matches = d.analyze_string("version1.2.3.4suffix");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ip_no_match_dot_boundary() {
        let d = IpPublicDetector::default();
        // Should not match when preceded/followed by dot
        let matches = d.analyze_string(".1.2.3.4.");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ip_secret_type() {
        let d = IpPublicDetector::default();
        assert_eq!(d.secret_type(), "Public IP (ipv4)");
    }

    // -- JSON output tests --

    #[test]
    fn test_json_names() {
        assert_eq!(
            MailchimpDetector::default().json()["name"],
            "MailchimpDetector"
        );
        assert_eq!(NpmDetector::default().json()["name"], "NpmDetector");
        assert_eq!(OpenAIDetector::default().json()["name"], "OpenAIDetector");
        assert_eq!(
            PypiTokenDetector::default().json()["name"],
            "PypiTokenDetector"
        );
        assert_eq!(
            SendGridDetector::default().json()["name"],
            "SendGridDetector"
        );
        assert_eq!(SlackDetector::default().json()["name"], "SlackDetector");
        assert_eq!(
            SquareOAuthDetector::default().json()["name"],
            "SquareOAuthDetector"
        );
        assert_eq!(StripeDetector::default().json()["name"], "StripeDetector");
        assert_eq!(
            TelegramBotTokenDetector::default().json()["name"],
            "TelegramBotTokenDetector"
        );
        assert_eq!(
            TwilioKeyDetector::default().json()["name"],
            "TwilioKeyDetector"
        );
        assert_eq!(
            IpPublicDetector::default().json()["name"],
            "IPPublicDetector"
        );
    }
}
