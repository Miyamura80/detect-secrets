//! Plugin framework traits for secret detection.
//!
//! This module provides the core trait system that all secret detection plugins
//! implement, mirroring the Python `detect_secrets.plugins.base` module.
//!
//! - [`SecretDetector`] — base trait with `secret_type()` and `analyze_string()`
//! - [`RegexBasedDetector`] — trait for regex-based plugins with `denylist()`
//! - [`build_assignment_regex`] — helper to generate assignment-pattern regexes

use regex::Regex;

use crate::potential_secret::PotentialSecret;

/// Result of optional secret verification.
///
/// Matches Python's `VerifiedResult` enum from `detect_secrets.constants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedResult {
    /// Secret tested and confirmed invalid.
    VerifiedFalse,
    /// Verification not attempted or inconclusive.
    Unverified,
    /// Secret tested and confirmed valid.
    VerifiedTrue,
}

/// Base trait for all secret detection plugins.
///
/// Mirrors Python's `BasePlugin` abstract class.
pub trait SecretDetector {
    /// Unique, user-facing description of the secret type.
    ///
    /// Examples: `"Basic Auth Credentials"`, `"AWS Access Key"`.
    fn secret_type(&self) -> &str;

    /// Yield all raw secret values found in `input`.
    ///
    /// Returns a `Vec<String>` of matched secret values (the Rust equivalent
    /// of Python's `Generator[str, None, None]`).
    fn analyze_string(&self, input: &str) -> Vec<String>;

    /// Examine a single line and return all potential secrets found.
    ///
    /// The default implementation calls [`analyze_string`] on `line` and wraps
    /// each match in a [`PotentialSecret`].
    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PotentialSecret> {
        self.analyze_string(line)
            .into_iter()
            .map(|secret| {
                PotentialSecret::new(
                    self.secret_type(),
                    filename,
                    &secret,
                    line_number,
                    None,
                    false,
                )
            })
            .collect()
    }

    /// Optional verification of a secret value.
    ///
    /// Plugins can override this to check whether a secret is actually valid
    /// (e.g. by calling an API). The default returns [`VerifiedResult::Unverified`].
    fn verify(&self, _secret: &str) -> VerifiedResult {
        VerifiedResult::Unverified
    }

    /// Serialize plugin configuration to JSON (for baseline files).
    ///
    /// Default returns `{"name": "<struct name>"}`. Plugins with constructor
    /// parameters should override this to include those parameters.
    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": self.secret_type() })
    }
}

/// Trait for regex-based secret detectors.
///
/// Provides a default [`analyze_string`](SecretDetector::analyze_string)
/// implementation that iterates `denylist()` regexes and collects matches.
///
/// ## Creating a new plugin
///
/// 1. Implement `secret_type()` returning a descriptive string.
/// 2. Implement `denylist()` returning a slice of compiled [`Regex`] patterns.
/// 3. The default `analyze_string()` will iterate the denylist, yielding:
///    - For patterns **with** capture groups: each non-empty capture.
///    - For patterns **without** capture groups: the full match.
///
/// Mirrors Python's `RegexBasedDetector`.
pub trait RegexBasedDetector: SecretDetector {
    /// Compiled regex patterns to match against input strings.
    fn denylist(&self) -> &[Regex];
}

/// Default `analyze_string` implementation for any `RegexBasedDetector`.
///
/// This is a free function because Rust traits can't have default method
/// implementations that depend on other trait methods from a supertrait
/// in a blanket-impl-friendly way. Plugins should call this from their
/// `SecretDetector::analyze_string()` implementation.
pub fn regex_analyze_string(detector: &dyn RegexBasedDetector, input: &str) -> Vec<String> {
    let mut results = Vec::new();

    for regex in detector.denylist() {
        for caps in regex.captures_iter(input) {
            let group_count = caps.len();

            if group_count > 1 {
                // Pattern has capture groups — yield each non-empty submatch.
                // This matches Python's `isinstance(match, tuple)` branch:
                // `regex.findall()` returns tuples when there are groups.
                for i in 1..group_count {
                    if let Some(m) = caps.get(i) {
                        let text = m.as_str();
                        if !text.is_empty() {
                            results.push(text.to_string());
                        }
                    }
                }
            } else {
                // No capture groups — yield the full match.
                results.push(caps[0].to_string());
            }
        }
    }

    results
}

/// Generate a regex for common assignment patterns.
///
/// Produces a pattern matching:
/// ```text
/// <prefix>(-|_|)<keyword> <assignment> <secret>
/// ```
///
/// where assignment operators include `=`, `:`, `:=`, `=>`, `::`, or whitespace.
///
/// Matches Python's `RegexBasedDetector.build_assignment_regex()`.
///
/// Returns `None` if the composed pattern fails to compile.
pub fn build_assignment_regex(
    prefix_regex: &str,
    secret_keyword_regex: &str,
    secret_regex: &str,
) -> Option<Regex> {
    // Python uses `(?:(?<=\W)|(?<=^))` but Rust regex doesn't support lookbehinds.
    // Use `(?:^|\W)` as a non-capturing equivalent — the non-word-char boundary
    // or start-of-string anchor achieves the same intent.
    let begin = r"(?:^|\W)";
    let opt_quote = r#"(?:["']?)"#;
    let opt_open_square_bracket = r"(?:\[?)";
    let opt_close_square_bracket = r"(?:\]?)";
    let opt_dash_underscore = r"(?:[_-]?)";
    let opt_space = r"(?: *)";
    let assignment = r"(?:=|:|:=|=>| +|::)";

    let pattern = format!(
        "(?i){begin}{opt_open_square_bracket}{opt_quote}{prefix_regex}{opt_dash_underscore}{secret_keyword_regex}{opt_quote}{opt_close_square_bracket}{opt_space}{assignment}{opt_space}{opt_quote}{secret_regex}{opt_quote}",
    );

    Regex::new(&pattern).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Test plugin to validate the framework ----

    struct TestPrivateKeyDetector {
        patterns: Vec<Regex>,
    }

    impl TestPrivateKeyDetector {
        fn new() -> Self {
            Self {
                patterns: vec![
                    Regex::new(r"BEGIN DSA PRIVATE KEY").unwrap(),
                    Regex::new(r"BEGIN EC PRIVATE KEY").unwrap(),
                    Regex::new(r"BEGIN RSA PRIVATE KEY").unwrap(),
                    Regex::new(r"BEGIN PRIVATE KEY").unwrap(),
                ],
            }
        }
    }

    impl SecretDetector for TestPrivateKeyDetector {
        fn secret_type(&self) -> &str {
            "Private Key"
        }

        fn analyze_string(&self, input: &str) -> Vec<String> {
            regex_analyze_string(self, input)
        }
    }

    impl RegexBasedDetector for TestPrivateKeyDetector {
        fn denylist(&self) -> &[Regex] {
            &self.patterns
        }
    }

    // ---- Test plugin with capture groups ----

    struct TestBasicAuthDetector {
        patterns: Vec<Regex>,
    }

    impl TestBasicAuthDetector {
        fn new() -> Self {
            Self {
                patterns: vec![Regex::new(r"://[^\s]+:([^\s]+)@").unwrap()],
            }
        }
    }

    impl SecretDetector for TestBasicAuthDetector {
        fn secret_type(&self) -> &str {
            "Basic Auth Credentials"
        }

        fn analyze_string(&self, input: &str) -> Vec<String> {
            regex_analyze_string(self, input)
        }
    }

    impl RegexBasedDetector for TestBasicAuthDetector {
        fn denylist(&self) -> &[Regex] {
            &self.patterns
        }
    }

    // ---- Test plugin with multiple capture groups ----

    struct TestMultiGroupDetector {
        patterns: Vec<Regex>,
    }

    impl TestMultiGroupDetector {
        fn new() -> Self {
            Self {
                patterns: vec![
                    // Pattern with two groups: key and value
                    Regex::new(
                        r#"(?i)aws[_-]?(key|secret)[_-]?=\s*['"]?([A-Za-z0-9/+=]{20,})['"]?"#,
                    )
                    .unwrap(),
                ],
            }
        }
    }

    impl SecretDetector for TestMultiGroupDetector {
        fn secret_type(&self) -> &str {
            "AWS Key"
        }

        fn analyze_string(&self, input: &str) -> Vec<String> {
            regex_analyze_string(self, input)
        }
    }

    impl RegexBasedDetector for TestMultiGroupDetector {
        fn denylist(&self) -> &[Regex] {
            &self.patterns
        }
    }

    // ---- SecretDetector trait tests ----

    #[test]
    fn test_secret_type() {
        let detector = TestPrivateKeyDetector::new();
        assert_eq!(detector.secret_type(), "Private Key");
    }

    #[test]
    fn test_verify_default_is_unverified() {
        let detector = TestPrivateKeyDetector::new();
        assert_eq!(detector.verify("anything"), VerifiedResult::Unverified);
    }

    #[test]
    fn test_json_default() {
        let detector = TestPrivateKeyDetector::new();
        let j = detector.json();
        assert_eq!(j["name"], "Private Key");
    }

    // ---- RegexBasedDetector tests (no capture groups) ----

    #[test]
    fn test_regex_no_groups_match() {
        let detector = TestPrivateKeyDetector::new();
        let line = "-----BEGIN RSA PRIVATE KEY-----";
        let matches = detector.analyze_string(line);
        assert_eq!(matches, vec!["BEGIN RSA PRIVATE KEY"]);
    }

    #[test]
    fn test_regex_no_groups_no_match() {
        let detector = TestPrivateKeyDetector::new();
        let line = "just a normal line of code";
        let matches = detector.analyze_string(line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_regex_no_groups_multiple_patterns_match() {
        let detector = TestPrivateKeyDetector::new();
        // Two different patterns match
        let line = "BEGIN DSA PRIVATE KEY and BEGIN EC PRIVATE KEY";
        let matches = detector.analyze_string(line);
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&"BEGIN DSA PRIVATE KEY".to_string()));
        assert!(matches.contains(&"BEGIN EC PRIVATE KEY".to_string()));
    }

    // ---- RegexBasedDetector tests (with capture groups) ----

    #[test]
    fn test_regex_with_capture_group() {
        let detector = TestBasicAuthDetector::new();
        let line = "https://user:hunter2@example.com";
        let matches = detector.analyze_string(line);
        assert_eq!(matches, vec!["hunter2"]);
    }

    #[test]
    fn test_regex_with_capture_group_no_match() {
        let detector = TestBasicAuthDetector::new();
        let line = "https://example.com/path";
        let matches = detector.analyze_string(line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_regex_multiple_capture_groups() {
        let detector = TestMultiGroupDetector::new();
        let line = r#"aws_secret="AKIAIOSFODNN7EXAMPLE12345678901234567890""#;
        let matches = detector.analyze_string(line);
        // Should yield both non-empty groups: the keyword and the value
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&"secret".to_string()));
        assert!(matches.contains(&"AKIAIOSFODNN7EXAMPLE12345678901234567890".to_string()));
    }

    // ---- analyze_line tests ----

    #[test]
    fn test_analyze_line_creates_potential_secrets() {
        let detector = TestPrivateKeyDetector::new();
        let secrets = detector.analyze_line("config.pem", "-----BEGIN RSA PRIVATE KEY-----", 5);
        assert_eq!(secrets.len(), 1);
        let s = &secrets[0];
        assert_eq!(s.secret_type, "Private Key");
        assert_eq!(s.filename, "config.pem");
        assert_eq!(s.line_number, 5);
        assert_eq!(s.secret_value.as_deref(), Some("BEGIN RSA PRIVATE KEY"));
        assert!(s.is_secret.is_none());
        assert!(!s.is_verified);
    }

    #[test]
    fn test_analyze_line_no_match_returns_empty() {
        let detector = TestPrivateKeyDetector::new();
        let secrets = detector.analyze_line("file.py", "print('hello')", 1);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_analyze_line_multiple_matches() {
        let detector = TestPrivateKeyDetector::new();
        let line = "BEGIN DSA PRIVATE KEY and also BEGIN EC PRIVATE KEY";
        let secrets = detector.analyze_line("keys.pem", line, 10);
        assert_eq!(secrets.len(), 2);
        assert!(secrets.iter().all(|s| s.filename == "keys.pem"));
        assert!(secrets.iter().all(|s| s.line_number == 10));
    }

    #[test]
    fn test_analyze_line_capture_group_match() {
        let detector = TestBasicAuthDetector::new();
        let secrets =
            detector.analyze_line("env.sh", "URL=https://admin:p4ssw0rd@db.example.com", 3);
        assert_eq!(secrets.len(), 1);
        let s = &secrets[0];
        assert_eq!(s.secret_type, "Basic Auth Credentials");
        assert_eq!(s.secret_value.as_deref(), Some("p4ssw0rd"));
    }

    // ---- build_assignment_regex tests ----

    #[test]
    fn test_build_assignment_regex_basic() {
        let regex = build_assignment_regex("aws", "secret", r"[A-Za-z0-9/+=]+").unwrap();

        // Should match: aws_secret = 'mySecretKey123'
        assert!(regex.is_match("aws_secret = 'mySecretKey123'"));
        assert!(regex.is_match("aws-secret = mySecretKey123"));
        assert!(regex.is_match("aws_secret=mySecretKey123"));
        assert!(regex.is_match("aws_secret:mySecretKey123"));
        assert!(regex.is_match("awssecret = mySecretKey123"));
    }

    #[test]
    fn test_build_assignment_regex_case_insensitive() {
        let regex = build_assignment_regex("AWS", "SECRET", r"[A-Za-z0-9]+").unwrap();
        assert!(regex.is_match("aws_secret = mykey"));
        assert!(regex.is_match("AWS_SECRET = MYKEY"));
        assert!(regex.is_match("Aws_Secret = MyKey"));
    }

    #[test]
    fn test_build_assignment_regex_with_quotes() {
        let regex = build_assignment_regex("api", "key", r"[A-Za-z0-9]+").unwrap();
        assert!(regex.is_match(r#""api_key" = "abc123""#));
        assert!(regex.is_match("'api_key' = 'abc123'"));
    }

    #[test]
    fn test_build_assignment_regex_with_square_brackets() {
        let regex = build_assignment_regex("api", "key", r"[A-Za-z0-9]+").unwrap();
        assert!(regex.is_match("[api_key] = abc123"));
    }

    #[test]
    fn test_build_assignment_regex_arrow_operator() {
        let regex = build_assignment_regex("db", "password", r"[A-Za-z0-9]+").unwrap();
        assert!(regex.is_match("db_password => secretpass"));
    }

    #[test]
    fn test_build_assignment_regex_double_colon() {
        let regex = build_assignment_regex("db", "password", r"[A-Za-z0-9]+").unwrap();
        assert!(regex.is_match("db_password::secretpass"));
    }

    #[test]
    fn test_build_assignment_regex_walrus_operator() {
        let regex = build_assignment_regex("db", "password", r"[A-Za-z0-9]+").unwrap();
        assert!(regex.is_match("db_password:=secretpass"));
    }

    #[test]
    fn test_build_assignment_regex_no_match_random() {
        let regex = build_assignment_regex("api", "key", r"[A-Za-z0-9]+").unwrap();
        assert!(!regex.is_match("just some random text"));
    }
}
