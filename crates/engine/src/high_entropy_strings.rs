//! High-entropy string plugins for secret detection.
//!
//! This module implements `Base64HighEntropyString` and `HexHighEntropyString`,
//! which detect secrets by finding quoted strings composed of a specific charset
//! and checking their Shannon entropy against a configurable threshold.
//!
//! Mirrors Python's `detect_secrets.plugins.high_entropy_strings` module.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::entropy::{
    calculate_hex_shannon_entropy, calculate_shannon_entropy, BASE64_CHARSET, HEX_CHARSET,
};
use crate::plugin::SecretDetector;
use crate::potential_secret::PotentialSecret;

// ---------------------------------------------------------------------------
// Cached compiled regexes for base64 and hex charsets
// ---------------------------------------------------------------------------

/// Pre-compiled double-quote regex for base64 charset.
static BASE64_REGEX_DOUBLE: Lazy<Regex> = Lazy::new(|| {
    let escaped = regex::escape(BASE64_CHARSET);
    Regex::new(&format!(r#""([{escaped}]+)""#)).expect("base64 double-quote regex must compile")
});

/// Pre-compiled single-quote regex for base64 charset.
static BASE64_REGEX_SINGLE: Lazy<Regex> = Lazy::new(|| {
    let escaped = regex::escape(BASE64_CHARSET);
    Regex::new(&format!(r"'([{escaped}]+)'")).expect("base64 single-quote regex must compile")
});

/// Pre-compiled double-quote regex for hex charset.
static HEX_REGEX_DOUBLE: Lazy<Regex> = Lazy::new(|| {
    let escaped = regex::escape(HEX_CHARSET);
    Regex::new(&format!(r#""([{escaped}]+)""#)).expect("hex double-quote regex must compile")
});

/// Pre-compiled single-quote regex for hex charset.
static HEX_REGEX_SINGLE: Lazy<Regex> = Lazy::new(|| {
    let escaped = regex::escape(HEX_CHARSET);
    Regex::new(&format!(r"'([{escaped}]+)'")).expect("hex single-quote regex must compile")
});

/// Base implementation for high-entropy string detection plugins.
///
/// Extracts quoted substrings composed entirely of `charset` characters,
/// then filters by Shannon entropy threshold.
#[derive(Debug, Clone)]
pub struct HighEntropyStringsPlugin {
    charset: &'static str,
    limit: f64,
    /// Regex for double-quoted strings: "([<charset>]+)"
    regex_double: Regex,
    /// Regex for single-quoted strings: '([<charset>]+)'
    regex_single: Regex,
    type_name: String,
}

impl HighEntropyStringsPlugin {
    /// Create a new high-entropy string plugin.
    ///
    /// - `charset`: The set of valid characters to look for in quoted strings.
    /// - `limit`: Entropy threshold (0.0–8.0). Strings with entropy above this
    ///   are flagged as potential secrets.
    /// - `type_name`: The secret type string (e.g. "Base64 High Entropy String").
    fn new(charset: &'static str, limit: f64, type_name: impl Into<String>) -> Self {
        // Use pre-compiled cached regexes for known charsets; fall back to
        // compiling on-the-fly for custom charsets.
        let (regex_double, regex_single) = if std::ptr::eq(charset, BASE64_CHARSET) {
            (BASE64_REGEX_DOUBLE.clone(), BASE64_REGEX_SINGLE.clone())
        } else if std::ptr::eq(charset, HEX_CHARSET) {
            (HEX_REGEX_DOUBLE.clone(), HEX_REGEX_SINGLE.clone())
        } else {
            // Rust regex doesn't support backreferences (\1), so we use two
            // separate patterns for single-quoted and double-quoted strings.
            let escaped = regex::escape(charset);
            let pattern_double = format!(r#""([{escaped}]+)""#);
            let pattern_single = format!(r"'([{escaped}]+)'");
            let rd =
                Regex::new(&pattern_double).expect("high-entropy double-quote regex must compile");
            let rs =
                Regex::new(&pattern_single).expect("high-entropy single-quote regex must compile");
            (rd, rs)
        };

        Self {
            charset,
            limit,
            regex_double,
            regex_single,
            type_name: type_name.into(),
        }
    }

    /// The entropy threshold.
    pub fn limit(&self) -> f64 {
        self.limit
    }

    /// The charset used for entropy calculation.
    pub fn charset(&self) -> &str {
        self.charset
    }

    /// Calculate Shannon entropy for a candidate string.
    ///
    /// Subclasses may override this (e.g. HexHighEntropyString applies
    /// numeric-only reduction).
    fn calculate_entropy(&self, data: &str) -> f64 {
        calculate_shannon_entropy(data, self.charset)
    }

    /// Extract quoted substrings that match the charset regex.
    ///
    /// Returns the captured content (group 1) for each match — the text
    /// between matching quotes (either single or double).
    fn find_candidates(&self, input: &str) -> Vec<String> {
        let mut results = Vec::new();
        for caps in self.regex_double.captures_iter(input) {
            results.push(caps[1].to_string());
        }
        for caps in self.regex_single.captures_iter(input) {
            results.push(caps[1].to_string());
        }
        results
    }

    /// Build a non-quoted string regex for eager search mode.
    ///
    /// - `is_exact_match = true`: `^([<charset>]+)$` — full line match.
    /// - `is_exact_match = false`: `([<charset>]+)` — substring match.
    fn non_quoted_regex(&self, is_exact_match: bool) -> Regex {
        let escaped = regex::escape(self.charset);
        let pattern = if is_exact_match {
            format!(r"^([{escaped}]+)$")
        } else {
            format!(r"([{escaped}]+)")
        };
        Regex::new(&pattern).expect("non-quoted regex must compile")
    }
}

/// Base64 high-entropy string detector.
///
/// Detects quoted strings of base64 characters with Shannon entropy above
/// the configured threshold (default 4.5).
///
/// Matches Python's `Base64HighEntropyString`.
#[derive(Debug, Clone)]
pub struct Base64HighEntropyString {
    inner: HighEntropyStringsPlugin,
}

impl Base64HighEntropyString {
    /// Default entropy threshold for Base64 strings.
    pub const DEFAULT_LIMIT: f64 = 4.5;

    /// Create a new Base64 high-entropy string detector with the given limit.
    pub fn new(limit: f64) -> Self {
        Self {
            inner: HighEntropyStringsPlugin::new(
                BASE64_CHARSET,
                limit,
                "Base64 High Entropy String",
            ),
        }
    }

    /// The entropy threshold.
    pub fn limit(&self) -> f64 {
        self.inner.limit()
    }
}

impl Default for Base64HighEntropyString {
    fn default() -> Self {
        Self::new(Self::DEFAULT_LIMIT)
    }
}

impl SecretDetector for Base64HighEntropyString {
    fn secret_type(&self) -> &str {
        &self.inner.type_name
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        self.inner
            .find_candidates(input)
            .into_iter()
            .filter(|candidate| self.inner.calculate_entropy(candidate) > self.inner.limit)
            .collect()
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PotentialSecret> {
        // First try quoted strings
        let mut results: Vec<PotentialSecret> = self
            .analyze_string(line)
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
            .collect();

        // Eager search: if no quoted matches, try unquoted substrings
        if results.is_empty() {
            let eager_regex = self.inner.non_quoted_regex(false);
            for caps in eager_regex.captures_iter(line) {
                let candidate = &caps[1];
                if self.inner.calculate_entropy(candidate) > self.inner.limit {
                    results.push(PotentialSecret::new(
                        self.secret_type(),
                        filename,
                        candidate,
                        line_number,
                        None,
                        false,
                    ));
                }
            }
        }

        results
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": "Base64HighEntropyString",
            "limit": self.inner.limit,
        })
    }
}

/// Hex high-entropy string detector.
///
/// Detects quoted strings of hex characters with Shannon entropy above
/// the configured threshold (default 3.0). Applies numeric-only reduction
/// to reduce false positives from all-digit strings.
///
/// Matches Python's `HexHighEntropyString`.
#[derive(Debug, Clone)]
pub struct HexHighEntropyString {
    inner: HighEntropyStringsPlugin,
}

impl HexHighEntropyString {
    /// Default entropy threshold for hex strings.
    pub const DEFAULT_LIMIT: f64 = 3.0;

    /// Create a new Hex high-entropy string detector with the given limit.
    pub fn new(limit: f64) -> Self {
        Self {
            inner: HighEntropyStringsPlugin::new(HEX_CHARSET, limit, "Hex High Entropy String"),
        }
    }

    /// The entropy threshold.
    pub fn limit(&self) -> f64 {
        self.inner.limit()
    }

    /// Calculate entropy with numeric-only reduction for hex strings.
    fn calculate_entropy(&self, data: &str) -> f64 {
        calculate_hex_shannon_entropy(data)
    }
}

impl Default for HexHighEntropyString {
    fn default() -> Self {
        Self::new(Self::DEFAULT_LIMIT)
    }
}

impl SecretDetector for HexHighEntropyString {
    fn secret_type(&self) -> &str {
        &self.inner.type_name
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        self.inner
            .find_candidates(input)
            .into_iter()
            .filter(|candidate| self.calculate_entropy(candidate) > self.inner.limit)
            .collect()
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PotentialSecret> {
        // First try quoted strings
        let mut results: Vec<PotentialSecret> = self
            .analyze_string(line)
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
            .collect();

        // Eager search: if no quoted matches, try unquoted substrings
        if results.is_empty() {
            let eager_regex = self.inner.non_quoted_regex(false);
            for caps in eager_regex.captures_iter(line) {
                let candidate = &caps[1];
                if self.calculate_entropy(candidate) > self.inner.limit {
                    results.push(PotentialSecret::new(
                        self.secret_type(),
                        filename,
                        candidate,
                        line_number,
                        None,
                        false,
                    ));
                }
            }
        }

        results
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": "HexHighEntropyString",
            "limit": self.inner.limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Base64HighEntropyString tests ----

    #[test]
    fn test_base64_secret_type() {
        let plugin = Base64HighEntropyString::default();
        assert_eq!(plugin.secret_type(), "Base64 High Entropy String");
    }

    #[test]
    fn test_base64_default_limit() {
        let plugin = Base64HighEntropyString::default();
        assert!((plugin.limit() - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_base64_custom_limit() {
        let plugin = Base64HighEntropyString::new(3.0);
        assert!((plugin.limit() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_base64_detects_high_entropy_quoted_string() {
        let plugin = Base64HighEntropyString::default();
        // This base64 string "c3VwZXIgc2VjcmV0IHZhbHVl" has entropy ~3.80 (below 4.5)
        // Use a longer, higher-entropy string
        let line = r#"secret = "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5""#;
        let matches = plugin.analyze_string(line);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0],
            "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5"
        );
    }

    #[test]
    fn test_base64_ignores_low_entropy_quoted_string() {
        let plugin = Base64HighEntropyString::default();
        let line = r#"value = "aaaaaa""#;
        let matches = plugin.analyze_string(line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_base64_requires_quotes() {
        let plugin = Base64HighEntropyString::default();
        // Unquoted high-entropy string should not be found by analyze_string
        let line = "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5";
        let matches = plugin.analyze_string(line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_base64_mismatched_quotes_no_match() {
        let plugin = Base64HighEntropyString::default();
        let line = r#"secret = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5""#;
        let matches = plugin.analyze_string(line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_base64_single_quotes() {
        let plugin = Base64HighEntropyString::default();
        let line = "secret = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'";
        let matches = plugin.analyze_string(line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_base64_analyze_line_creates_potential_secrets() {
        let plugin = Base64HighEntropyString::default();
        let line = r#"API_KEY = "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5""#;
        let secrets = plugin.analyze_line("config.py", line, 42);
        assert_eq!(secrets.len(), 1);
        let s = &secrets[0];
        assert_eq!(s.secret_type, "Base64 High Entropy String");
        assert_eq!(s.filename, "config.py");
        assert_eq!(s.line_number, 42);
    }

    #[test]
    fn test_base64_eager_search_unquoted() {
        // analyze_line with eager search should find unquoted high-entropy strings
        let plugin = Base64HighEntropyString::default();
        let line = "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5";
        let secrets = plugin.analyze_line("file.txt", line, 1);
        // Eager search kicks in because no quoted matches
        assert!(!secrets.is_empty());
    }

    #[test]
    fn test_base64_json_serialization() {
        let plugin = Base64HighEntropyString::new(5.0);
        let j = plugin.json();
        assert_eq!(j["name"], "Base64HighEntropyString");
        assert_eq!(j["limit"], 5.0);
    }

    // ---- HexHighEntropyString tests ----

    #[test]
    fn test_hex_secret_type() {
        let plugin = HexHighEntropyString::default();
        assert_eq!(plugin.secret_type(), "Hex High Entropy String");
    }

    #[test]
    fn test_hex_default_limit() {
        let plugin = HexHighEntropyString::default();
        assert!((plugin.limit() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_hex_custom_limit() {
        let plugin = HexHighEntropyString::new(2.5);
        assert!((plugin.limit() - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_hex_detects_high_entropy_quoted_string() {
        let plugin = HexHighEntropyString::default();
        // MD5 hash has high entropy
        let line = r#"hash = "2b00042f7481c7b056c4b410d28f33cf""#;
        let matches = plugin.analyze_string(line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "2b00042f7481c7b056c4b410d28f33cf");
    }

    #[test]
    fn test_hex_ignores_low_entropy_string() {
        let plugin = HexHighEntropyString::default();
        let line = r#"value = "aaaaaa""#;
        let matches = plugin.analyze_string(line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_hex_numeric_reduction_filters_digits() {
        let plugin = HexHighEntropyString::default();
        // "0123456789" is all digits → entropy reduced below 3.0 threshold
        let line = r#"port = "0123456789""#;
        let matches = plugin.analyze_string(line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_hex_no_reduction_for_mixed() {
        let plugin = HexHighEntropyString::default();
        // Mixed hex: no numeric reduction, should have high enough entropy
        let line = r#"hash = "1234567890abcdef1234567890abcdef""#;
        let matches = plugin.analyze_string(line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hex_requires_quotes() {
        let plugin = HexHighEntropyString::default();
        let line = "2b00042f7481c7b056c4b410d28f33cf";
        let matches = plugin.analyze_string(line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_hex_analyze_line_creates_potential_secrets() {
        let plugin = HexHighEntropyString::default();
        let line = r#"token = "2b00042f7481c7b056c4b410d28f33cf""#;
        let secrets = plugin.analyze_line("app.py", line, 10);
        assert_eq!(secrets.len(), 1);
        let s = &secrets[0];
        assert_eq!(s.secret_type, "Hex High Entropy String");
        assert_eq!(s.filename, "app.py");
        assert_eq!(s.line_number, 10);
    }

    #[test]
    fn test_hex_eager_search_unquoted() {
        let plugin = HexHighEntropyString::default();
        let line = "2b00042f7481c7b056c4b410d28f33cf";
        let secrets = plugin.analyze_line("file.txt", line, 1);
        assert!(!secrets.is_empty());
    }

    #[test]
    fn test_hex_json_serialization() {
        let plugin = HexHighEntropyString::new(2.5);
        let j = plugin.json();
        assert_eq!(j["name"], "HexHighEntropyString");
        assert_eq!(j["limit"], 2.5);
    }

    // ---- Cross-plugin tests ----

    #[test]
    fn test_both_plugins_on_same_line() {
        let b64 = Base64HighEntropyString::default();
        let hex = HexHighEntropyString::default();

        // Line with both a hex hash and a base64 string
        let line = r#"hash = "2b00042f7481c7b056c4b410d28f33cf" key = "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5""#;

        let hex_matches = hex.analyze_string(line);
        let b64_matches = b64.analyze_string(line);

        // Hex plugin finds the MD5 hash
        assert!(hex_matches
            .iter()
            .any(|m| m == "2b00042f7481c7b056c4b410d28f33cf"));

        // Base64 plugin finds the base64 string
        assert!(b64_matches
            .iter()
            .any(|m| m == "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5"));
    }

    #[test]
    fn test_empty_line() {
        let b64 = Base64HighEntropyString::default();
        let hex = HexHighEntropyString::default();
        assert!(b64.analyze_string("").is_empty());
        assert!(hex.analyze_string("").is_empty());
    }

    #[test]
    fn test_no_quotes_in_line() {
        let b64 = Base64HighEntropyString::default();
        let hex = HexHighEntropyString::default();
        let line = "just some regular code without any quoted strings";
        assert!(b64.analyze_string(line).is_empty());
        assert!(hex.analyze_string(line).is_empty());
    }

    #[test]
    fn test_threshold_boundary() {
        // With a very low threshold, even short strings should match
        let plugin = Base64HighEntropyString::new(0.0);
        let line = r#"x = "abc""#;
        let matches = plugin.analyze_string(line);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_threshold_high_rejects_all() {
        // With an impossibly high threshold, nothing should match
        let plugin = Base64HighEntropyString::new(8.0);
        let line = r#"key = "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5""#;
        let matches = plugin.analyze_string(line);
        assert!(matches.is_empty());
    }

    // ---- Candidate extraction tests ----

    #[test]
    fn test_find_candidates_double_quotes() {
        let plugin = Base64HighEntropyString::default();
        let candidates = plugin.inner.find_candidates(r#"key = "abc123""#);
        assert_eq!(candidates, vec!["abc123"]);
    }

    #[test]
    fn test_find_candidates_single_quotes() {
        let plugin = Base64HighEntropyString::default();
        let candidates = plugin.inner.find_candidates("key = 'abc123'");
        assert_eq!(candidates, vec!["abc123"]);
    }

    #[test]
    fn test_find_candidates_multiple() {
        let plugin = Base64HighEntropyString::default();
        let candidates = plugin.inner.find_candidates(r#"a = "foo" b = "bar""#);
        assert_eq!(candidates, vec!["foo", "bar"]);
    }

    #[test]
    fn test_find_candidates_non_charset_chars_excluded() {
        // Space is not in base64 charset, so this won't match
        let plugin = Base64HighEntropyString::default();
        let candidates = plugin.inner.find_candidates(r#""hello world""#);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_hex_find_candidates_only_hex_chars() {
        let plugin = HexHighEntropyString::default();
        let candidates = plugin.inner.find_candidates(r#""abcdef0123""#);
        assert_eq!(candidates, vec!["abcdef0123"]);
    }

    #[test]
    fn test_hex_find_candidates_non_hex_excluded() {
        let plugin = HexHighEntropyString::default();
        // 'g' is not a hex char
        let candidates = plugin.inner.find_candidates(r#""abcdefg""#);
        assert!(candidates.is_empty());
    }
}
