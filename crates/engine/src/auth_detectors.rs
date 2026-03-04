//! Auth and token secret detectors.
//!
//! Ports of the following Python detect-secrets plugins:
//! - [`BasicAuthDetector`] — Basic Auth credentials in URIs
//! - [`DiscordBotTokenDetector`] — Discord Bot tokens
//! - [`GitHubTokenDetector`] — GitHub personal access tokens and similar
//! - [`GitLabTokenDetector`] — GitLab tokens (PAT, deploy, runner, etc.)
//! - [`JwtTokenDetector`] — JSON Web Tokens
//! - [`PrivateKeyDetector`] — Private key file headers

use once_cell::sync::Lazy;
use regex::Regex;

use crate::plugin::{regex_analyze_string, RegexBasedDetector, SecretDetector};

// ---------------------------------------------------------------------------
// Cached compiled regex denylists
// ---------------------------------------------------------------------------

static BASIC_AUTH_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"://[^:/?#\[\]@!$&'()*+,;=\s]+:([^:/?#\[\]@!$&'()*+,;=\s]+)@").unwrap()]
});

static DISCORD_BOT_TOKEN_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Discord Bot Token: [M|N|O]XXX...XXX.XXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXX
        Regex::new(r"[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}").unwrap(),
    ]
});

static GITHUB_TOKEN_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // GitHub token prefixes: ghp (PAT), gho (OAuth), ghu (user-to-server),
        // ghs (server-to-server), ghr (refresh)
        Regex::new(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}").unwrap(),
    ]
});

static GITLAB_TOKEN_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Personal Access Token, Deploy Token, Feed Token, OAuth Access Token, Runner Token
        // Has capture group (glpat|...) -- group 1 returns the prefix.
        Regex::new(r"(glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_-]{20,50}(?:\W|$)").unwrap(),
        // Runner Registration Token (no group in Python -> wrap in group)
        Regex::new(r"(GR1348941[A-Za-z0-9_-]{20,50})(?:\W|$)").unwrap(),
        // CI/CD Token -- has optional group for partition_id
        Regex::new(r"glcbt-([0-9a-fA-F]{2}_)?[A-Za-z0-9_-]{20,50}(?:\W|$)").unwrap(),
        // Incoming Mail Token (no group -> wrap)
        Regex::new(r"(glimt-[A-Za-z0-9_-]{25})(?:\W|$)").unwrap(),
        // Trigger Token (no group -> wrap)
        Regex::new(r"(glptt-[A-Za-z0-9_-]{40})(?:\W|$)").unwrap(),
        // Agent Token (no group -> wrap)
        Regex::new(r"(glagent-[A-Za-z0-9_-]{50,1024})(?:\W|$)").unwrap(),
        // GitLab OAuth Application Secret (no group -> wrap)
        Regex::new(r"(gloas-[A-Za-z0-9_-]{64})(?:\W|$)").unwrap(),
    ]
});

static JWT_TOKEN_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*?").unwrap()]
});

static PRIVATE_KEY_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"BEGIN DSA PRIVATE KEY").unwrap(),
        Regex::new(r"BEGIN EC PRIVATE KEY").unwrap(),
        Regex::new(r"BEGIN OPENSSH PRIVATE KEY").unwrap(),
        Regex::new(r"BEGIN PGP PRIVATE KEY BLOCK").unwrap(),
        Regex::new(r"BEGIN PRIVATE KEY").unwrap(),
        Regex::new(r"BEGIN RSA PRIVATE KEY").unwrap(),
        Regex::new(r"BEGIN SSH2 ENCRYPTED PRIVATE KEY").unwrap(),
        Regex::new(r"PuTTY-User-Key-File-2").unwrap(),
    ]
});

// ---------------------------------------------------------------------------
// BasicAuthDetector
// ---------------------------------------------------------------------------

/// Detects Basic Auth credentials in URIs (`://user:password@host`).
///
/// Matches Python's `detect_secrets.plugins.basic_auth.BasicAuthDetector`.
#[derive(Clone)]
pub struct BasicAuthDetector {
    patterns: Vec<Regex>,
}

impl BasicAuthDetector {
    pub fn new() -> Self {
        Self {
            patterns: BASIC_AUTH_DENYLIST.clone(),
        }
    }
}

impl Default for BasicAuthDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for BasicAuthDetector {
    fn secret_type(&self) -> &str {
        "Basic Auth Credentials"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "BasicAuthDetector" })
    }
}

impl RegexBasedDetector for BasicAuthDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// DiscordBotTokenDetector
// ---------------------------------------------------------------------------

/// Detects Discord Bot tokens.
///
/// Matches Python's `detect_secrets.plugins.discord.DiscordBotTokenDetector`.
#[derive(Clone)]
pub struct DiscordBotTokenDetector {
    patterns: Vec<Regex>,
}

impl DiscordBotTokenDetector {
    pub fn new() -> Self {
        Self {
            patterns: DISCORD_BOT_TOKEN_DENYLIST.clone(),
        }
    }
}

impl Default for DiscordBotTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for DiscordBotTokenDetector {
    fn secret_type(&self) -> &str {
        "Discord Bot Token"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "DiscordBotTokenDetector" })
    }
}

impl RegexBasedDetector for DiscordBotTokenDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// GitHubTokenDetector
// ---------------------------------------------------------------------------

/// Detects GitHub tokens (PAT, OAuth, etc.).
///
/// Matches Python's `detect_secrets.plugins.github_token.GitHubTokenDetector`.
#[derive(Clone)]
pub struct GitHubTokenDetector {
    patterns: Vec<Regex>,
}

impl GitHubTokenDetector {
    pub fn new() -> Self {
        Self {
            patterns: GITHUB_TOKEN_DENYLIST.clone(),
        }
    }
}

impl Default for GitHubTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for GitHubTokenDetector {
    fn secret_type(&self) -> &str {
        "GitHub Token"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "GitHubTokenDetector" })
    }
}

impl RegexBasedDetector for GitHubTokenDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// GitLabTokenDetector
// ---------------------------------------------------------------------------

/// Detects GitLab tokens (PAT, deploy, runner, CI/CD, etc.).
///
/// Matches Python's `detect_secrets.plugins.gitlab_token.GitLabTokenDetector`.
///
/// Note: Python patterns use `(?!\w)` negative lookahead which Rust regex
/// doesn't support. For patterns WITHOUT capture groups we wrap the token
/// in `(...)` and append `(?:\W|$)` so `regex_analyze_string` returns
/// just the token via group 1. For patterns WITH existing groups the
/// consuming boundary doesn't affect the captured value.
#[derive(Clone)]
pub struct GitLabTokenDetector {
    patterns: Vec<Regex>,
}

impl GitLabTokenDetector {
    pub fn new() -> Self {
        Self {
            patterns: GITLAB_TOKEN_DENYLIST.clone(),
        }
    }
}

impl Default for GitLabTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for GitLabTokenDetector {
    fn secret_type(&self) -> &str {
        "GitLab Token"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "GitLabTokenDetector" })
    }
}

impl RegexBasedDetector for GitLabTokenDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// JwtTokenDetector
// ---------------------------------------------------------------------------

/// Detects JSON Web Tokens.
///
/// Matches Python's `detect_secrets.plugins.jwt.JwtTokenDetector`.
///
/// Overrides the default `analyze_string` to filter regex matches through
/// `is_formally_valid()` — checking base64 URL-safe decoding and JSON
/// validity of header/payload parts.
#[derive(Clone)]
pub struct JwtTokenDetector {
    patterns: Vec<Regex>,
}

impl JwtTokenDetector {
    pub fn new() -> Self {
        Self {
            patterns: JWT_TOKEN_DENYLIST.clone(),
        }
    }

    /// Validate that a token string is a well-formed JWT.
    ///
    /// Checks:
    /// 1. Each dot-separated part can be base64-url-safe decoded.
    /// 2. The first two parts (header and payload) are valid JSON.
    ///
    /// Matches Python's `JwtTokenDetector.is_formally_valid()`.
    pub fn is_formally_valid(token: &str) -> bool {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let parts: Vec<&str> = token.split('.').collect();

        for (idx, part_str) in parts.iter().enumerate() {
            let part = part_str.as_bytes();
            let m = part.len() % 4;
            if m == 1 {
                return false; // Incorrect padding
            }

            // Pad to valid base64 length
            let mut padded = part.to_vec();
            if m == 2 {
                padded.extend_from_slice(b"==");
            } else if m == 3 {
                padded.extend_from_slice(b"=");
            }

            // Remove any existing `=` padding before decoding with NO_PAD engine,
            // or just use the padded version with standard URL_SAFE.
            // The NO_PAD engine rejects `=`, so strip them and use NO_PAD:
            let stripped: Vec<u8> = padded.into_iter().filter(|&b| b != b'=').collect();
            // Re-pad to multiple of 4 for URL_SAFE_NO_PAD
            let decoded = match URL_SAFE_NO_PAD.decode(&stripped) {
                Ok(d) => d,
                Err(_) => return false,
            };

            // First two parts must be valid JSON
            if idx < 2 {
                if let Ok(s) = std::str::from_utf8(&decoded) {
                    if serde_json::from_str::<serde_json::Value>(s).is_err() {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }

        true
    }
}

impl Default for JwtTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for JwtTokenDetector {
    fn secret_type(&self) -> &str {
        "JSON Web Token"
    }

    /// Custom analyze_string that filters regex matches through JWT validation.
    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
            .into_iter()
            .filter(|token| Self::is_formally_valid(token))
            .collect()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "JwtTokenDetector" })
    }
}

impl RegexBasedDetector for JwtTokenDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// PrivateKeyDetector
// ---------------------------------------------------------------------------

/// Detects private key file headers (PEM, PuTTY, SSH2).
///
/// Matches Python's `detect_secrets.plugins.private_key.PrivateKeyDetector`.
#[derive(Clone)]
pub struct PrivateKeyDetector {
    patterns: Vec<Regex>,
}

impl PrivateKeyDetector {
    pub fn new() -> Self {
        Self {
            patterns: PRIVATE_KEY_DENYLIST.clone(),
        }
    }
}

impl Default for PrivateKeyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for PrivateKeyDetector {
    fn secret_type(&self) -> &str {
        "Private Key"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "PrivateKeyDetector" })
    }
}

impl RegexBasedDetector for PrivateKeyDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===== BasicAuthDetector =====

    #[test]
    fn test_basic_auth_https() {
        let d = BasicAuthDetector::default();
        let matches = d.analyze_string("https://user:hunter2@example.com");
        assert_eq!(matches, vec!["hunter2"]);
    }

    #[test]
    fn test_basic_auth_http() {
        let d = BasicAuthDetector::default();
        let matches = d.analyze_string("http://admin:p4ssw0rd@db.local:5432/mydb");
        assert_eq!(matches, vec!["p4ssw0rd"]);
    }

    #[test]
    fn test_basic_auth_ftp() {
        let d = BasicAuthDetector::default();
        let matches = d.analyze_string("ftp://deploy:s3cret@files.example.com/pub");
        assert_eq!(matches, vec!["s3cret"]);
    }

    #[test]
    fn test_basic_auth_no_match_no_password() {
        let d = BasicAuthDetector::default();
        let matches = d.analyze_string("https://example.com/path");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_basic_auth_no_match_no_protocol() {
        let d = BasicAuthDetector::default();
        // No :// scheme
        let matches = d.analyze_string("user:password@host");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_basic_auth_excludes_reserved_chars() {
        let d = BasicAuthDetector::default();
        // Password should not contain reserved chars like '/'
        let matches = d.analyze_string("https://user:pass/word@example.com");
        assert!(matches.is_empty() || !matches[0].contains('/'));
    }

    #[test]
    fn test_basic_auth_analyze_line() {
        let d = BasicAuthDetector::default();
        let secrets = d.analyze_line("config.py", "URL = 'https://admin:s3cret@db.local'", 5);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, "Basic Auth Credentials");
        assert_eq!(secrets[0].filename, "config.py");
        assert_eq!(secrets[0].line_number, 5);
    }

    // ===== DiscordBotTokenDetector =====

    #[test]
    fn test_discord_bot_token_match() {
        let d = DiscordBotTokenDetector::default();
        // M + 24 chars . 6 chars . 27 chars
        let token = format!("M{}.{}.{}", "a".repeat(24), "b".repeat(6), "c".repeat(27));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_discord_bot_token_starts_with_n() {
        let d = DiscordBotTokenDetector::default();
        let token = format!("N{}.{}.{}", "x".repeat(23), "y".repeat(6), "z".repeat(27));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_discord_bot_token_starts_with_o() {
        let d = DiscordBotTokenDetector::default();
        let token = format!("O{}.{}.{}", "x".repeat(25), "y".repeat(6), "z".repeat(27));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_discord_bot_token_no_match_wrong_prefix() {
        let d = DiscordBotTokenDetector::default();
        let token = format!("A{}.{}.{}", "a".repeat(24), "b".repeat(6), "c".repeat(27));
        let matches = d.analyze_string(&token);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_discord_bot_token_no_match_random() {
        let d = DiscordBotTokenDetector::default();
        let matches = d.analyze_string("just some random text");
        assert!(matches.is_empty());
    }

    // ===== GitHubTokenDetector =====

    #[test]
    fn test_github_pat() {
        let d = GitHubTokenDetector::default();
        let token = format!("ghp_{}", "A".repeat(36));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        // Capture group returns just the prefix
        assert_eq!(matches[0], "ghp");
    }

    #[test]
    fn test_github_oauth() {
        let d = GitHubTokenDetector::default();
        let token = format!("gho_{}", "B".repeat(36));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "gho");
    }

    #[test]
    fn test_github_user_to_server() {
        let d = GitHubTokenDetector::default();
        let token = format!("ghu_{}", "C".repeat(36));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "ghu");
    }

    #[test]
    fn test_github_server_to_server() {
        let d = GitHubTokenDetector::default();
        let token = format!("ghs_{}", "D".repeat(36));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "ghs");
    }

    #[test]
    fn test_github_refresh() {
        let d = GitHubTokenDetector::default();
        let token = format!("ghr_{}", "E".repeat(36));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "ghr");
    }

    #[test]
    fn test_github_no_match_wrong_prefix() {
        let d = GitHubTokenDetector::default();
        let token = format!("ghx_{}", "A".repeat(36));
        let matches = d.analyze_string(&token);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_github_no_match_too_short() {
        let d = GitHubTokenDetector::default();
        let token = format!("ghp_{}", "A".repeat(35));
        let matches = d.analyze_string(&token);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_github_no_match_random() {
        let d = GitHubTokenDetector::default();
        let matches = d.analyze_string("nothing here");
        assert!(matches.is_empty());
    }

    // ===== GitLabTokenDetector =====

    #[test]
    fn test_gitlab_pat() {
        let d = GitLabTokenDetector::default();
        let token = format!("glpat-{} ", "A".repeat(20));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "glpat");
    }

    #[test]
    fn test_gitlab_deploy_token() {
        let d = GitLabTokenDetector::default();
        let token = format!("gldt-{} ", "B".repeat(30));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "gldt");
    }

    #[test]
    fn test_gitlab_runner_registration() {
        let d = GitLabTokenDetector::default();
        let token = format!("GR1348941{} ", "C".repeat(20));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].starts_with("GR1348941"));
    }

    #[test]
    fn test_gitlab_incoming_mail_token() {
        let d = GitLabTokenDetector::default();
        let token = format!("glimt-{} ", "D".repeat(25));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].starts_with("glimt-"));
    }

    #[test]
    fn test_gitlab_trigger_token() {
        let d = GitLabTokenDetector::default();
        let token = format!("glptt-{} ", "E".repeat(40));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].starts_with("glptt-"));
    }

    #[test]
    fn test_gitlab_oauth_app_secret() {
        let d = GitLabTokenDetector::default();
        let token = format!("gloas-{} ", "F".repeat(64));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].starts_with("gloas-"));
    }

    #[test]
    fn test_gitlab_no_match_random() {
        let d = GitLabTokenDetector::default();
        let matches = d.analyze_string("just some random text");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_gitlab_boundary_end_of_string() {
        let d = GitLabTokenDetector::default();
        // Token at end of string (no trailing space)
        let token = format!("GR1348941{}", "A".repeat(20));
        let matches = d.analyze_string(&token);
        assert_eq!(matches.len(), 1);
    }

    // ===== JwtTokenDetector =====

    #[test]
    fn test_jwt_valid_token() {
        let d = JwtTokenDetector::default();
        // eyJ... is base64url for {"
        // Header: {"alg":"HS256","typ":"JWT"}
        // base64url: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        // Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
        // base64url: eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
        // Signature: SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let matches = d.analyze_string(token);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_jwt_invalid_base64_filtered_out() {
        let d = JwtTokenDetector::default();
        // Starts with eyJ but is not valid JWT
        let fake = "eyJ!!!.eyJ!!!.sig";
        let matches = d.analyze_string(fake);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_jwt_no_match_random() {
        let d = JwtTokenDetector::default();
        let matches = d.analyze_string("not a jwt token");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_jwt_is_formally_valid_good_token() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(JwtTokenDetector::is_formally_valid(token));
    }

    #[test]
    fn test_jwt_is_formally_valid_bad_json() {
        // base64url("not json") = "bm90IGpzb24"  — starts with b, not eyJ
        // Let's construct something that starts with eyJ but has bad JSON
        // eyJ = base64url of {"  — we need more to form invalid JSON
        // eyJhYmM = {"abc  — not valid JSON (no closing brace/quotes)
        // Actually the regex requires eyJ prefix so the header starts with {"
        // If the header is just {"abc without closing, JSON parse fails
        assert!(!JwtTokenDetector::is_formally_valid("eyJhYmM.eyJhYmM.sig"));
    }

    #[test]
    fn test_jwt_is_formally_valid_bad_padding() {
        // A single base64 character has length%4 == 1, which is invalid
        assert!(!JwtTokenDetector::is_formally_valid("a.b.c"));
    }

    // ===== PrivateKeyDetector =====

    #[test]
    fn test_private_key_rsa() {
        let d = PrivateKeyDetector::default();
        let matches = d.analyze_string("-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(matches, vec!["BEGIN RSA PRIVATE KEY"]);
    }

    #[test]
    fn test_private_key_dsa() {
        let d = PrivateKeyDetector::default();
        let matches = d.analyze_string("-----BEGIN DSA PRIVATE KEY-----");
        assert_eq!(matches, vec!["BEGIN DSA PRIVATE KEY"]);
    }

    #[test]
    fn test_private_key_ec() {
        let d = PrivateKeyDetector::default();
        let matches = d.analyze_string("-----BEGIN EC PRIVATE KEY-----");
        assert_eq!(matches, vec!["BEGIN EC PRIVATE KEY"]);
    }

    #[test]
    fn test_private_key_openssh() {
        let d = PrivateKeyDetector::default();
        let matches = d.analyze_string("-----BEGIN OPENSSH PRIVATE KEY-----");
        assert_eq!(matches, vec!["BEGIN OPENSSH PRIVATE KEY"]);
    }

    #[test]
    fn test_private_key_pgp() {
        let d = PrivateKeyDetector::default();
        let matches = d.analyze_string("-----BEGIN PGP PRIVATE KEY BLOCK-----");
        assert_eq!(matches, vec!["BEGIN PGP PRIVATE KEY BLOCK"]);
    }

    #[test]
    fn test_private_key_generic() {
        let d = PrivateKeyDetector::default();
        let matches = d.analyze_string("-----BEGIN PRIVATE KEY-----");
        assert_eq!(matches, vec!["BEGIN PRIVATE KEY"]);
    }

    #[test]
    fn test_private_key_ssh2() {
        let d = PrivateKeyDetector::default();
        let matches = d.analyze_string("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----");
        assert_eq!(matches, vec!["BEGIN SSH2 ENCRYPTED PRIVATE KEY"]);
    }

    #[test]
    fn test_private_key_putty() {
        let d = PrivateKeyDetector::default();
        let matches = d.analyze_string("PuTTY-User-Key-File-2: ssh-rsa");
        assert_eq!(matches, vec!["PuTTY-User-Key-File-2"]);
    }

    #[test]
    fn test_private_key_no_match() {
        let d = PrivateKeyDetector::default();
        let matches = d.analyze_string("just some normal text");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_private_key_analyze_line() {
        let d = PrivateKeyDetector::default();
        let secrets = d.analyze_line("key.pem", "-----BEGIN RSA PRIVATE KEY-----", 1);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, "Private Key");
        assert_eq!(secrets[0].filename, "key.pem");
        assert_eq!(secrets[0].line_number, 1);
    }

    // ===== Secret type and JSON tests =====

    #[test]
    fn test_all_secret_types() {
        assert_eq!(
            BasicAuthDetector::default().secret_type(),
            "Basic Auth Credentials"
        );
        assert_eq!(
            DiscordBotTokenDetector::default().secret_type(),
            "Discord Bot Token"
        );
        assert_eq!(GitHubTokenDetector::default().secret_type(), "GitHub Token");
        assert_eq!(GitLabTokenDetector::default().secret_type(), "GitLab Token");
        assert_eq!(JwtTokenDetector::default().secret_type(), "JSON Web Token");
        assert_eq!(PrivateKeyDetector::default().secret_type(), "Private Key");
    }

    #[test]
    fn test_all_json_names() {
        assert_eq!(
            BasicAuthDetector::default().json()["name"],
            "BasicAuthDetector"
        );
        assert_eq!(
            DiscordBotTokenDetector::default().json()["name"],
            "DiscordBotTokenDetector"
        );
        assert_eq!(
            GitHubTokenDetector::default().json()["name"],
            "GitHubTokenDetector"
        );
        assert_eq!(
            GitLabTokenDetector::default().json()["name"],
            "GitLabTokenDetector"
        );
        assert_eq!(
            JwtTokenDetector::default().json()["name"],
            "JwtTokenDetector"
        );
        assert_eq!(
            PrivateKeyDetector::default().json()["name"],
            "PrivateKeyDetector"
        );
    }
}
