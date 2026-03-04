//! Cloud and infrastructure secret detectors.
//!
//! Ports of the following Python detect-secrets plugins:
//! - [`AWSKeyDetector`] — AWS access key IDs and secret tokens
//! - [`AzureStorageKeyDetector`] — Azure Storage Account access keys
//! - [`ArtifactoryDetector`] — JFrog Artifactory tokens and encrypted passwords
//! - [`CloudantDetector`] — IBM Cloudant credentials
//! - [`IbmCloudIamDetector`] — IBM Cloud IAM keys
//! - [`IbmCosHmacDetector`] — IBM Cloud Object Storage HMAC credentials
//! - [`SoftlayerDetector`] — SoftLayer/IBM Classic Infrastructure credentials

use once_cell::sync::Lazy;
use regex::Regex;

use crate::plugin::{
    build_assignment_regex, regex_analyze_string, RegexBasedDetector, SecretDetector,
};

// ---------------------------------------------------------------------------
// Cached compiled regex denylists
// ---------------------------------------------------------------------------

static AWS_KEY_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // AWS Key ID prefixes: A3T*, ABIA, ACCA, AKIA, ASIA followed by 16 uppercase alphanumeric
        Regex::new(r"(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}").unwrap(),
        // AWS secret access key in assignment context (capture group for the 40-char key)
        Regex::new(
            r#"(?i)aws.{0,20}?(?:key|pwd|pw|password|pass|token).{0,20}?['"]([0-9a-zA-Z/+]{40})['"]"#,
        )
        .unwrap(),
    ]
});

static AZURE_STORAGE_KEY_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // AccountKey=<88 base64 chars>
        Regex::new(r"AccountKey=[a-zA-Z0-9+/=]{88}").unwrap(),
    ]
});

static ARTIFACTORY_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // API tokens begin with AKC
        Regex::new(r#"(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}(?:\s|"|$)"#).unwrap(),
        // Encrypted passwords begin with AP[0-9A-F]
        Regex::new(r#"(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|"|$)"#).unwrap(),
    ]
});

static CLOUDANT_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    let cl = r"(?:cloudant|cl|clou)";
    let cl_key_or_pass = r"(?:api|)(?:key|pwd|pw|password|pass|token)";
    let cl_pw = r"([0-9a-f]{64})";
    let cl_api_key = r"([a-z]{24})";

    let mut patterns = Vec::new();

    // Assignment regex for 64-char hex password
    if let Some(r) = build_assignment_regex(cl, cl_key_or_pass, cl_pw) {
        patterns.push(r);
    }

    // Assignment regex for 24-char lowercase API key
    if let Some(r) = build_assignment_regex(cl, cl_key_or_pass, cl_api_key) {
        patterns.push(r);
    }

    // URL pattern with 64-char hex password
    patterns.push(
        Regex::new(r"(?i)(?:https?://)[\w\-]+:([0-9a-f]{64})@[\w\-]+\.cloudant\.com").unwrap(),
    );

    // URL pattern with 24-char API key
    patterns
        .push(Regex::new(r"(?i)(?:https?://)[\w\-]+:([a-z]{24})@[\w\-]+\.cloudant\.com").unwrap());

    patterns
});

static IBM_CLOUD_IAM_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    let opt_ibm_cloud_iam = r"(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)";
    let opt_dash_underscore = r"(?:_|-|)";
    let opt_api = r"(?:api|)";
    let key_or_pass = r"(?:key|pwd|password|pass|token)";
    // Rust regex doesn't support negative lookahead (?!...).
    // Use a non-capturing boundary group instead:
    // Match exactly 44 chars followed by a non-token char or end-of-string.
    let secret = r"([a-zA-Z0-9_\-]{44})(?:[^a-zA-Z0-9_\-]|$)";

    let prefix = &format!("{opt_ibm_cloud_iam}{opt_dash_underscore}{opt_api}");

    let mut patterns = Vec::new();
    if let Some(r) = build_assignment_regex(prefix, key_or_pass, secret) {
        patterns.push(r);
    }

    patterns
});

static IBM_COS_HMAC_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    let token_prefix = r"(?:(?:ibm)?[-_]?cos[-_]?(?:hmac)?|)";
    let password_keyword = r"(?:secret[-_]?(?:access)?[-_]?key)";
    // Replace negative lookahead with boundary assertion.
    let password = r"([a-f0-9]{48})(?:[^a-f0-9]|$)";

    let mut patterns = Vec::new();
    if let Some(r) = build_assignment_regex(token_prefix, password_keyword, password) {
        patterns.push(r);
    }

    patterns
});

static SOFTLAYER_DENYLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    let sl = r"(?:softlayer|sl)(?:_|-|)(?:api|)";
    let key_or_pass = r"(?:key|pwd|password|pass|token)";
    let secret = r"([a-z0-9]{64})";

    let mut patterns = Vec::new();

    // Assignment regex
    if let Some(r) = build_assignment_regex(sl, key_or_pass, secret) {
        patterns.push(r);
    }

    // URL pattern for SoftLayer SOAP API
    patterns.push(
        Regex::new(r"(?i)(?:https?://)?api\.softlayer\.com/soap/(?:v3|v3\.1)/([a-z0-9]{64})")
            .unwrap(),
    );

    patterns
});

// ---------------------------------------------------------------------------
// AWSKeyDetector
// ---------------------------------------------------------------------------

/// Detects AWS access key IDs and secret tokens.
///
/// Matches Python's `detect_secrets.plugins.aws.AWSKeyDetector`.
#[derive(Clone)]
pub struct AWSKeyDetector {
    patterns: Vec<Regex>,
}

impl AWSKeyDetector {
    pub fn new() -> Self {
        Self {
            patterns: AWS_KEY_DENYLIST.clone(),
        }
    }
}

impl Default for AWSKeyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for AWSKeyDetector {
    fn secret_type(&self) -> &str {
        "AWS Access Key"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "AWSKeyDetector" })
    }
}

impl RegexBasedDetector for AWSKeyDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// AzureStorageKeyDetector
// ---------------------------------------------------------------------------

/// Detects Azure Storage Account access keys.
///
/// Matches Python's `detect_secrets.plugins.azure_storage_key.AzureStorageKeyDetector`.
#[derive(Clone)]
pub struct AzureStorageKeyDetector {
    patterns: Vec<Regex>,
}

impl AzureStorageKeyDetector {
    pub fn new() -> Self {
        Self {
            patterns: AZURE_STORAGE_KEY_DENYLIST.clone(),
        }
    }
}

impl Default for AzureStorageKeyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for AzureStorageKeyDetector {
    fn secret_type(&self) -> &str {
        "Azure Storage Account access key"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "AzureStorageKeyDetector" })
    }
}

impl RegexBasedDetector for AzureStorageKeyDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// ArtifactoryDetector
// ---------------------------------------------------------------------------

/// Detects JFrog Artifactory API tokens and encrypted passwords.
///
/// Matches Python's `detect_secrets.plugins.artifactory.ArtifactoryDetector`.
#[derive(Clone)]
pub struct ArtifactoryDetector {
    patterns: Vec<Regex>,
}

impl ArtifactoryDetector {
    pub fn new() -> Self {
        Self {
            patterns: ARTIFACTORY_DENYLIST.clone(),
        }
    }
}

impl Default for ArtifactoryDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for ArtifactoryDetector {
    fn secret_type(&self) -> &str {
        "Artifactory Credentials"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "ArtifactoryDetector" })
    }
}

impl RegexBasedDetector for ArtifactoryDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// CloudantDetector
// ---------------------------------------------------------------------------

/// Detects IBM Cloudant credentials (64-char hex password or 24-char API key).
///
/// Matches Python's `detect_secrets.plugins.cloudant.CloudantDetector`.
#[derive(Clone)]
pub struct CloudantDetector {
    patterns: Vec<Regex>,
}

impl CloudantDetector {
    pub fn new() -> Self {
        Self {
            patterns: CLOUDANT_DENYLIST.clone(),
        }
    }
}

impl Default for CloudantDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for CloudantDetector {
    fn secret_type(&self) -> &str {
        "Cloudant Credentials"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "CloudantDetector" })
    }
}

impl RegexBasedDetector for CloudantDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// IbmCloudIamDetector
// ---------------------------------------------------------------------------

/// Detects IBM Cloud IAM API keys.
///
/// Matches Python's `detect_secrets.plugins.ibm_cloud_iam.IbmCloudIamDetector`.
#[derive(Clone)]
pub struct IbmCloudIamDetector {
    patterns: Vec<Regex>,
}

impl IbmCloudIamDetector {
    pub fn new() -> Self {
        Self {
            patterns: IBM_CLOUD_IAM_DENYLIST.clone(),
        }
    }
}

impl Default for IbmCloudIamDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for IbmCloudIamDetector {
    fn secret_type(&self) -> &str {
        "IBM Cloud IAM Key"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "IbmCloudIamDetector" })
    }
}

impl RegexBasedDetector for IbmCloudIamDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// IbmCosHmacDetector
// ---------------------------------------------------------------------------

/// Detects IBM Cloud Object Storage HMAC credentials.
///
/// Matches Python's `detect_secrets.plugins.ibm_cos_hmac.IbmCosHmacDetector`.
#[derive(Clone)]
pub struct IbmCosHmacDetector {
    patterns: Vec<Regex>,
}

impl IbmCosHmacDetector {
    pub fn new() -> Self {
        Self {
            patterns: IBM_COS_HMAC_DENYLIST.clone(),
        }
    }
}

impl Default for IbmCosHmacDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for IbmCosHmacDetector {
    fn secret_type(&self) -> &str {
        "IBM COS HMAC Credentials"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "IbmCosHmacDetector" })
    }
}

impl RegexBasedDetector for IbmCosHmacDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

// ---------------------------------------------------------------------------
// SoftlayerDetector
// ---------------------------------------------------------------------------

/// Detects SoftLayer/IBM Classic Infrastructure credentials.
///
/// Matches Python's `detect_secrets.plugins.softlayer.SoftlayerDetector`.
#[derive(Clone)]
pub struct SoftlayerDetector {
    patterns: Vec<Regex>,
}

impl SoftlayerDetector {
    pub fn new() -> Self {
        Self {
            patterns: SOFTLAYER_DENYLIST.clone(),
        }
    }
}

impl Default for SoftlayerDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for SoftlayerDetector {
    fn secret_type(&self) -> &str {
        "SoftLayer Credentials"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({ "name": "SoftlayerDetector" })
    }
}

impl RegexBasedDetector for SoftlayerDetector {
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

    // ===== AWSKeyDetector =====

    #[test]
    fn test_aws_key_id_akia() {
        let d = AWSKeyDetector::default();
        let matches = d.analyze_string("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(matches, vec!["AKIAIOSFODNN7EXAMPLE"]);
    }

    #[test]
    fn test_aws_key_id_asia() {
        let d = AWSKeyDetector::default();
        // ASIA + 16 uppercase alphanumeric = 20 chars total
        let matches = d.analyze_string("ASIAISAMPLEKEYID1234");
        assert_eq!(matches.len(), 1);
        assert!(matches[0].starts_with("ASIA"));
    }

    #[test]
    fn test_aws_key_id_a3t() {
        let d = AWSKeyDetector::default();
        let matches = d.analyze_string("A3TXSAMPLEKEYID12345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_aws_secret_in_assignment() {
        let d = AWSKeyDetector::default();
        let line = r#"aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""#;
        let matches = d.analyze_string(line);
        assert_eq!(matches, vec!["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]);
    }

    #[test]
    fn test_aws_no_match() {
        let d = AWSKeyDetector::default();
        let matches = d.analyze_string("just some random text here");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_aws_key_id_too_short() {
        let d = AWSKeyDetector::default();
        // AKIA + 16 uppercase alphanumeric chars = 20 total, should match
        let matches = d.analyze_string("AKIA1234567890ABCDEF");
        assert_eq!(matches.len(), 1);
        // AKIA + 15 chars = 19 total, should NOT match
        let matches = d.analyze_string("AKIA1234567890ABCDE");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_aws_analyze_line() {
        let d = AWSKeyDetector::default();
        let secrets = d.analyze_line("config.py", "KEY = 'AKIAIOSFODNN7EXAMPLE'", 10);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, "AWS Access Key");
        assert_eq!(secrets[0].filename, "config.py");
        assert_eq!(secrets[0].line_number, 10);
    }

    // ===== AzureStorageKeyDetector =====

    #[test]
    fn test_azure_storage_key_match() {
        let d = AzureStorageKeyDetector::default();
        let key88 = "A".repeat(88);
        let line = format!("AccountKey={key88}");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].starts_with("AccountKey="));
    }

    #[test]
    fn test_azure_storage_key_in_connection_string() {
        let d = AzureStorageKeyDetector::default();
        let key88 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuv==";
        assert_eq!(key88.len(), 88);
        let line = format!("DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey={key88};EndpointSuffix=core.windows.net");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_azure_storage_key_no_match() {
        let d = AzureStorageKeyDetector::default();
        let matches = d.analyze_string("AccountKey=tooshort");
        assert!(matches.is_empty());
    }

    // ===== ArtifactoryDetector =====

    #[test]
    fn test_artifactory_api_token() {
        let d = ArtifactoryDetector::default();
        let matches = d.analyze_string("AKCabcdefghij1234");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_artifactory_api_token_with_prefix() {
        let d = ArtifactoryDetector::default();
        let matches = d.analyze_string(r#"token = "AKCxyzxyzxyz1234""#);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_artifactory_encrypted_password() {
        let d = ArtifactoryDetector::default();
        let matches = d.analyze_string("AP6abcdefgh12");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_artifactory_encrypted_password_apb() {
        let d = ArtifactoryDetector::default();
        let matches = d.analyze_string("APBabcdefgh12");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_artifactory_no_match() {
        let d = ArtifactoryDetector::default();
        let matches = d.analyze_string("NORMAL_TEXT_HERE");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_artifactory_akc_too_short() {
        let d = ArtifactoryDetector::default();
        // AKC + 10 chars = match (minimum)
        let matches = d.analyze_string("AKCabcdefghij");
        assert_eq!(matches.len(), 1);
        // AKC + 9 chars = not enough
        let matches = d.analyze_string("AKCabcdefghi");
        assert!(matches.is_empty());
    }

    // ===== CloudantDetector =====

    #[test]
    fn test_cloudant_hex_password_assignment() {
        let d = CloudantDetector::default();
        // Use hex chars with digits to distinguish from 24-char lowercase pattern
        let pwd = "0123456789abcdef".repeat(4); // 64 hex chars
        let line = format!("cloudant_password = {pwd}");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], pwd);
    }

    #[test]
    fn test_cloudant_api_key_assignment() {
        let d = CloudantDetector::default();
        let key = "a".repeat(24);
        let line = format!("cloudant_key = {key}");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], key);
    }

    #[test]
    fn test_cloudant_url_with_hex_password() {
        let d = CloudantDetector::default();
        let pwd = "a".repeat(64);
        let line = format!("https://myuser:{pwd}@myaccount.cloudant.com");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], pwd);
    }

    #[test]
    fn test_cloudant_url_with_api_key() {
        let d = CloudantDetector::default();
        let key = "a".repeat(24);
        let line = format!("https://myuser:{key}@myaccount.cloudant.com");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], key);
    }

    #[test]
    fn test_cloudant_no_match() {
        let d = CloudantDetector::default();
        let matches = d.analyze_string("just some random cloudant text");
        assert!(matches.is_empty());
    }

    // ===== IbmCloudIamDetector =====

    #[test]
    fn test_ibm_cloud_iam_key_match() {
        let d = IbmCloudIamDetector::default();
        let key = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH";
        assert_eq!(key.len(), 44);
        let line = format!("ibm_cloud_iam_api_key = {key} ");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], key);
    }

    #[test]
    fn test_ibm_cloud_iam_key_with_dashes() {
        let d = IbmCloudIamDetector::default();
        let key = "abcdefghijkl-nopqrstuvwxyz_123456789ABCDEFGH";
        assert_eq!(key.len(), 44);
        let line = format!(r#"iam_key = "{key}""#);
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], key);
    }

    #[test]
    fn test_ibm_cloud_iam_no_match_too_long() {
        let d = IbmCloudIamDetector::default();
        // 50 chars — the boundary assertion should prevent matching the first 44
        // when followed by more alphanumeric chars
        let long_key = "a".repeat(50);
        let line = format!("ibm_cloud_iam_key = {long_key}");
        let matches = d.analyze_string(&line);
        // Should not match because the 45th char is still alphanumeric
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ibm_cloud_iam_no_match_random() {
        let d = IbmCloudIamDetector::default();
        let matches = d.analyze_string("just some random text");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ibm_cloud_iam_various_prefixes() {
        let d = IbmCloudIamDetector::default();
        let key = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH";
        for prefix in &[
            "ibm_cloud_iam_key",
            "cloud_iam_token",
            "ibm_cloud_key",
            "ibm_iam_pass",
            "ibm_key",
            "iam_token",
            "cloud_pass",
        ] {
            let line = format!("{prefix} = {key} ");
            let matches = d.analyze_string(&line);
            assert!(!matches.is_empty(), "Expected match for prefix '{prefix}'");
        }
    }

    // ===== IbmCosHmacDetector =====

    #[test]
    fn test_ibm_cos_hmac_secret_key() {
        let d = IbmCosHmacDetector::default();
        let secret = "a".repeat(48);
        let line = format!("cos_secret_access_key = {secret} ");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], secret);
    }

    #[test]
    fn test_ibm_cos_hmac_with_prefix() {
        let d = IbmCosHmacDetector::default();
        let secret = "0123456789abcdef".repeat(3); // 48 hex chars
        let line = format!("ibm_cos_hmac_secret_key = {secret} ");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ibm_cos_hmac_no_match_too_long() {
        let d = IbmCosHmacDetector::default();
        let long_secret = "a".repeat(52);
        let line = format!("cos_secret_key = {long_secret}");
        let matches = d.analyze_string(&line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ibm_cos_hmac_no_match() {
        let d = IbmCosHmacDetector::default();
        let matches = d.analyze_string("random text here");
        assert!(matches.is_empty());
    }

    // ===== SoftlayerDetector =====

    #[test]
    fn test_softlayer_assignment() {
        let d = SoftlayerDetector::default();
        let secret = "a".repeat(64);
        let line = format!("softlayer_api_key = {secret}");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], secret);
    }

    #[test]
    fn test_softlayer_sl_prefix() {
        let d = SoftlayerDetector::default();
        let secret = "a".repeat(64);
        let line = format!("sl_token = {secret}");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_softlayer_url_v3() {
        let d = SoftlayerDetector::default();
        let secret = "a".repeat(64);
        let line = format!("https://api.softlayer.com/soap/v3/{secret}");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], secret);
    }

    #[test]
    fn test_softlayer_url_v31() {
        let d = SoftlayerDetector::default();
        let secret = "b".repeat(64);
        let line = format!("http://api.softlayer.com/soap/v3.1/{secret}");
        let matches = d.analyze_string(&line);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], secret);
    }

    #[test]
    fn test_softlayer_no_match() {
        let d = SoftlayerDetector::default();
        let matches = d.analyze_string("nothing to see here");
        assert!(matches.is_empty());
    }

    // ===== Secret type and JSON tests =====

    #[test]
    fn test_all_secret_types() {
        assert_eq!(AWSKeyDetector::default().secret_type(), "AWS Access Key");
        assert_eq!(
            AzureStorageKeyDetector::default().secret_type(),
            "Azure Storage Account access key"
        );
        assert_eq!(
            ArtifactoryDetector::default().secret_type(),
            "Artifactory Credentials"
        );
        assert_eq!(
            CloudantDetector::default().secret_type(),
            "Cloudant Credentials"
        );
        assert_eq!(
            IbmCloudIamDetector::default().secret_type(),
            "IBM Cloud IAM Key"
        );
        assert_eq!(
            IbmCosHmacDetector::default().secret_type(),
            "IBM COS HMAC Credentials"
        );
        assert_eq!(
            SoftlayerDetector::default().secret_type(),
            "SoftLayer Credentials"
        );
    }

    #[test]
    fn test_all_json_names() {
        assert_eq!(AWSKeyDetector::default().json()["name"], "AWSKeyDetector");
        assert_eq!(
            AzureStorageKeyDetector::default().json()["name"],
            "AzureStorageKeyDetector"
        );
        assert_eq!(
            ArtifactoryDetector::default().json()["name"],
            "ArtifactoryDetector"
        );
        assert_eq!(
            CloudantDetector::default().json()["name"],
            "CloudantDetector"
        );
        assert_eq!(
            IbmCloudIamDetector::default().json()["name"],
            "IbmCloudIamDetector"
        );
        assert_eq!(
            IbmCosHmacDetector::default().json()["name"],
            "IbmCosHmacDetector"
        );
        assert_eq!(
            SoftlayerDetector::default().json()["name"],
            "SoftlayerDetector"
        );
    }
}
