//! Core data model for detected secrets.
//!
//! This module implements [`PotentialSecret`], the fundamental data structure
//! used to store and compare scan results. It mirrors the Python
//! `detect_secrets.core.potential_secret.PotentialSecret` class.

use std::hash::{Hash, Hasher};

use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};

/// Compute the SHA-1 hex digest of a secret string (UTF-8 encoded).
///
/// Matches Python's `hashlib.sha1(secret.encode('utf-8')).hexdigest()`.
pub fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// A potential secret found during scanning.
///
/// Identity is determined by `(filename, secret_hash, secret_type)` — these
/// three fields are used for equality comparison and hashing.  Other fields
/// like `line_number`, `is_secret`, and `is_verified` are metadata that can
/// change between runs without affecting identity.
#[derive(Debug, Clone)]
pub struct PotentialSecret {
    /// The type of secret (e.g. "High Entropy String", "AWS Access Key").
    pub secret_type: String,
    /// The filename where the secret was found.
    pub filename: String,
    /// SHA-1 hex digest of the plaintext secret.
    pub secret_hash: String,
    /// Line number in the file (0 means unknown/unset).
    pub line_number: u64,
    /// Whether this secret is a true positive (`Some(true)`), false positive
    /// (`Some(false)`), or unknown (`None`).
    pub is_secret: Option<bool>,
    /// Whether the secret has been externally verified.
    pub is_verified: bool,
    /// The plaintext secret value – kept in memory for verification but
    /// **never** serialized to baseline files.
    pub secret_value: Option<String>,
}

impl PotentialSecret {
    /// Create a new `PotentialSecret`, hashing the plaintext secret.
    pub fn new(
        secret_type: impl Into<String>,
        filename: impl Into<String>,
        secret: impl AsRef<str>,
        line_number: u64,
        is_secret: Option<bool>,
        is_verified: bool,
    ) -> Self {
        let secret_str = secret.as_ref();
        Self {
            secret_type: secret_type.into(),
            filename: filename.into(),
            secret_hash: hash_secret(secret_str),
            line_number,
            is_secret,
            is_verified,
            secret_value: Some(secret_str.to_string()),
        }
    }

    /// Serialize to a JSON dict matching Python's `PotentialSecret.json()`.
    ///
    /// Key differences from internal field names:
    /// - `secret_hash` → `"hashed_secret"` in JSON
    /// - `secret_type` → `"type"` in JSON
    /// - `line_number` is omitted when 0
    /// - `is_secret` is omitted when `None`
    /// - `secret_value` is **never** included
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("type".to_string(), json!(self.secret_type));
        map.insert("filename".to_string(), json!(self.filename));
        map.insert("hashed_secret".to_string(), json!(self.secret_hash));
        map.insert("is_verified".to_string(), json!(self.is_verified));
        if self.line_number != 0 {
            map.insert("line_number".to_string(), json!(self.line_number));
        }
        if let Some(is_secret) = self.is_secret {
            map.insert("is_secret".to_string(), json!(is_secret));
        }
        Value::Object(map)
    }

    /// Deserialize from a JSON dict (baseline format).
    ///
    /// Matches Python's `PotentialSecret.load_secret_from_dict(data)`.
    /// The `secret_value` is set to `None` since the plaintext is not stored
    /// in baseline files.
    pub fn load_from_dict(data: &Value) -> Result<Self, String> {
        let obj = data.as_object().ok_or("expected JSON object")?;

        let secret_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or("missing 'type' field")?
            .to_string();

        let filename = obj
            .get("filename")
            .and_then(|v| v.as_str())
            .ok_or("missing 'filename' field")?
            .to_string();

        let secret_hash = obj
            .get("hashed_secret")
            .and_then(|v| v.as_str())
            .ok_or("missing 'hashed_secret' field")?
            .to_string();

        let line_number = obj.get("line_number").and_then(|v| v.as_u64()).unwrap_or(0);

        let is_secret = obj.get("is_secret").and_then(|v| v.as_bool());

        let is_verified = obj
            .get("is_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(Self {
            secret_type,
            filename,
            secret_hash,
            line_number,
            is_secret,
            is_verified,
            secret_value: None,
        })
    }
}

/// Equality is based on `(filename, secret_hash, secret_type)` only,
/// matching Python's `fields_to_compare`.
impl PartialEq for PotentialSecret {
    fn eq(&self, other: &Self) -> bool {
        self.filename == other.filename
            && self.secret_hash == other.secret_hash
            && self.secret_type == other.secret_type
    }
}

impl Eq for PotentialSecret {}

/// Hash is based on `(filename, secret_hash, secret_type)` only,
/// consistent with `PartialEq`.
impl Hash for PotentialSecret {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.filename.hash(state);
        self.secret_hash.hash(state);
        self.secret_type.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_secret_sha1() {
        // Verified against Python: hashlib.sha1(b"my_secret").hexdigest()
        assert_eq!(
            hash_secret("my_secret"),
            "7585d1f7ceb90fd0b1ab42d0a6ca39fcf55065c7"
        );
    }

    #[test]
    fn test_hash_secret_empty_string() {
        // hashlib.sha1(b"").hexdigest()
        assert_eq!(hash_secret(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_new_sets_hash_and_value() {
        let secret = PotentialSecret::new("type", "file.py", "password123", 1, None, false);
        assert_eq!(secret.secret_hash, hash_secret("password123"));
        assert_eq!(secret.secret_value.as_deref(), Some("password123"));
    }

    #[test]
    fn test_equality_same_identity() {
        let s1 = PotentialSecret::new("type", "file.py", "secret", 1, None, false);
        let s2 = PotentialSecret::new("type", "file.py", "secret", 2, Some(true), true);
        // Same (filename, secret_hash, type) → equal despite different line/flags
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_inequality_different_type() {
        let s1 = PotentialSecret::new("TypeA", "file.py", "secret", 1, None, false);
        let s2 = PotentialSecret::new("TypeB", "file.py", "secret", 1, None, false);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_inequality_different_filename() {
        let s1 = PotentialSecret::new("type", "a.py", "secret", 1, None, false);
        let s2 = PotentialSecret::new("type", "b.py", "secret", 1, None, false);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_inequality_different_secret() {
        let s1 = PotentialSecret::new("type", "file.py", "alpha", 1, None, false);
        let s2 = PotentialSecret::new("type", "file.py", "beta", 1, None, false);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_hashset_dedup() {
        use std::collections::HashSet;
        let s1 = PotentialSecret::new("type", "file.py", "secret", 1, None, false);
        let s2 = PotentialSecret::new("type", "file.py", "secret", 99, Some(true), true);
        let mut set = HashSet::new();
        set.insert(s1);
        set.insert(s2);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_to_json_full() {
        let secret =
            PotentialSecret::new("Basic Auth", "config.py", "hunter2", 42, Some(true), false);
        let j = secret.to_json();
        assert_eq!(j["type"], "Basic Auth");
        assert_eq!(j["filename"], "config.py");
        assert_eq!(j["hashed_secret"], hash_secret("hunter2"));
        assert_eq!(j["is_verified"], false);
        assert_eq!(j["line_number"], 42);
        assert_eq!(j["is_secret"], true);
        // secret_value must NOT be in JSON
        assert!(j.get("secret_value").is_none());
    }

    #[test]
    fn test_to_json_omits_zero_line_and_none_is_secret() {
        let secret = PotentialSecret::new("type", "file.py", "s", 0, None, false);
        let j = secret.to_json();
        assert!(j.get("line_number").is_none());
        assert!(j.get("is_secret").is_none());
    }

    #[test]
    fn test_load_from_dict() {
        let data = json!({
            "type": "High Entropy String",
            "filename": "app.py",
            "hashed_secret": "abc123",
            "is_verified": true,
            "line_number": 10,
            "is_secret": false,
        });
        let secret = PotentialSecret::load_from_dict(&data).unwrap();
        assert_eq!(secret.secret_type, "High Entropy String");
        assert_eq!(secret.filename, "app.py");
        assert_eq!(secret.secret_hash, "abc123");
        assert_eq!(secret.line_number, 10);
        assert_eq!(secret.is_secret, Some(false));
        assert!(secret.is_verified);
        assert!(secret.secret_value.is_none());
    }

    #[test]
    fn test_load_from_dict_minimal() {
        let data = json!({
            "type": "type",
            "filename": "file",
            "hashed_secret": "hash",
        });
        let secret = PotentialSecret::load_from_dict(&data).unwrap();
        assert_eq!(secret.line_number, 0);
        assert_eq!(secret.is_secret, None);
        assert!(!secret.is_verified);
    }

    #[test]
    fn test_json_round_trip_preserves_equality() {
        let original = PotentialSecret::new("type", "file.py", "secret", 5, Some(true), false);
        let j = original.to_json();
        let restored = PotentialSecret::load_from_dict(&j).unwrap();
        assert_eq!(original, restored);
        // Restored from baseline should NOT have plaintext
        assert!(restored.secret_value.is_none());
    }

    #[test]
    fn test_load_from_dict_missing_type() {
        let data = json!({"filename": "f", "hashed_secret": "h"});
        assert!(PotentialSecret::load_from_dict(&data).is_err());
    }

    #[test]
    fn test_load_from_dict_missing_filename() {
        let data = json!({"type": "t", "hashed_secret": "h"});
        assert!(PotentialSecret::load_from_dict(&data).is_err());
    }

    #[test]
    fn test_load_from_dict_missing_hashed_secret() {
        let data = json!({"type": "t", "filename": "f"});
        assert!(PotentialSecret::load_from_dict(&data).is_err());
    }
}
