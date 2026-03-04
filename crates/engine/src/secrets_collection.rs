//! SecretsCollection — aggregate storage for detected secrets.
//!
//! Ported from `detect_secrets.core.secrets_collection.SecretsCollection`.
//! Provides a `HashMap<String, HashSet<PotentialSecret>>` keyed by filename,
//! with merge, trim, subtraction, equality, and sorted iteration.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use crate::potential_secret::PotentialSecret;
use crate::scan;

/// A collection of secrets keyed by filename.
///
/// Mirrors Python's `SecretsCollection` class.
#[derive(Debug, Clone)]
pub struct SecretsCollection {
    /// `filename → { PotentialSecret, … }`.
    pub data: HashMap<String, HashSet<PotentialSecret>>,
    /// Root directory for relative path resolution.
    pub root: String,
}

impl Default for SecretsCollection {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretsCollection {
    /// Create an empty collection with no root.
    pub fn new() -> Self {
        SecretsCollection {
            data: HashMap::new(),
            root: String::new(),
        }
    }

    /// Create an empty collection with a specific root directory.
    pub fn with_root(root: impl Into<String>) -> Self {
        SecretsCollection {
            data: HashMap::new(),
            root: root.into(),
        }
    }

    /// Returns the set of filenames that have entries.
    pub fn files(&self) -> HashSet<&str> {
        self.data.keys().map(|s| s.as_str()).collect()
    }

    /// Get or create the secret set for a filename.
    pub fn entry(&mut self, filename: impl Into<String>) -> &mut HashSet<PotentialSecret> {
        self.data.entry(filename.into()).or_default()
    }

    /// Get the secret set for a filename (immutable).
    pub fn get(&self, filename: &str) -> Option<&HashSet<PotentialSecret>> {
        self.data.get(filename)
    }

    /// Add a secret to the collection under its filename.
    pub fn add_secret(&mut self, secret: PotentialSecret) {
        self.data
            .entry(secret.filename.clone())
            .or_default()
            .insert(secret);
    }

    /// Scan multiple files in parallel using rayon and store results.
    ///
    /// - `filenames` — list of file paths to scan.
    /// - `num_threads` — thread pool size; `None` defaults to `num_cpus`.
    ///
    /// Results are added to the collection under each filename.
    /// Matches Python's `SecretsCollection.scan_files()` (which uses
    /// `multiprocessing.Pool`), but uses rayon for zero-serialization
    /// thread-based parallelism.
    pub fn scan_files(&mut self, filenames: &[String], num_threads: Option<usize>) {
        let results = scan::scan_files(filenames, num_threads);

        for (filename, secrets) in results {
            let set = self.data.entry(filename).or_default();
            for secret in secrets {
                set.insert(secret);
            }
        }
    }

    /// Load a `SecretsCollection` from a baseline JSON dict.
    ///
    /// Expects `baseline["results"]` to be `{ filename: [secret_dict, …] }`.
    /// Matches Python's `SecretsCollection.load_from_baseline()`.
    pub fn load_from_baseline(baseline: &Value) -> Result<Self, String> {
        let mut output = SecretsCollection::new();

        let results = baseline
            .get("results")
            .and_then(|v| v.as_object())
            .ok_or("missing or invalid 'results' field in baseline")?;

        for (filename, secrets_val) in results {
            let secrets_arr = secrets_val
                .as_array()
                .ok_or_else(|| format!("results['{filename}'] is not an array"))?;

            for item in secrets_arr {
                // Add filename to the dict like Python does: {filename: filename, **item}
                let mut secret_dict = item.clone();
                if let Some(obj) = secret_dict.as_object_mut() {
                    obj.insert("filename".to_string(), Value::String(filename.clone()));
                }
                let secret = PotentialSecret::load_from_dict(&secret_dict)?;
                output
                    .data
                    .entry(filename.clone())
                    .or_default()
                    .insert(secret);
            }
        }

        Ok(output)
    }

    /// Merge old baseline results into this collection.
    ///
    /// Preserves `is_secret` and `is_verified` from old results for secrets
    /// that still exist in the current scan. Matches Python's `merge()`.
    pub fn merge(&mut self, old_results: &SecretsCollection) {
        for filename in old_results.files() {
            if !self.data.contains_key(filename) {
                continue;
            }

            // Build a mapping for O(1) lookup: identity → mutable ref
            // Since we can't easily get mutable refs from a HashSet,
            // we extract, modify, and re-insert.
            let current_set = self.data.get_mut(filename).unwrap();

            // Build lookup of current secrets by identity key
            let current_map: HashMap<(String, String, String), PotentialSecret> = current_set
                .iter()
                .map(|s| {
                    (
                        (
                            s.filename.clone(),
                            s.secret_hash.clone(),
                            s.secret_type.clone(),
                        ),
                        s.clone(),
                    )
                })
                .collect();

            let old_set = match old_results.data.get(filename) {
                Some(s) => s,
                None => continue,
            };

            let mut updated_set = HashSet::new();
            for (_key, mut current_secret) in current_map {
                // Find matching old secret
                if let Some(old_secret) = old_set.get(&current_secret) {
                    // Only override is_secret if current is None (unadjudicated)
                    if current_secret.is_secret.is_none() {
                        current_secret.is_secret = old_secret.is_secret;
                    }
                    // Only override is_verified if current is false
                    if !current_secret.is_verified {
                        current_secret.is_verified = old_secret.is_verified;
                    }
                }
                updated_set.insert(current_secret);
            }

            *current_set = updated_set;
        }
    }

    /// Trim the collection against fresh scan results.
    ///
    /// - For files in both `self` and `scanned_results`: keep only the intersection.
    /// - For files only in `self` that were scanned (in `filelist`): remove them.
    /// - For files only in `self` that were NOT scanned: keep all secrets.
    ///
    /// Line numbers are updated from the fresh scan.
    /// Matches Python's `trim()`.
    pub fn trim(
        &mut self,
        scanned_results: Option<&SecretsCollection>,
        filelist: Option<&[String]>,
    ) {
        // Default behavior when no scanned_results: use files that no longer exist
        let default_collection;
        let default_filelist;
        let (scan_ref, file_ref) = match scanned_results {
            Some(sr) => (sr, filelist.unwrap_or(&[])),
            None => {
                default_collection = SecretsCollection::new();
                default_filelist = self
                    .files()
                    .into_iter()
                    .filter(|f| !std::path::Path::new(f).exists())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>();
                (
                    &default_collection as &SecretsCollection,
                    default_filelist.as_slice(),
                )
            }
        };

        let fileset: HashSet<&str> = file_ref.iter().map(|s| s.as_str()).collect();

        let mut result: HashMap<String, HashSet<PotentialSecret>> = HashMap::new();

        // Phase 1: For files in scanned_results, intersect with current
        for filename in scan_ref.files() {
            if !self.data.contains_key(filename) {
                continue;
            }

            let existing_secrets = &self.data[filename];
            let scanned_secrets = &scan_ref.data[filename];

            // Build a map of existing secrets for O(1) lookup
            let existing_map: HashMap<&PotentialSecret, &PotentialSecret> =
                existing_secrets.iter().map(|s| (s, s)).collect();

            let mut intersected = HashSet::new();
            for scanned_secret in scanned_secrets {
                if let Some(&existing_secret) = existing_map.get(scanned_secret) {
                    let mut kept = existing_secret.clone();
                    // Update line number from fresh scan
                    if kept.line_number != 0 {
                        kept.line_number = scanned_secret.line_number;
                    }
                    intersected.insert(kept);
                }
            }

            result.insert(filename.to_string(), intersected);
        }

        // Phase 2: For files only in self
        for filename in self.files() {
            if result.contains_key(filename) {
                continue; // Already processed in phase 1
            }

            if fileset.contains(filename) {
                continue; // Was scanned but had no secrets — remove
            }

            // Not scanned — keep all secrets
            if let Some(secrets) = self.data.get(filename) {
                result.insert(filename.to_string(), secrets.clone());
            }
        }

        self.data = result;
    }

    /// Serialize to the `results` JSON dict format.
    ///
    /// Output: `{ filename: [ secret.to_json(), … ] }`, with filenames sorted
    /// alphabetically and secrets sorted by (line_number, secret_hash, type).
    /// Matches Python's `SecretsCollection.json()`.
    pub fn json(&self) -> Value {
        let mut output = Map::new();

        for (filename, secret) in self.iter() {
            let arr = output
                .entry(filename.to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(ref mut vec) = arr {
                vec.push(secret.to_json());
            }
        }

        Value::Object(output)
    }

    /// Returns an iterator over `(filename, &PotentialSecret)` tuples,
    /// sorted by filename then by (line_number, secret_hash, secret_type).
    ///
    /// Matches Python's `__iter__` which yields `(filename, secret)` tuples.
    pub fn iter(&self) -> SecretsIterator<'_> {
        // Collect and sort all items
        let mut items: Vec<(&str, &PotentialSecret)> = Vec::new();

        let mut filenames: Vec<&str> = self.data.keys().map(|s| s.as_str()).collect();
        filenames.sort();

        for filename in filenames {
            if let Some(secrets) = self.data.get(filename) {
                let mut sorted_secrets: Vec<&PotentialSecret> = secrets.iter().collect();
                sorted_secrets.sort_by(|a, b| {
                    a.line_number
                        .cmp(&b.line_number)
                        .then_with(|| a.secret_hash.cmp(&b.secret_hash))
                        .then_with(|| a.secret_type.cmp(&b.secret_type))
                });
                for secret in sorted_secrets {
                    items.push((filename, secret));
                }
            }
        }

        SecretsIterator { items, index: 0 }
    }

    /// Total number of secrets across all files.
    pub fn len(&self) -> usize {
        self.data.values().map(|s| s.len()).sum()
    }

    /// Returns true if the collection has no secrets.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Loose equality: same files, same secrets by identity (hash, type, filename).
    /// Ignores line_number, is_secret, is_verified.
    pub fn eq_loose(&self, other: &SecretsCollection) -> bool {
        if self.files() != other.files() {
            return false;
        }

        for filename in self.files() {
            let self_secrets = self.data.get(filename).cloned().unwrap_or_default();
            let other_secrets = other.data.get(filename).cloned().unwrap_or_default();
            if self_secrets != other_secrets {
                return false;
            }
        }

        true
    }

    /// Strict equality: same files, same secrets, AND same metadata
    /// (line_number, is_secret, is_verified).
    pub fn eq_strict(&self, other: &SecretsCollection) -> bool {
        if self.files() != other.files() {
            return false;
        }

        for filename in self.files() {
            let self_secrets = match self.data.get(filename) {
                Some(s) => s,
                None => return false,
            };
            let other_secrets = match other.data.get(filename) {
                Some(s) => s,
                None => return false,
            };

            // Check identity equality first
            if self_secrets != other_secrets {
                return false;
            }

            // Build maps for attribute-level comparison
            let self_map: HashMap<(&str, &str, &str), &PotentialSecret> = self_secrets
                .iter()
                .map(|s| {
                    (
                        (
                            s.filename.as_str(),
                            s.secret_hash.as_str(),
                            s.secret_type.as_str(),
                        ),
                        s,
                    )
                })
                .collect();

            let other_map: HashMap<(&str, &str, &str), &PotentialSecret> = other_secrets
                .iter()
                .map(|s| {
                    (
                        (
                            s.filename.as_str(),
                            s.secret_hash.as_str(),
                            s.secret_type.as_str(),
                        ),
                        s,
                    )
                })
                .collect();

            for (key, self_s) in &self_map {
                let other_s = match other_map.get(key) {
                    Some(s) => s,
                    None => return false,
                };

                // Skip line_number comparison if either is 0
                if self_s.line_number != 0
                    && other_s.line_number != 0
                    && self_s.line_number != other_s.line_number
                {
                    return false;
                }

                if self_s.is_secret != other_s.is_secret {
                    return false;
                }
                if self_s.is_verified != other_s.is_verified {
                    return false;
                }
            }
        }

        true
    }

    /// Set subtraction: `self - other`.
    ///
    /// For files in both: keep secrets only in self.
    /// For files only in self: keep all secrets.
    /// Matches Python's `__sub__`.
    pub fn subtract(&self, other: &SecretsCollection) -> SecretsCollection {
        let mut output = SecretsCollection::new();

        // Files in other — keep only secrets NOT in other
        for filename in other.files() {
            if let Some(self_secrets) = self.data.get(filename) {
                let other_secrets = other.data.get(filename).cloned().unwrap_or_default();
                let diff: HashSet<PotentialSecret> =
                    self_secrets.difference(&other_secrets).cloned().collect();
                output.data.insert(filename.to_string(), diff);
            }
        }

        // Files only in self — keep all
        for filename in self.files() {
            if other.data.contains_key(filename) {
                continue;
            }
            if let Some(secrets) = self.data.get(filename) {
                output.data.insert(filename.to_string(), secrets.clone());
            }
        }

        output
    }
}

/// Default `PartialEq` uses loose equality (same as Python's `__eq__`).
impl PartialEq for SecretsCollection {
    fn eq(&self, other: &Self) -> bool {
        self.eq_loose(other)
    }
}

impl Eq for SecretsCollection {}

/// Iterator over `(filename, &PotentialSecret)` in sorted order.
pub struct SecretsIterator<'a> {
    items: Vec<(&'a str, &'a PotentialSecret)>,
    index: usize,
}

impl<'a> Iterator for SecretsIterator<'a> {
    type Item = (&'a str, &'a PotentialSecret);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.items.len() {
            let item = self.items[self.index];
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::potential_secret::hash_secret;
    use serde_json::json;

    fn make_secret(secret_type: &str, filename: &str, secret: &str, line: u64) -> PotentialSecret {
        PotentialSecret::new(secret_type, filename, secret, line, None, false)
    }

    fn make_secret_with_meta(
        secret_type: &str,
        filename: &str,
        secret: &str,
        line: u64,
        is_secret: Option<bool>,
        is_verified: bool,
    ) -> PotentialSecret {
        PotentialSecret::new(secret_type, filename, secret, line, is_secret, is_verified)
    }

    // ---- new / with_root ----

    #[test]
    fn test_new_empty_collection() {
        let c = SecretsCollection::new();
        assert!(c.data.is_empty());
        assert!(c.root.is_empty());
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn test_with_root() {
        let c = SecretsCollection::with_root("/my/project");
        assert_eq!(c.root, "/my/project");
        assert!(c.data.is_empty());
    }

    // ---- add_secret / entry / get ----

    #[test]
    fn test_add_secret() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret("type", "file.py", "secret1", 1));
        assert_eq!(c.len(), 1);
        assert!(c.files().contains("file.py"));
    }

    #[test]
    fn test_add_duplicate_secret_deduplicates() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret("type", "file.py", "secret1", 1));
        c.add_secret(make_secret("type", "file.py", "secret1", 2));
        // Same identity → deduplicated
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn test_entry_creates_set() {
        let mut c = SecretsCollection::new();
        let set = c.entry("new_file.py");
        set.insert(make_secret("type", "new_file.py", "s", 1));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn test_get_existing_file() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret("type", "file.py", "s", 1));
        assert!(c.get("file.py").is_some());
        assert_eq!(c.get("file.py").unwrap().len(), 1);
    }

    #[test]
    fn test_get_nonexistent_file() {
        let c = SecretsCollection::new();
        assert!(c.get("nope.py").is_none());
    }

    // ---- files ----

    #[test]
    fn test_files_returns_all_filenames() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret("type", "a.py", "s1", 1));
        c.add_secret(make_secret("type", "b.py", "s2", 1));
        c.add_secret(make_secret("type", "a.py", "s3", 2));
        let files = c.files();
        assert_eq!(files.len(), 2);
        assert!(files.contains("a.py"));
        assert!(files.contains("b.py"));
    }

    // ---- load_from_baseline ----

    #[test]
    fn test_load_from_baseline() {
        let baseline = json!({
            "results": {
                "file.py": [
                    {
                        "type": "Secret Keyword",
                        "hashed_secret": "abc123",
                        "is_verified": false,
                        "line_number": 5
                    }
                ],
                "config.yaml": [
                    {
                        "type": "Base64 High Entropy String",
                        "hashed_secret": "def456",
                        "is_verified": true,
                        "line_number": 10,
                        "is_secret": true
                    }
                ]
            }
        });

        let c = SecretsCollection::load_from_baseline(&baseline).unwrap();
        assert_eq!(c.len(), 2);
        assert!(c.files().contains("file.py"));
        assert!(c.files().contains("config.yaml"));

        let file_secrets: Vec<&PotentialSecret> = c.get("file.py").unwrap().iter().collect();
        assert_eq!(file_secrets[0].secret_type, "Secret Keyword");
        assert_eq!(file_secrets[0].secret_hash, "abc123");
        assert_eq!(file_secrets[0].line_number, 5);
    }

    #[test]
    fn test_load_from_baseline_empty_results() {
        let baseline = json!({"results": {}});
        let c = SecretsCollection::load_from_baseline(&baseline).unwrap();
        assert!(c.is_empty());
    }

    #[test]
    fn test_load_from_baseline_missing_results() {
        let baseline = json!({"plugins_used": []});
        assert!(SecretsCollection::load_from_baseline(&baseline).is_err());
    }

    #[test]
    fn test_load_from_baseline_sets_filename() {
        let baseline = json!({
            "results": {
                "test.py": [
                    {
                        "type": "type",
                        "hashed_secret": "hash",
                        "is_verified": false
                    }
                ]
            }
        });

        let c = SecretsCollection::load_from_baseline(&baseline).unwrap();
        let secrets: Vec<&PotentialSecret> = c.get("test.py").unwrap().iter().collect();
        assert_eq!(secrets[0].filename, "test.py");
    }

    // ---- merge ----

    #[test]
    fn test_merge_preserves_is_secret() {
        let mut current = SecretsCollection::new();
        current.add_secret(make_secret("type", "file.py", "s1", 1));

        let mut old = SecretsCollection::new();
        old.add_secret(make_secret_with_meta(
            "type",
            "file.py",
            "s1",
            1,
            Some(false),
            false,
        ));

        current.merge(&old);

        let secret = current.get("file.py").unwrap().iter().next().unwrap();
        assert_eq!(secret.is_secret, Some(false));
    }

    #[test]
    fn test_merge_preserves_is_verified() {
        let mut current = SecretsCollection::new();
        current.add_secret(make_secret("type", "file.py", "s1", 1));

        let mut old = SecretsCollection::new();
        old.add_secret(make_secret_with_meta(
            "type", "file.py", "s1", 1, None, true,
        ));

        current.merge(&old);

        let secret = current.get("file.py").unwrap().iter().next().unwrap();
        assert!(secret.is_verified);
    }

    #[test]
    fn test_merge_does_not_override_existing_is_secret() {
        let mut current = SecretsCollection::new();
        current.add_secret(make_secret_with_meta(
            "type",
            "file.py",
            "s1",
            1,
            Some(true),
            false,
        ));

        let mut old = SecretsCollection::new();
        old.add_secret(make_secret_with_meta(
            "type",
            "file.py",
            "s1",
            1,
            Some(false),
            false,
        ));

        current.merge(&old);

        let secret = current.get("file.py").unwrap().iter().next().unwrap();
        // Current's Some(true) should NOT be overridden by old's Some(false)
        assert_eq!(secret.is_secret, Some(true));
    }

    #[test]
    fn test_merge_does_not_override_existing_is_verified() {
        let mut current = SecretsCollection::new();
        current.add_secret(make_secret_with_meta(
            "type", "file.py", "s1", 1, None, true,
        ));

        let mut old = SecretsCollection::new();
        old.add_secret(make_secret_with_meta(
            "type", "file.py", "s1", 1, None, false,
        ));

        current.merge(&old);

        let secret = current.get("file.py").unwrap().iter().next().unwrap();
        assert!(secret.is_verified);
    }

    #[test]
    fn test_merge_skips_files_not_in_current() {
        let mut current = SecretsCollection::new();
        current.add_secret(make_secret("type", "file.py", "s1", 1));

        let mut old = SecretsCollection::new();
        old.add_secret(make_secret_with_meta(
            "type",
            "other.py",
            "s2",
            1,
            Some(true),
            true,
        ));

        current.merge(&old);

        // No changes — other.py not in current
        assert!(!current.files().contains("other.py"));
        assert_eq!(current.len(), 1);
    }

    #[test]
    fn test_merge_skips_secrets_not_in_current() {
        let mut current = SecretsCollection::new();
        current.add_secret(make_secret("type", "file.py", "s1", 1));

        let mut old = SecretsCollection::new();
        old.add_secret(make_secret_with_meta(
            "type",
            "file.py",
            "different_secret",
            1,
            Some(true),
            true,
        ));

        current.merge(&old);

        let secret = current.get("file.py").unwrap().iter().next().unwrap();
        // s1 should be unchanged
        assert_eq!(secret.is_secret, None);
        assert!(!secret.is_verified);
    }

    // ---- trim ----

    #[test]
    fn test_trim_intersection() {
        let mut baseline = SecretsCollection::new();
        baseline.add_secret(make_secret("type", "file.py", "s1", 1));
        baseline.add_secret(make_secret("type", "file.py", "s2", 2));

        let mut scanned = SecretsCollection::new();
        scanned.add_secret(make_secret("type", "file.py", "s1", 5)); // Same identity, new line

        baseline.trim(Some(&scanned), Some(&["file.py".to_string()]));

        // Only s1 should remain (was in both)
        assert_eq!(baseline.len(), 1);
        let secret = baseline.get("file.py").unwrap().iter().next().unwrap();
        assert_eq!(secret.secret_hash, hash_secret("s1"));
        // Line number should be updated from scanned
        assert_eq!(secret.line_number, 5);
    }

    #[test]
    fn test_trim_preserves_unscanned_files() {
        let mut baseline = SecretsCollection::new();
        baseline.add_secret(make_secret("type", "scanned.py", "s1", 1));
        baseline.add_secret(make_secret("type", "unscanned.py", "s2", 2));

        let mut scanned = SecretsCollection::new();
        scanned.add_secret(make_secret("type", "scanned.py", "s1", 1));

        // Only scanned.py was scanned
        baseline.trim(Some(&scanned), Some(&["scanned.py".to_string()]));

        assert_eq!(baseline.len(), 2);
        assert!(baseline.files().contains("scanned.py"));
        assert!(baseline.files().contains("unscanned.py"));
    }

    #[test]
    fn test_trim_removes_scanned_empty_files() {
        let mut baseline = SecretsCollection::new();
        baseline.add_secret(make_secret("type", "file.py", "s1", 1));

        let scanned = SecretsCollection::new(); // File scanned but no secrets found

        // file.py was scanned (in filelist) but has no secrets in scanned_results
        baseline.trim(Some(&scanned), Some(&["file.py".to_string()]));

        // file.py should be removed since it was scanned but had no matches
        assert!(baseline.is_empty());
    }

    // ---- json ----

    #[test]
    fn test_json_format() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret(
            "AWS Key",
            "config.py",
            "AKIAIOSFODNN7EXAMPLE",
            10,
        ));
        c.add_secret(make_secret(
            "Secret Keyword",
            "config.py",
            "password123",
            20,
        ));
        c.add_secret(make_secret("Private Key", "keys/id_rsa", "BEGIN RSA", 1));

        let j = c.json();
        let obj = j.as_object().unwrap();

        // Should have 2 files
        assert_eq!(obj.len(), 2);

        // config.py should have 2 secrets
        let config_secrets = obj["config.py"].as_array().unwrap();
        assert_eq!(config_secrets.len(), 2);

        // Sorted by line number
        assert!(
            config_secrets[0]["line_number"].as_u64().unwrap()
                <= config_secrets[1]["line_number"].as_u64().unwrap()
        );

        // keys/id_rsa should have 1 secret
        let key_secrets = obj["keys/id_rsa"].as_array().unwrap();
        assert_eq!(key_secrets.len(), 1);
    }

    #[test]
    fn test_json_empty_collection() {
        let c = SecretsCollection::new();
        let j = c.json();
        assert_eq!(j, json!({}));
    }

    #[test]
    fn test_json_sorted_filenames() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret("type", "z.py", "s1", 1));
        c.add_secret(make_secret("type", "a.py", "s2", 1));
        c.add_secret(make_secret("type", "m.py", "s3", 1));

        let j = c.json();
        let keys: Vec<&String> = j.as_object().unwrap().keys().collect();
        // Since iteration is sorted, entries should appear in alphabetical order
        assert_eq!(keys, vec!["a.py", "m.py", "z.py"]);
    }

    // ---- iterator ----

    #[test]
    fn test_iter_sorted_by_filename_then_line() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret("type", "b.py", "s1", 10));
        c.add_secret(make_secret("type", "a.py", "s2", 5));
        c.add_secret(make_secret("type", "a.py", "s3", 1));

        let items: Vec<(&str, &PotentialSecret)> = c.iter().collect();
        assert_eq!(items.len(), 3);

        // First file: a.py, sorted by line_number
        assert_eq!(items[0].0, "a.py");
        assert_eq!(items[0].1.line_number, 1);
        assert_eq!(items[1].0, "a.py");
        assert_eq!(items[1].1.line_number, 5);

        // Second file: b.py
        assert_eq!(items[2].0, "b.py");
        assert_eq!(items[2].1.line_number, 10);
    }

    #[test]
    fn test_iter_sorts_by_hash_then_type_on_tie() {
        let mut c = SecretsCollection::new();
        let s1 = PotentialSecret::new("TypeB", "file.py", "alpha", 1, None, false);
        let s2 = PotentialSecret::new("TypeA", "file.py", "beta", 1, None, false);
        c.add_secret(s1);
        c.add_secret(s2);

        let items: Vec<(&str, &PotentialSecret)> = c.iter().collect();
        assert_eq!(items.len(), 2);

        // Same line → sorted by secret_hash
        let hash_alpha = hash_secret("alpha");
        let hash_beta = hash_secret("beta");
        // Verify that iteration order matches hash ordering
        if hash_alpha < hash_beta {
            assert_eq!(items[0].1.secret_hash, hash_alpha);
            assert_eq!(items[1].1.secret_hash, hash_beta);
        } else {
            assert_eq!(items[0].1.secret_hash, hash_beta);
            assert_eq!(items[1].1.secret_hash, hash_alpha);
        }
    }

    #[test]
    fn test_iter_empty() {
        let c = SecretsCollection::new();
        assert_eq!(c.iter().count(), 0);
    }

    // ---- len / is_empty ----

    #[test]
    fn test_len_counts_all_secrets() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret("type", "a.py", "s1", 1));
        c.add_secret(make_secret("type", "a.py", "s2", 2));
        c.add_secret(make_secret("type", "b.py", "s3", 1));
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn test_is_empty_true() {
        let c = SecretsCollection::new();
        assert!(c.is_empty());
    }

    #[test]
    fn test_is_empty_false() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret("type", "file.py", "s1", 1));
        assert!(!c.is_empty());
    }

    // ---- equality ----

    #[test]
    fn test_eq_loose_same_secrets() {
        let mut a = SecretsCollection::new();
        a.add_secret(make_secret("type", "file.py", "s1", 1));

        let mut b = SecretsCollection::new();
        b.add_secret(make_secret("type", "file.py", "s1", 99)); // Different line

        assert_eq!(a, b);
    }

    #[test]
    fn test_eq_loose_different_secrets() {
        let mut a = SecretsCollection::new();
        a.add_secret(make_secret("type", "file.py", "s1", 1));

        let mut b = SecretsCollection::new();
        b.add_secret(make_secret("type", "file.py", "s2", 1));

        assert_ne!(a, b);
    }

    #[test]
    fn test_eq_loose_different_files() {
        let mut a = SecretsCollection::new();
        a.add_secret(make_secret("type", "a.py", "s1", 1));

        let mut b = SecretsCollection::new();
        b.add_secret(make_secret("type", "b.py", "s1", 1));

        assert_ne!(a, b);
    }

    #[test]
    fn test_eq_strict_same_metadata() {
        let mut a = SecretsCollection::new();
        a.add_secret(make_secret_with_meta(
            "type",
            "file.py",
            "s1",
            5,
            Some(true),
            true,
        ));

        let mut b = SecretsCollection::new();
        b.add_secret(make_secret_with_meta(
            "type",
            "file.py",
            "s1",
            5,
            Some(true),
            true,
        ));

        assert!(a.eq_strict(&b));
    }

    #[test]
    fn test_eq_strict_different_line_number() {
        let mut a = SecretsCollection::new();
        a.add_secret(make_secret_with_meta(
            "type", "file.py", "s1", 5, None, false,
        ));

        let mut b = SecretsCollection::new();
        b.add_secret(make_secret_with_meta(
            "type", "file.py", "s1", 10, None, false,
        ));

        assert!(!a.eq_strict(&b));
    }

    #[test]
    fn test_eq_strict_zero_line_skipped() {
        let mut a = SecretsCollection::new();
        a.add_secret(make_secret_with_meta(
            "type", "file.py", "s1", 0, None, false,
        ));

        let mut b = SecretsCollection::new();
        b.add_secret(make_secret_with_meta(
            "type", "file.py", "s1", 10, None, false,
        ));

        // One has line_number 0 → skip comparison
        assert!(a.eq_strict(&b));
    }

    #[test]
    fn test_eq_strict_different_is_secret() {
        let mut a = SecretsCollection::new();
        a.add_secret(make_secret_with_meta(
            "type",
            "file.py",
            "s1",
            1,
            Some(true),
            false,
        ));

        let mut b = SecretsCollection::new();
        b.add_secret(make_secret_with_meta(
            "type",
            "file.py",
            "s1",
            1,
            Some(false),
            false,
        ));

        assert!(!a.eq_strict(&b));
    }

    // ---- subtract ----

    #[test]
    fn test_subtract_common_files() {
        let mut a = SecretsCollection::new();
        a.add_secret(make_secret("type", "file.py", "s1", 1));
        a.add_secret(make_secret("type", "file.py", "s2", 2));

        let mut b = SecretsCollection::new();
        b.add_secret(make_secret("type", "file.py", "s1", 1));

        let diff = a.subtract(&b);
        assert_eq!(diff.len(), 1);
        let secret = diff.get("file.py").unwrap().iter().next().unwrap();
        assert_eq!(secret.secret_hash, hash_secret("s2"));
    }

    #[test]
    fn test_subtract_keeps_self_only_files() {
        let mut a = SecretsCollection::new();
        a.add_secret(make_secret("type", "only_a.py", "s1", 1));

        let b = SecretsCollection::new();

        let diff = a.subtract(&b);
        assert_eq!(diff.len(), 1);
        assert!(diff.files().contains("only_a.py"));
    }

    #[test]
    fn test_subtract_omits_other_only_files() {
        let a = SecretsCollection::new();

        let mut b = SecretsCollection::new();
        b.add_secret(make_secret("type", "only_b.py", "s1", 1));

        let diff = a.subtract(&b);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_subtract_empty_minus_empty() {
        let a = SecretsCollection::new();
        let b = SecretsCollection::new();
        let diff = a.subtract(&b);
        assert!(diff.is_empty());
    }

    // ---- load_from_baseline round trip ----

    #[test]
    fn test_json_roundtrip() {
        let mut c = SecretsCollection::new();
        c.add_secret(make_secret(
            "AWS Key",
            "config.py",
            "AKIAIOSFODNN7EXAMPLE",
            10,
        ));
        c.add_secret(make_secret_with_meta(
            "Secret Keyword",
            "app.py",
            "password",
            5,
            Some(true),
            false,
        ));

        let j = c.json();
        let baseline = json!({"results": j});
        let loaded = SecretsCollection::load_from_baseline(&baseline).unwrap();

        // Loose equality (ignores secret_value being None on loaded)
        assert_eq!(c, loaded);
    }

    // ---- scan_files ----

    #[test]
    fn test_scan_files_parallel() {
        use crate::settings;
        use std::io::Write;

        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let dir = std::env::temp_dir();
        let paths: Vec<std::path::PathBuf> = (0..3)
            .map(|i| {
                let path = dir.join(format!("test_sc_par_{}.py", i));
                let mut f = std::fs::File::create(&path).unwrap();
                writeln!(f, "aws_key_{} = 'AKIAIOSFODNN7EXAMPL{}'", i, i).unwrap();
                path
            })
            .collect();

        let filenames: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        let mut collection = SecretsCollection::new();
        collection.scan_files(&filenames, Some(2));

        // Should have detected secrets
        assert!(
            !collection.is_empty(),
            "scan_files should populate the collection"
        );

        // Clean up
        for path in &paths {
            std::fs::remove_file(path).ok();
        }
    }

    #[test]
    fn test_scan_files_empty_list() {
        use crate::settings;

        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let mut collection = SecretsCollection::new();
        collection.scan_files(&[], None);

        assert!(
            collection.is_empty(),
            "Empty file list should produce empty collection"
        );
    }
}
