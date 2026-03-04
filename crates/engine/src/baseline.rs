//! Baseline management — create, load, save, format, and upgrade baseline files.
//!
//! Ported from `detect_secrets/core/baseline.py`. Provides:
//! - [`create`] — scan files to initialize a new baseline
//! - [`load`] — load and configure settings from a baseline dict
//! - [`load_from_file`] — read a baseline JSON file from disk
//! - [`format_for_output`] — format a [`SecretsCollection`] for JSON output
//! - [`save_to_file`] — write baseline JSON to disk
//! - [`upgrade`] — migrate older baseline formats to the current version

use serde_json::{json, Map, Value};
use std::fs;

use crate::scan::get_files_to_scan;
use crate::secrets_collection::SecretsCollection;
use crate::settings;

/// Baseline format version — matches Python detect-secrets v1.5.0 for
/// compatibility with existing `.secrets.baseline` files.
pub const BASELINE_VERSION: &str = "1.5.0";

// ---------------------------------------------------------------------------
// Semantic version comparison (ported from detect_secrets/util/semver.py)
// ---------------------------------------------------------------------------

/// Simple semantic version for baseline format comparisons.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SemVer {
    major: u32,
    minor: u32,
    patch: u32,
}

impl SemVer {
    fn parse(version: &str) -> Option<Self> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(SemVer {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
        })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during baseline operations.
#[derive(Debug)]
pub enum BaselineError {
    /// Unable to read or parse the baseline file.
    UnableToRead(String),
    /// Invalid baseline format.
    Invalid(String),
}

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaselineError::UnableToRead(msg) => write!(f, "Unable to read baseline: {msg}"),
            BaselineError::Invalid(msg) => write!(f, "Invalid baseline: {msg}"),
        }
    }
}

impl std::error::Error for BaselineError {}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Resolve a relative filename to an absolute scan path.
fn resolve_scan_path(filename: &str, root: &str) -> String {
    if std::path::Path::new(filename).is_absolute() {
        filename.to_string()
    } else if !root.is_empty() {
        std::path::Path::new(root)
            .join(filename)
            .to_string_lossy()
            .to_string()
    } else {
        filename.to_string()
    }
}

/// Scan files recursively to initialize a new baseline.
///
/// Uses parallel scanning via rayon when multiple files are found.
/// Matches Python's `baseline.create()`.
pub fn create(paths: &[String], should_scan_all_files: bool, root: &str) -> SecretsCollection {
    let files = get_files_to_scan(paths, should_scan_all_files, root);
    let mut secrets = SecretsCollection::with_root(root);

    // Build list of (relative_name, absolute_scan_path) pairs
    let scan_paths: Vec<String> = files.iter().map(|f| resolve_scan_path(f, root)).collect();

    // Use parallel scanning for better performance
    let results = crate::scan::scan_files(&scan_paths, None);

    for (scan_path, found) in results {
        // Find the original relative filename for this scan path
        let relative_name = files
            .iter()
            .find(|f| resolve_scan_path(f, root) == scan_path)
            .cloned()
            .unwrap_or(scan_path);

        for mut secret in found {
            secret.filename = relative_name.clone();
            secrets.add_secret(secret);
        }
    }

    secrets
}

/// Load a baseline dict: upgrade it, configure settings, and return its secrets.
///
/// Matches Python's `baseline.load()`.
pub fn load(baseline: &Value, filename: &str) -> Result<SecretsCollection, BaselineError> {
    let upgraded = upgrade(baseline);
    settings::configure_settings_from_baseline(&upgraded, filename);
    SecretsCollection::load_from_baseline(&upgraded).map_err(BaselineError::Invalid)
}

/// Read and parse a baseline JSON file from disk.
///
/// Matches Python's `baseline.load_from_file()`.
pub fn load_from_file(filename: &str) -> Result<Value, BaselineError> {
    let contents = fs::read_to_string(filename)
        .map_err(|e| BaselineError::UnableToRead(format!("{filename}: {e}")))?;

    serde_json::from_str(&contents)
        .map_err(|e| BaselineError::UnableToRead(format!("{filename}: invalid JSON: {e}")))
}

/// Format a [`SecretsCollection`] for baseline output.
///
/// Returns a dict with `version`, `plugins_used`, `filters_used`, `results`,
/// and optionally `generated_at`.
///
/// Matches Python's `baseline.format_for_output()`.
pub fn format_for_output(secrets: &SecretsCollection, is_slim_mode: bool) -> Value {
    let settings_json = settings::get_settings().json();

    let results = secrets.json();

    let mut output = Map::new();
    output.insert("version".to_string(), json!(BASELINE_VERSION));

    // Merge settings (plugins_used, filters_used) into output
    if let Some(settings_obj) = settings_json.as_object() {
        for (k, v) in settings_obj {
            output.insert(k.clone(), v.clone());
        }
    }

    if is_slim_mode {
        // In slim mode, strip line_number from each secret dict
        let mut slim_results = results.clone();
        if let Some(results_obj) = slim_results.as_object_mut() {
            for (_filename, secret_list) in results_obj.iter_mut() {
                if let Some(arr) = secret_list.as_array_mut() {
                    for secret_dict in arr.iter_mut() {
                        if let Some(obj) = secret_dict.as_object_mut() {
                            obj.remove("line_number");
                        }
                    }
                }
            }
        }
        output.insert("results".to_string(), slim_results);
    } else {
        output.insert("results".to_string(), results);
        // Add generated_at timestamp
        let now = time_now_utc();
        output.insert("generated_at".to_string(), json!(now));
    }

    Value::Object(output)
}

/// Write a baseline to a JSON file with 2-space indent.
///
/// Accepts either a pre-formatted dict or a [`SecretsCollection`] (which will
/// be formatted via [`format_for_output`]).
///
/// Matches Python's `baseline.save_to_file()`.
pub fn save_to_file(output: &Value, filename: &str) -> Result<(), BaselineError> {
    let json_str = serde_json::to_string_pretty(output)
        .map_err(|e| BaselineError::Invalid(format!("serialization error: {e}")))?;

    // serde_json's to_string_pretty uses 2-space indent by default
    // Add trailing newline to match Python's output
    let contents = format!("{json_str}\n");

    fs::write(filename, contents)
        .map_err(|e| BaselineError::UnableToRead(format!("failed to write {filename}: {e}")))
}

/// Upgrade an older baseline format to the current version.
///
/// Applies version-specific migrations sequentially. Matches Python's
/// `baseline.upgrade()`.
pub fn upgrade(baseline: &Value) -> Value {
    let baseline_version_str = baseline
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0");

    let baseline_version = match SemVer::parse(baseline_version_str) {
        Some(v) => v,
        None => return baseline.clone(),
    };

    let current_version = match SemVer::parse(BASELINE_VERSION) {
        Some(v) => v,
        None => return baseline.clone(),
    };

    if baseline_version >= current_version {
        return baseline.clone();
    }

    let mut new_baseline = baseline.clone();

    // v0.12 upgrade: exclude_regex → exclude dict, add word_list
    let v0_12 = SemVer {
        major: 0,
        minor: 12,
        patch: 0,
    };
    if baseline_version < v0_12 {
        upgrade_v0_12(&mut new_baseline);
    }

    // v1.0 upgrade: migrate filters, rename high-entropy args, migrate custom plugins
    let v1_0 = SemVer {
        major: 1,
        minor: 0,
        patch: 0,
    };
    if baseline_version < v1_0 {
        upgrade_v1_0(&mut new_baseline);
    }

    // v1.1 upgrade: add new default filters
    let v1_1 = SemVer {
        major: 1,
        minor: 1,
        patch: 0,
    };
    if baseline_version < v1_1 {
        upgrade_v1_1(&mut new_baseline);
    }

    // Set version to current
    if let Some(obj) = new_baseline.as_object_mut() {
        obj.insert("version".to_string(), json!(BASELINE_VERSION));
    }

    new_baseline
}

// ---------------------------------------------------------------------------
// Version-specific upgrade functions
// ---------------------------------------------------------------------------

/// v0.12 upgrade: migrate exclude_regex → exclude dict, add word_list.
fn upgrade_v0_12(baseline: &mut Value) {
    if let Some(obj) = baseline.as_object_mut() {
        if let Some(exclude_regex) = obj.remove("exclude_regex") {
            let mut exclude = Map::new();
            exclude.insert("files".to_string(), exclude_regex);
            exclude.insert("lines".to_string(), Value::Null);
            obj.insert("exclude".to_string(), Value::Object(exclude));
        }

        let mut word_list = Map::new();
        word_list.insert("file".to_string(), Value::Null);
        word_list.insert("hash".to_string(), Value::Null);
        obj.insert("word_list".to_string(), Value::Object(word_list));
    }
}

/// v1.0 upgrade: migrate filters, rename high-entropy string arguments,
/// migrate custom plugins.
fn upgrade_v1_0(baseline: &mut Value) {
    upgrade_v1_0_migrate_filters(baseline);
    upgrade_v1_0_rename_high_entropy_args(baseline);
    upgrade_v1_0_migrate_custom_plugins(baseline);
}

fn upgrade_v1_0_migrate_filters(baseline: &mut Value) {
    let mut filters_used: Vec<Value> = vec![
        json!({"path": "detect_secrets.filters.allowlist.is_line_allowlisted"}),
        json!({"path": "detect_secrets.filters.heuristic.is_sequential_string"}),
        json!({"path": "detect_secrets.filters.heuristic.is_potential_uuid"}),
        json!({"path": "detect_secrets.filters.heuristic.is_likely_id_string"}),
        json!({"path": "detect_secrets.filters.heuristic.is_templated_secret"}),
        json!({"path": "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign"}),
        json!({"path": "detect_secrets.filters.heuristic.is_indirect_reference"}),
        json!({
            "path": "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
            "min_level": 2
        }),
    ];

    if let Some(obj) = baseline.as_object_mut() {
        // Migrate exclude.files → regex.should_exclude_file
        if let Some(exclude) = obj.get("exclude").and_then(|v| v.as_object()) {
            if let Some(files_pattern) = exclude.get("files").and_then(|v| v.as_str()) {
                filters_used.push(json!({
                    "path": "detect_secrets.filters.regex.should_exclude_file",
                    "pattern": [files_pattern]
                }));
            }
            if let Some(lines_pattern) = exclude.get("lines").and_then(|v| v.as_str()) {
                filters_used.push(json!({
                    "path": "detect_secrets.filters.regex.should_exclude_line",
                    "pattern": [lines_pattern]
                }));
            }
        }
        obj.remove("exclude");

        // Migrate word_list → wordlist filter
        if let Some(word_list) = obj.get("word_list").and_then(|v| v.as_object()) {
            if let Some(file) = word_list.get("file").and_then(|v| v.as_str()) {
                let hash = word_list.get("hash").and_then(|v| v.as_str()).unwrap_or("");
                filters_used.push(json!({
                    "path": "detect_secrets.filters.wordlist.should_exclude_secret",
                    "min_length": 3,
                    "file_name": file,
                    "file_hash": hash
                }));
            }
        }
        obj.remove("word_list");

        obj.insert("filters_used".to_string(), json!(filters_used));
    }
}

fn upgrade_v1_0_rename_high_entropy_args(baseline: &mut Value) {
    if let Some(plugins) = baseline
        .get_mut("plugins_used")
        .and_then(|v| v.as_array_mut())
    {
        for plugin in plugins.iter_mut() {
            if let Some(obj) = plugin.as_object_mut() {
                let name = obj
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if name == "Base64HighEntropyString" {
                    if let Some(val) = obj.remove("base64_limit") {
                        obj.insert("limit".to_string(), val);
                    }
                } else if name == "HexHighEntropyString" {
                    if let Some(val) = obj.remove("hex_limit") {
                        obj.insert("limit".to_string(), val);
                    }
                }
            }
        }
    }
}

fn upgrade_v1_0_migrate_custom_plugins(baseline: &mut Value) {
    if let Some(obj) = baseline.as_object_mut() {
        // Best-effort migration: we can't introspect Python files from Rust,
        // so we just remove the key. Custom plugin migration requires Python.
        obj.remove("custom_plugin_paths");
    }
}

/// v1.1 upgrade: add new default filters.
fn upgrade_v1_1(baseline: &mut Value) {
    if let Some(filters) = baseline
        .get_mut("filters_used")
        .and_then(|v| v.as_array_mut())
    {
        filters.push(json!({"path": "detect_secrets.filters.heuristic.is_lock_file"}));
        filters
            .push(json!({"path": "detect_secrets.filters.heuristic.is_not_alphanumeric_string"}));
        filters.push(json!({"path": "detect_secrets.filters.heuristic.is_swagger_file"}));
    }
}

// ---------------------------------------------------------------------------
// Time helper
// ---------------------------------------------------------------------------

/// Get the current UTC time formatted as `YYYY-MM-DDTHH:MM:SSZ`.
fn time_now_utc() -> String {
    // Use std::time to get seconds since epoch, then convert to date components
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Convert to date/time components
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm based on Howard Hinnant's civil_from_days
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let year = if m <= 2 { y + 1 } else { y } as u64;

    (year, m, d)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SemVer ----

    #[test]
    fn test_semver_parse() {
        let v = SemVer::parse("1.5.0").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 5);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_semver_parse_invalid() {
        assert!(SemVer::parse("1.5").is_none());
        assert!(SemVer::parse("abc").is_none());
    }

    #[test]
    fn test_semver_comparison() {
        let v1 = SemVer::parse("0.12.0").unwrap();
        let v2 = SemVer::parse("1.0.0").unwrap();
        let v3 = SemVer::parse("1.5.0").unwrap();

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
        assert!(v3 > v2);
        assert_eq!(v1, SemVer::parse("0.12.0").unwrap());
    }

    // ---- load_from_file ----

    #[test]
    fn test_load_from_file_nonexistent() {
        let result = load_from_file("/nonexistent/baseline.json");
        assert!(result.is_err());
        if let Err(BaselineError::UnableToRead(msg)) = result {
            assert!(msg.contains("nonexistent"));
        }
    }

    #[test]
    fn test_load_from_file_valid() {
        let dir = std::env::temp_dir().join("ds_test_load_from_file");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("baseline.json");
        let content = json!({
            "version": "0.1.0",
            "plugins_used": [],
            "filters_used": [],
            "results": {}
        });
        fs::write(&path, serde_json::to_string_pretty(&content).unwrap()).unwrap();

        let loaded = load_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded["version"], "0.1.0");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_from_file_invalid_json() {
        let dir = std::env::temp_dir().join("ds_test_load_invalid");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("bad.json");
        fs::write(&path, "not json {{{").unwrap();

        let result = load_from_file(path.to_str().unwrap());
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- format_for_output ----

    #[test]
    fn test_format_for_output_basic() {
        let _serial = settings::serial_test();
        settings::cache_bust();
        let _guard = settings::default_settings();
        let secrets = SecretsCollection::new();

        let output = format_for_output(&secrets, false);
        assert_eq!(output["version"], BASELINE_VERSION);
        assert!(output["plugins_used"].is_array());
        assert!(output["filters_used"].is_array());
        assert!(output["results"].is_object());
        assert!(output["generated_at"].is_string());
    }

    #[test]
    fn test_format_for_output_slim_mode() {
        let _serial = settings::serial_test();
        settings::cache_bust();
        let _guard = settings::default_settings();

        let mut secrets = SecretsCollection::new();
        let secret = crate::potential_secret::PotentialSecret::new(
            "Secret Type",
            "test.py",
            "my_secret",
            5,
            None,
            false,
        );
        secrets.add_secret(secret);

        let output = format_for_output(&secrets, true);
        // Slim mode: no generated_at
        assert!(output.get("generated_at").is_none());

        // Slim mode: no line_number in results
        let results = output["results"].as_object().unwrap();
        let file_secrets = results["test.py"].as_array().unwrap();
        assert!(!file_secrets[0]
            .as_object()
            .unwrap()
            .contains_key("line_number"));
    }

    #[test]
    fn test_format_for_output_key_ordering() {
        let _serial = settings::serial_test();
        settings::cache_bust();
        let _guard = settings::default_settings();
        let secrets = SecretsCollection::new();

        let output = format_for_output(&secrets, false);
        // With serde_json preserve_order, keys should be in insertion order:
        // version, plugins_used, filters_used, results, generated_at
        let obj = output.as_object().unwrap();
        let keys: Vec<&String> = obj.keys().collect();
        assert_eq!(keys[0], "version");
        assert_eq!(keys[1], "plugins_used");
        assert_eq!(keys[2], "filters_used");
        assert_eq!(keys[3], "results");
        assert_eq!(keys[4], "generated_at");
    }

    // ---- save_to_file ----

    #[test]
    fn test_save_to_file_and_reload() {
        let _serial = settings::serial_test();
        settings::cache_bust();
        let _guard = settings::default_settings();
        let secrets = SecretsCollection::new();
        let output = format_for_output(&secrets, false);

        let dir = std::env::temp_dir().join("ds_test_save");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("baseline.json");

        save_to_file(&output, path.to_str().unwrap()).unwrap();

        // Verify trailing newline
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.ends_with('\n'));

        // Verify round-trip
        let loaded = load_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded["version"], BASELINE_VERSION);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_save_to_file_with_2_space_indent() {
        let output = json!({"version": "0.1.0", "results": {}});
        let dir = std::env::temp_dir().join("ds_test_indent");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("indent.json");

        save_to_file(&output, path.to_str().unwrap()).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        // serde_json's to_string_pretty uses 2-space indent
        assert!(raw.contains("  \"version\""));
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- upgrade ----

    #[test]
    fn test_upgrade_current_version_unchanged() {
        let baseline = json!({
            "version": BASELINE_VERSION,
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [],
            "results": {}
        });

        let result = upgrade(&baseline);
        assert_eq!(result, baseline);
    }

    #[test]
    fn test_upgrade_v0_12_migrate_exclude_regex() {
        let baseline = json!({
            "version": "0.11.0",
            "exclude_regex": "tests/.*",
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "results": {}
        });

        let result = upgrade(&baseline);

        // exclude_regex should be removed
        assert!(result.get("exclude_regex").is_none());
        // Should have word_list removed (v0.12 adds it then v1.0 removes it)
        assert!(result.get("word_list").is_none());
        // Should have filters_used from v1.0
        assert!(result["filters_used"].is_array());
        // version should be updated
        assert_eq!(result["version"], BASELINE_VERSION);
    }

    #[test]
    fn test_upgrade_v1_0_migrate_filters() {
        let baseline = json!({
            "version": "0.14.0",
            "exclude": {
                "files": "tests/.*",
                "lines": null
            },
            "word_list": {
                "file": null,
                "hash": null
            },
            "plugins_used": [
                {"name": "Base64HighEntropyString", "base64_limit": 4.5},
                {"name": "HexHighEntropyString", "hex_limit": 3.0}
            ],
            "results": {}
        });

        let result = upgrade(&baseline);

        // exclude and word_list should be removed
        assert!(result.get("exclude").is_none());
        assert!(result.get("word_list").is_none());

        // filters_used should exist
        let filters = result["filters_used"].as_array().unwrap();
        assert!(!filters.is_empty());

        // Should have the exclude_file filter with the pattern
        let has_exclude_file = filters.iter().any(|f| {
            f.get("path")
                .and_then(|v| v.as_str())
                .map(|s| s == "detect_secrets.filters.regex.should_exclude_file")
                .unwrap_or(false)
        });
        assert!(has_exclude_file);

        // base64_limit should be renamed to limit
        let plugins = result["plugins_used"].as_array().unwrap();
        let b64 = plugins
            .iter()
            .find(|p| {
                p.get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s == "Base64HighEntropyString")
                    .unwrap_or(false)
            })
            .unwrap();
        assert!(b64.get("base64_limit").is_none());
        assert_eq!(b64["limit"], 4.5);

        let hex = plugins
            .iter()
            .find(|p| {
                p.get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s == "HexHighEntropyString")
                    .unwrap_or(false)
            })
            .unwrap();
        assert!(hex.get("hex_limit").is_none());
        assert_eq!(hex["limit"], 3.0);
    }

    #[test]
    fn test_upgrade_v1_0_migrate_wordlist() {
        let baseline = json!({
            "version": "0.14.0",
            "word_list": {
                "file": "/path/to/wordlist.txt",
                "hash": "abc123"
            },
            "plugins_used": [],
            "results": {}
        });

        let result = upgrade(&baseline);

        let filters = result["filters_used"].as_array().unwrap();
        let wl = filters.iter().find(|f| {
            f.get("path")
                .and_then(|v| v.as_str())
                .map(|s| s == "detect_secrets.filters.wordlist.should_exclude_secret")
                .unwrap_or(false)
        });
        assert!(wl.is_some());
        let wl = wl.unwrap();
        assert_eq!(wl["file_name"], "/path/to/wordlist.txt");
        assert_eq!(wl["file_hash"], "abc123");
        assert_eq!(wl["min_length"], 3);
    }

    #[test]
    fn test_upgrade_v1_1_adds_new_filters() {
        let baseline = json!({
            "version": "1.0.0",
            "plugins_used": [],
            "filters_used": [
                {"path": "detect_secrets.filters.heuristic.is_sequential_string"}
            ],
            "results": {}
        });

        let result = upgrade(&baseline);

        let filters = result["filters_used"].as_array().unwrap();
        let paths: Vec<&str> = filters
            .iter()
            .filter_map(|f| f.get("path").and_then(|v| v.as_str()))
            .collect();

        assert!(paths.contains(&"detect_secrets.filters.heuristic.is_lock_file"));
        assert!(paths.contains(&"detect_secrets.filters.heuristic.is_not_alphanumeric_string"));
        assert!(paths.contains(&"detect_secrets.filters.heuristic.is_swagger_file"));
    }

    #[test]
    fn test_upgrade_custom_plugins_removed() {
        let baseline = json!({
            "version": "0.14.0",
            "custom_plugin_paths": ["/path/to/plugin.py"],
            "plugins_used": [],
            "word_list": {"file": null, "hash": null},
            "results": {}
        });

        let result = upgrade(&baseline);
        assert!(result.get("custom_plugin_paths").is_none());
    }

    // ---- load (integration) ----

    #[test]
    fn test_load_configures_settings_and_returns_secrets() {
        let _serial = settings::serial_test();
        settings::cache_bust();

        let baseline = json!({
            "version": BASELINE_VERSION,
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [
                {"path": "detect_secrets.filters.heuristic.is_sequential_string"}
            ],
            "results": {
                "test.py": [{
                    "type": "AWS Access Key",
                    "hashed_secret": "abc123",
                    "is_verified": false,
                    "line_number": 5
                }]
            }
        });

        let collection = load(&baseline, "").unwrap();
        assert_eq!(collection.len(), 1);

        // Check that settings were configured
        let settings = settings::get_settings();
        assert!(settings.plugins.contains_key("AWSKeyDetector"));
    }

    #[test]
    fn test_load_with_filename_sets_baseline_filter() {
        let _serial = settings::serial_test();
        settings::cache_bust();

        let baseline = json!({
            "version": BASELINE_VERSION,
            "plugins_used": [],
            "filters_used": [],
            "results": {}
        });

        let _ = load(&baseline, ".secrets.baseline").unwrap();

        let settings = settings::get_settings();
        assert!(settings
            .filters
            .contains_key("detect_secrets.filters.common.is_baseline_file"));
    }

    // ---- create (integration) ----

    #[test]
    fn test_create_empty_paths() {
        let _serial = settings::serial_test();
        let dir = std::env::temp_dir().join("ds_test_create_empty");
        let _ = fs::create_dir_all(&dir);

        settings::cache_bust();
        let _guard = settings::default_settings();

        let secrets = create(&[], false, dir.to_str().unwrap());
        assert!(secrets.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_create_with_file() {
        let _serial = settings::serial_test();
        settings::cache_bust();
        let _guard = settings::default_settings();

        // Create a temp file with a known secret
        let dir = std::env::temp_dir().join("ds_test_create");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("secret.py");
        fs::write(&path, "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n").unwrap();

        let secrets = create(
            &[path.to_str().unwrap().to_string()],
            false,
            dir.to_str().unwrap(),
        );
        // Should find at least one secret (AWS key)
        assert!(!secrets.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    // ---- round trip ----

    #[test]
    fn test_round_trip_create_save_load() {
        let _serial = settings::serial_test();
        settings::cache_bust();

        // Create a temp file with a known secret
        let dir = std::env::temp_dir().join("ds_test_roundtrip");
        let _ = fs::create_dir_all(&dir);
        let secret_file = dir.join("secret.py");
        fs::write(&secret_file, "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n").unwrap();

        // Phase 1: create baseline with default settings
        let original_len;
        {
            let _guard = settings::default_settings();
            let secrets = create(
                &[secret_file.to_str().unwrap().to_string()],
                false,
                dir.to_str().unwrap(),
            );
            original_len = secrets.len();

            // Format and save
            let output = format_for_output(&secrets, false);
            let baseline_path = dir.join(".secrets.baseline");
            save_to_file(&output, baseline_path.to_str().unwrap()).unwrap();
        }

        // Phase 2: load back from saved baseline
        let baseline_path = dir.join(".secrets.baseline");
        let loaded_dict = load_from_file(baseline_path.to_str().unwrap()).unwrap();
        settings::cache_bust();
        let loaded_secrets = load(&loaded_dict, baseline_path.to_str().unwrap()).unwrap();

        // Compare
        assert_eq!(original_len, loaded_secrets.len());
        assert!(loaded_secrets.len() > 0);

        let _ = fs::remove_dir_all(&dir);
    }

    // ---- time helper ----

    #[test]
    fn test_time_now_utc_format() {
        let ts = time_now_utc();
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2026-03-03 is day 20515 since epoch
        let (y, m, d) = days_to_ymd(20515);
        assert_eq!((y, m, d), (2026, 3, 3));
    }
}
