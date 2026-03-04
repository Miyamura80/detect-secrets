//! Settings and configuration system for detect-secrets.
//!
//! Ported from `detect_secrets/settings.py`. Provides:
//! - [`Settings`] — central config holding active plugins and filters
//! - [`get_settings`] / [`get_settings_mut`] — singleton access
//! - [`configure_settings_from_baseline`] — load from baseline JSON
//! - [`default_settings`] / [`transient_settings`] — scoped overrides
//! - [`get_plugins`] / [`get_filters`] — resolved plugin/filter instances

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use once_cell::sync::Lazy;
use serde_json::Value;

use crate::filters::registry::FilterId;
use crate::plugin::SecretDetector;

// ---------------------------------------------------------------------------
// Plugin registry — maps class name → constructor function
// ---------------------------------------------------------------------------

/// A boxed plugin constructor: `fn(config) -> Box<dyn SecretDetector>`.
type PluginFactory = fn(&Value) -> Box<dyn SecretDetector + Send + Sync>;

/// A boxed factory for external (custom) plugins (e.g. Python plugins via PyO3).
///
/// Unlike `PluginFactory` (a plain function pointer), this is a trait object
/// that can capture state (such as a Python class reference).
pub type ExternalPluginFactory =
    Arc<dyn Fn(&Value) -> Box<dyn SecretDetector + Send + Sync> + Send + Sync>;

/// Entry in the plugin registry.
struct PluginEntry {
    /// The class name used in baselines, e.g. `"AWSKeyDetector"`.
    class_name: &'static str,
    /// The secret type string (used for reverse lookup).
    _secret_type: &'static str,
    /// Constructor that accepts a JSON config object.
    factory: PluginFactory,
}

// Macro to reduce boilerplate for simple plugins with no config
macro_rules! simple_plugin {
    ($class_name:expr, $secret_type:expr, $struct_name:ident) => {
        PluginEntry {
            class_name: $class_name,
            _secret_type: $secret_type,
            factory: |_config: &Value| Box::new($struct_name::default()),
        }
    };
}

/// All built-in plugins with their class names and factories.
fn builtin_plugins() -> Vec<PluginEntry> {
    use crate::auth_detectors::*;
    use crate::cloud_detectors::*;
    use crate::high_entropy_strings::*;
    use crate::keyword_detector::KeywordDetector;
    use crate::saas_detectors::*;

    vec![
        // High-entropy plugins (parameterised)
        PluginEntry {
            class_name: "Base64HighEntropyString",
            _secret_type: "Base64 High Entropy String",
            factory: |config| {
                let limit = config
                    .get("limit")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(Base64HighEntropyString::DEFAULT_LIMIT);
                Box::new(Base64HighEntropyString::new(limit))
            },
        },
        PluginEntry {
            class_name: "HexHighEntropyString",
            _secret_type: "Hex High Entropy String",
            factory: |config| {
                let limit = config
                    .get("limit")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(HexHighEntropyString::DEFAULT_LIMIT);
                Box::new(HexHighEntropyString::new(limit))
            },
        },
        // Cloud detectors
        simple_plugin!("AWSKeyDetector", "AWS Access Key", AWSKeyDetector),
        simple_plugin!(
            "AzureStorageKeyDetector",
            "Azure Storage Account access key",
            AzureStorageKeyDetector
        ),
        simple_plugin!(
            "ArtifactoryDetector",
            "Artifactory Credentials",
            ArtifactoryDetector
        ),
        simple_plugin!("CloudantDetector", "Cloudant Credentials", CloudantDetector),
        simple_plugin!(
            "IbmCloudIamDetector",
            "IBM Cloud IAM Key",
            IbmCloudIamDetector
        ),
        simple_plugin!(
            "IbmCosHmacDetector",
            "IBM COS HMAC Credentials",
            IbmCosHmacDetector
        ),
        simple_plugin!(
            "SoftlayerDetector",
            "SoftLayer Credentials",
            SoftlayerDetector
        ),
        // Auth detectors
        simple_plugin!(
            "BasicAuthDetector",
            "Basic Auth Credentials",
            BasicAuthDetector
        ),
        simple_plugin!(
            "DiscordBotTokenDetector",
            "Discord Bot Token",
            DiscordBotTokenDetector
        ),
        simple_plugin!("GitHubTokenDetector", "GitHub Token", GitHubTokenDetector),
        simple_plugin!("GitLabTokenDetector", "GitLab Token", GitLabTokenDetector),
        simple_plugin!("JwtTokenDetector", "JSON Web Token", JwtTokenDetector),
        simple_plugin!("PrivateKeyDetector", "Private Key", PrivateKeyDetector),
        // SaaS detectors
        simple_plugin!(
            "MailchimpDetector",
            "Mailchimp Access Key",
            MailchimpDetector
        ),
        simple_plugin!("NpmDetector", "NPM tokens", NpmDetector),
        simple_plugin!("OpenAIDetector", "OpenAI API Key", OpenAIDetector),
        simple_plugin!("PypiTokenDetector", "PyPI upload token", PypiTokenDetector),
        simple_plugin!("SendGridDetector", "SendGrid API key", SendGridDetector),
        simple_plugin!("SlackDetector", "Slack Token", SlackDetector),
        simple_plugin!(
            "SquareOAuthDetector",
            "Square OAuth Secret",
            SquareOAuthDetector
        ),
        simple_plugin!("StripeDetector", "Stripe Access Key", StripeDetector),
        simple_plugin!(
            "TelegramBotTokenDetector",
            "Telegram Bot Token",
            TelegramBotTokenDetector
        ),
        simple_plugin!("TwilioKeyDetector", "Twilio API Key", TwilioKeyDetector),
        simple_plugin!("IpPublicDetector", "IP Address", IpPublicDetector),
        // Keyword detector (parameterised)
        PluginEntry {
            class_name: "KeywordDetector",
            _secret_type: "Secret Keyword",
            factory: |config| {
                let exclude = config
                    .get("keyword_exclude")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Box::new(KeywordDetector::new(exclude.as_deref()))
            },
        },
    ]
}

/// Look up a plugin factory by class name. Returns `None` for unknown plugins.
fn find_plugin_factory(class_name: &str) -> Option<PluginFactory> {
    builtin_plugins()
        .into_iter()
        .find(|e| e.class_name == class_name)
        .map(|e| e.factory)
}

/// Returns a mapping from class name to factory for all built-in plugins.
pub fn get_mapping_from_class_name() -> HashMap<&'static str, PluginFactory> {
    builtin_plugins()
        .into_iter()
        .map(|e| (e.class_name, e.factory))
        .collect()
}

/// Returns all built-in plugin class names, sorted alphabetically.
pub fn all_plugin_class_names() -> Vec<&'static str> {
    let mut names: Vec<&str> = builtin_plugins().iter().map(|e| e.class_name).collect();
    names.sort_unstable();
    names
}

// ---------------------------------------------------------------------------
// External (custom) plugin registry
// ---------------------------------------------------------------------------

static EXTERNAL_PLUGIN_REGISTRY: Lazy<Mutex<HashMap<String, ExternalPluginFactory>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Register an external plugin factory by class name.
///
/// Used by the Python crate to register custom Python plugins that implement
/// the `SecretDetector` interface via a PyO3 adapter.
pub fn register_external_plugin(class_name: String, factory: ExternalPluginFactory) {
    EXTERNAL_PLUGIN_REGISTRY
        .lock()
        .expect("external plugin registry poisoned")
        .insert(class_name, factory);
}

/// Remove an external plugin by class name.
pub fn unregister_external_plugin(class_name: &str) {
    EXTERNAL_PLUGIN_REGISTRY
        .lock()
        .expect("external plugin registry poisoned")
        .remove(class_name);
}

/// Clear all external plugins.
pub fn clear_external_plugins() {
    EXTERNAL_PLUGIN_REGISTRY
        .lock()
        .expect("external plugin registry poisoned")
        .clear();
}

/// Get names of all registered external plugins.
pub fn get_external_plugin_names() -> Vec<String> {
    EXTERNAL_PLUGIN_REGISTRY
        .lock()
        .expect("external plugin registry poisoned")
        .keys()
        .cloned()
        .collect()
}

/// Returns a mapping from `secret_type` to `class_name` for all known plugins
/// (both built-in and external).
///
/// Matches Python's `get_mapping_from_secret_type_to_class()` from
/// `detect_secrets.core.plugins.util`.
pub fn get_mapping_from_secret_type_to_class() -> HashMap<String, String> {
    let mut mapping = HashMap::new();

    // Built-in plugins
    for entry in builtin_plugins() {
        mapping.insert(entry._secret_type.to_string(), entry.class_name.to_string());
    }

    // External plugins — instantiate each to get its secret_type
    let ext_registry = EXTERNAL_PLUGIN_REGISTRY
        .lock()
        .expect("external plugin registry poisoned");
    for (class_name, factory) in ext_registry.iter() {
        let plugin = factory(&Value::Object(serde_json::Map::new()));
        mapping.insert(plugin.secret_type().to_string(), class_name.clone());
    }

    mapping
}

// ---------------------------------------------------------------------------
// Default filter set
// ---------------------------------------------------------------------------

/// Filters that are ALWAYS included (cannot be removed by configure_filters).
const DEFAULT_FILTERS: &[&str] = &[
    "detect_secrets.filters.common.is_invalid_file",
    "detect_secrets.filters.heuristic.is_non_text_file",
];

/// Filters included by default when settings are cleared.
const INITIAL_FILTERS: &[&str] = &[
    "detect_secrets.filters.common.is_invalid_file",
    "detect_secrets.filters.heuristic.is_non_text_file",
    "detect_secrets.filters.allowlist.is_line_allowlisted",
    "detect_secrets.filters.heuristic.is_sequential_string",
    "detect_secrets.filters.heuristic.is_potential_uuid",
    "detect_secrets.filters.heuristic.is_likely_id_string",
    "detect_secrets.filters.heuristic.is_templated_secret",
    "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign",
    "detect_secrets.filters.heuristic.is_indirect_reference",
    "detect_secrets.filters.heuristic.is_lock_file",
    "detect_secrets.filters.heuristic.is_not_alphanumeric_string",
    "detect_secrets.filters.heuristic.is_swagger_file",
];

// ---------------------------------------------------------------------------
// Settings struct
// ---------------------------------------------------------------------------

/// Central configuration for a detect-secrets session.
///
/// Mirrors Python's `Settings` class.  Holds:
/// - `plugins` — `{ class_name: { config… } }` for each enabled plugin.
/// - `filters` — `{ dotted_path: { config… } }` for each enabled filter.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `class_name → config dict` for each enabled plugin.
    pub plugins: HashMap<String, Value>,
    /// `dotted_path → config dict` for each enabled filter.
    pub filters: HashMap<String, Value>,
}

impl Default for Settings {
    fn default() -> Self {
        Self::new()
    }
}

impl Settings {
    /// Create a new Settings with default filter set and no plugins.
    pub fn new() -> Self {
        let filters = INITIAL_FILTERS
            .iter()
            .map(|&path| (path.to_string(), Value::Object(serde_json::Map::new())))
            .collect();

        Settings {
            plugins: HashMap::new(),
            filters,
        }
    }

    /// Reset to defaults (no plugins, default filters).
    pub fn clear(&mut self) {
        self.plugins.clear();
        self.filters = INITIAL_FILTERS
            .iter()
            .map(|&path| (path.to_string(), Value::Object(serde_json::Map::new())))
            .collect();
    }

    /// Replace this settings entirely with another.
    pub fn set(&mut self, other: &Settings) {
        self.plugins = other.plugins.clone();
        self.filters = other.filters.clone();
    }

    /// Configure plugins from a list of `{"name": "ClassName", ...params}` dicts.
    ///
    /// Matches Python's `Settings.configure_plugins()`.
    pub fn configure_plugins(&mut self, config: &[Value]) {
        for plugin_config in config {
            if let Some(name) = plugin_config.get("name").and_then(|v| v.as_str()) {
                // Clone config, remove `name` key — remaining keys are plugin params.
                let mut params = plugin_config.clone();
                if let Some(obj) = params.as_object_mut() {
                    obj.remove("name");
                }
                self.plugins.insert(name.to_string(), params);
            }
        }
    }

    /// Disable plugins by class name.
    pub fn disable_plugins(&mut self, plugin_names: &[&str]) {
        for name in plugin_names {
            self.plugins.remove(*name);
        }
    }

    /// Configure filters from a list of `{"path": "dotted.path", ...params}` dicts.
    ///
    /// Matches Python's `Settings.configure_filters()`. Resets to DEFAULT_FILTERS
    /// first, then adds all provided filters.
    pub fn configure_filters(&mut self, config: &[Value]) {
        // Start with only the mandatory default filters
        self.filters = DEFAULT_FILTERS
            .iter()
            .map(|&path| (path.to_string(), Value::Object(serde_json::Map::new())))
            .collect();

        // Add all configured filters
        for filter_config in config {
            if let Some(path) = filter_config.get("path").and_then(|v| v.as_str()) {
                self.filters.insert(path.to_string(), filter_config.clone());
            }
        }
    }

    /// Disable filters by path.
    pub fn disable_filters(&mut self, filter_paths: &[&str]) {
        for path in filter_paths {
            self.filters.remove(*path);
        }
    }

    /// Serialize to baseline JSON format.
    ///
    /// Returns `{"plugins_used": [...], "filters_used": [...]}`.
    ///
    /// `plugins_used` includes all enabled plugins with their config parameters.
    /// `filters_used` includes only non-default filters with their config.
    pub fn json(&self) -> Value {
        // Build plugins_used — instantiate each plugin to get its canonical JSON
        let mut plugins_used: Vec<Value> = Vec::new();
        for (class_name, config) in &self.plugins {
            if let Some(factory) = find_plugin_factory(class_name) {
                let plugin = factory(config);
                let mut serialized = plugin.json();

                // Merge settings config (e.g. `path` for custom plugins)
                if let (Some(ser_obj), Some(cfg_obj)) =
                    (serialized.as_object_mut(), config.as_object())
                {
                    // Settings config goes first (underneath)
                    let mut merged = cfg_obj.clone();
                    // Then plugin's own JSON overrides
                    for (k, v) in ser_obj.iter() {
                        merged.insert(k.clone(), v.clone());
                    }
                    // Ensure `name` is first by rebuilding
                    let name = merged
                        .remove("name")
                        .unwrap_or_else(|| Value::String(class_name.clone()));
                    let mut ordered = serde_json::Map::new();
                    ordered.insert("name".to_string(), name);
                    for (k, v) in merged {
                        ordered.insert(k, v);
                    }
                    serialized = Value::Object(ordered);
                }

                plugins_used.push(serialized);
            } else {
                // Unknown plugin — emit as-is with name
                let mut obj = serde_json::Map::new();
                obj.insert("name".to_string(), Value::String(class_name.clone()));
                if let Some(cfg_obj) = config.as_object() {
                    for (k, v) in cfg_obj {
                        obj.insert(k.clone(), v.clone());
                    }
                }
                plugins_used.push(Value::Object(obj));
            }
        }

        // Sort plugins by name (case-insensitive)
        plugins_used.sort_by(|a, b| {
            let name_a = a
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let name_b = b
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            name_a.cmp(&name_b)
        });

        // Build filters_used — exclude DEFAULT_FILTERS
        let default_set: std::collections::HashSet<&str> =
            DEFAULT_FILTERS.iter().copied().collect();
        let mut filters_used: Vec<Value> = Vec::new();
        for (path, config) in &self.filters {
            if default_set.contains(path.as_str()) {
                continue;
            }
            let mut obj = serde_json::Map::new();
            obj.insert("path".to_string(), Value::String(path.clone()));
            if let Some(cfg_obj) = config.as_object() {
                for (k, v) in cfg_obj {
                    if k != "path" {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
            filters_used.push(Value::Object(obj));
        }

        // Sort filters by path (case-insensitive)
        filters_used.sort_by(|a, b| {
            let path_a = a
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let path_b = b
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            path_a.cmp(&path_b)
        });

        serde_json::json!({
            "plugins_used": plugins_used,
            "filters_used": filters_used,
        })
    }

    /// Get the list of active filter IDs (only for built-in filters).
    pub fn active_filter_ids(&self) -> Vec<FilterId> {
        self.filters
            .keys()
            .filter_map(|path| FilterId::from_path(path))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

static GLOBAL_SETTINGS: Lazy<Mutex<Settings>> = Lazy::new(|| Mutex::new(Settings::new()));

/// Access the global settings singleton (read-only).
pub fn get_settings() -> MutexGuard<'static, Settings> {
    GLOBAL_SETTINGS.lock().expect("settings mutex poisoned")
}

/// Access the global settings singleton (mutable).
///
/// This is the same lock as `get_settings()` — the distinction is for
/// clarity at call-sites.
pub fn get_settings_mut() -> MutexGuard<'static, Settings> {
    GLOBAL_SETTINGS.lock().expect("settings mutex poisoned")
}

/// Reset the global singleton to default state.
pub fn cache_bust() {
    get_settings_mut().clear();
}

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

/// Load settings from a baseline JSON dict.
///
/// Matches Python's `configure_settings_from_baseline()`.
pub fn configure_settings_from_baseline(baseline: &Value, filename: &str) {
    let mut settings = get_settings_mut();

    if let Some(plugins_used) = baseline.get("plugins_used").and_then(|v| v.as_array()) {
        settings.configure_plugins(plugins_used);
    }

    if let Some(filters_used) = baseline.get("filters_used").and_then(|v| v.as_array()) {
        settings.configure_filters(filters_used);
    }

    // If a baseline filename is provided, add it to the baseline file filter
    if !filename.is_empty() {
        let mut config = serde_json::Map::new();
        config.insert("filename".to_string(), Value::String(filename.to_string()));
        settings.filters.insert(
            "detect_secrets.filters.common.is_baseline_file".to_string(),
            Value::Object(config),
        );
    }
}

/// Instantiate all configured plugins based on current settings.
///
/// Checks built-in plugins first, then the external plugin registry for
/// custom Python plugins.
///
/// Returns a `Vec<Box<dyn SecretDetector + Send + Sync>>`.
pub fn get_plugins() -> Vec<Box<dyn SecretDetector + Send + Sync>> {
    // Clone plugin entries out of the settings lock to avoid holding two locks.
    let plugin_entries: Vec<(String, Value)> = {
        let settings = get_settings();
        settings
            .plugins
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };

    let ext_registry = EXTERNAL_PLUGIN_REGISTRY
        .lock()
        .expect("external plugin registry poisoned");

    let mut plugins: Vec<Box<dyn SecretDetector + Send + Sync>> = Vec::new();

    for (class_name, config) in &plugin_entries {
        if let Some(factory) = find_plugin_factory(class_name) {
            plugins.push(factory(config));
        } else if let Some(ext_factory) = ext_registry.get(class_name.as_str()) {
            plugins.push(ext_factory(config));
        }
    }

    plugins
}

/// Returns the active filter IDs from current settings.
pub fn get_active_filters() -> Vec<FilterId> {
    get_settings().active_filter_ids()
}

// ---------------------------------------------------------------------------
// Scoped settings (context manager equivalents)
// ---------------------------------------------------------------------------

/// RAII guard that restores settings when dropped.
///
/// Rust equivalent of Python's `transient_settings()` context manager.
pub struct TransientSettingsGuard {
    original: Settings,
}

impl Drop for TransientSettingsGuard {
    fn drop(&mut self) {
        let mut settings = get_settings_mut();
        settings.set(&self.original);
    }
}

/// Apply transient settings and return a guard that restores on drop.
///
/// Usage:
/// ```ignore
/// let _guard = transient_settings(&config);
/// // settings are now modified
/// // when _guard goes out of scope, original settings are restored
/// ```
pub fn transient_settings(config: &Value) -> TransientSettingsGuard {
    // Save original
    let original = get_settings().clone();

    // Apply new config
    cache_bust();
    configure_settings_from_baseline(config, "");

    TransientSettingsGuard { original }
}

/// Apply default settings (all built-in plugins, default filters) and return
/// a guard that restores on drop.
///
/// Matches Python's `default_settings()` context manager.
pub fn default_settings() -> TransientSettingsGuard {
    let all_plugins: Vec<Value> = all_plugin_class_names()
        .into_iter()
        .map(|name| serde_json::json!({ "name": name }))
        .collect();

    let config = serde_json::json!({
        "plugins_used": all_plugins,
    });

    transient_settings(&config)
}

// ---------------------------------------------------------------------------
// Test serialization — prevents parallel tests from clobbering the global
// settings singleton. Tests that call `default_settings()` or modify the
// global settings must acquire this lock first.
// ---------------------------------------------------------------------------

/// A process-wide mutex that serialises tests needing the global settings
/// singleton.  Any test that calls `default_settings()`, `cache_bust()`, or
/// otherwise mutates `GLOBAL_SETTINGS` should start with:
///
/// ```ignore
/// let _serial = settings::serial_test();
/// ```
///
/// This returns a `MutexGuard` that lives until end-of-scope, ensuring no
/// other settings-dependent test runs concurrently.
#[cfg(test)]
static TEST_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[cfg(test)]
pub fn serial_test() -> MutexGuard<'static, ()> {
    TEST_MUTEX.lock().expect("test mutex poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: create a Settings without touching the global singleton
    fn fresh_settings() -> Settings {
        Settings::new()
    }

    // ---- Settings::new / clear ----

    #[test]
    fn test_new_settings_has_no_plugins() {
        let s = fresh_settings();
        assert!(s.plugins.is_empty());
    }

    #[test]
    fn test_new_settings_has_default_filters() {
        let s = fresh_settings();
        assert!(s
            .filters
            .contains_key("detect_secrets.filters.common.is_invalid_file"));
        assert!(s
            .filters
            .contains_key("detect_secrets.filters.heuristic.is_non_text_file"));
        assert!(s
            .filters
            .contains_key("detect_secrets.filters.allowlist.is_line_allowlisted"));
        assert!(s
            .filters
            .contains_key("detect_secrets.filters.heuristic.is_sequential_string"));
        assert_eq!(s.filters.len(), INITIAL_FILTERS.len());
    }

    #[test]
    fn test_clear_resets_to_defaults() {
        let mut s = fresh_settings();
        s.plugins.insert("Foo".to_string(), serde_json::json!({}));
        s.filters.clear();
        s.clear();
        assert!(s.plugins.is_empty());
        assert_eq!(s.filters.len(), INITIAL_FILTERS.len());
    }

    // ---- configure_plugins ----

    #[test]
    fn test_configure_plugins_basic() {
        let mut s = fresh_settings();
        s.configure_plugins(&[serde_json::json!({"name": "AWSKeyDetector"})]);
        assert!(s.plugins.contains_key("AWSKeyDetector"));
        assert_eq!(s.plugins["AWSKeyDetector"], serde_json::json!({}));
    }

    #[test]
    fn test_configure_plugins_with_params() {
        let mut s = fresh_settings();
        s.configure_plugins(&[
            serde_json::json!({"name": "Base64HighEntropyString", "limit": 4.5}),
        ]);
        assert!(s.plugins.contains_key("Base64HighEntropyString"));
        assert_eq!(
            s.plugins["Base64HighEntropyString"]["limit"],
            serde_json::json!(4.5)
        );
    }

    #[test]
    fn test_configure_plugins_multiple() {
        let mut s = fresh_settings();
        s.configure_plugins(&[
            serde_json::json!({"name": "AWSKeyDetector"}),
            serde_json::json!({"name": "BasicAuthDetector"}),
        ]);
        assert_eq!(s.plugins.len(), 2);
    }

    #[test]
    fn test_configure_plugins_name_excluded_from_config() {
        let mut s = fresh_settings();
        s.configure_plugins(&[serde_json::json!({"name": "AWSKeyDetector"})]);
        // The config should NOT contain "name"
        let config = &s.plugins["AWSKeyDetector"];
        assert!(config.get("name").is_none());
    }

    // ---- disable_plugins ----

    #[test]
    fn test_disable_plugins() {
        let mut s = fresh_settings();
        s.configure_plugins(&[
            serde_json::json!({"name": "AWSKeyDetector"}),
            serde_json::json!({"name": "BasicAuthDetector"}),
        ]);
        s.disable_plugins(&["AWSKeyDetector"]);
        assert!(!s.plugins.contains_key("AWSKeyDetector"));
        assert!(s.plugins.contains_key("BasicAuthDetector"));
    }

    #[test]
    fn test_disable_plugins_unknown_is_noop() {
        let mut s = fresh_settings();
        s.configure_plugins(&[serde_json::json!({"name": "AWSKeyDetector"})]);
        s.disable_plugins(&["NonExistent"]);
        assert_eq!(s.plugins.len(), 1);
    }

    // ---- configure_filters ----

    #[test]
    fn test_configure_filters_resets_to_defaults() {
        let mut s = fresh_settings();
        s.configure_filters(&[serde_json::json!({
            "path": "detect_secrets.filters.heuristic.is_sequential_string"
        })]);
        // Should have DEFAULT_FILTERS + the configured filter
        assert!(s
            .filters
            .contains_key("detect_secrets.filters.common.is_invalid_file"));
        assert!(s
            .filters
            .contains_key("detect_secrets.filters.heuristic.is_non_text_file"));
        assert!(s
            .filters
            .contains_key("detect_secrets.filters.heuristic.is_sequential_string"));
    }

    #[test]
    fn test_configure_filters_with_params() {
        let mut s = fresh_settings();
        s.configure_filters(&[serde_json::json!({
            "path": "detect_secrets.filters.regex.should_exclude_file",
            "pattern": "^test.*"
        })]);
        let config = &s.filters["detect_secrets.filters.regex.should_exclude_file"];
        assert_eq!(config["pattern"], serde_json::json!("^test.*"));
    }

    #[test]
    fn test_configure_filters_replaces_non_defaults() {
        let mut s = fresh_settings();
        // Start with 12 initial filters
        assert_eq!(s.filters.len(), INITIAL_FILTERS.len());
        // Configure with just one non-default filter
        s.configure_filters(&[serde_json::json!({
            "path": "detect_secrets.filters.heuristic.is_sequential_string"
        })]);
        // Should have 2 defaults + 1 configured
        assert_eq!(s.filters.len(), 3);
    }

    // ---- disable_filters ----

    #[test]
    fn test_disable_filters() {
        let mut s = fresh_settings();
        let original_len = s.filters.len();
        s.disable_filters(&["detect_secrets.filters.heuristic.is_sequential_string"]);
        assert_eq!(s.filters.len(), original_len - 1);
        assert!(!s
            .filters
            .contains_key("detect_secrets.filters.heuristic.is_sequential_string"));
    }

    // ---- json ----

    #[test]
    fn test_json_empty_plugins() {
        let s = fresh_settings();
        let j = s.json();
        assert_eq!(j["plugins_used"], serde_json::json!([]));
    }

    #[test]
    fn test_json_with_plugins() {
        let mut s = fresh_settings();
        s.configure_plugins(&[serde_json::json!({"name": "AWSKeyDetector"})]);
        let j = s.json();
        let plugins = j["plugins_used"].as_array().unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0]["name"], "AWSKeyDetector");
    }

    #[test]
    fn test_json_plugins_sorted_by_name() {
        let mut s = fresh_settings();
        s.configure_plugins(&[
            serde_json::json!({"name": "PrivateKeyDetector"}),
            serde_json::json!({"name": "AWSKeyDetector"}),
            serde_json::json!({"name": "BasicAuthDetector"}),
        ]);
        let j = s.json();
        let plugins = j["plugins_used"].as_array().unwrap();
        let names: Vec<&str> = plugins
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["AWSKeyDetector", "BasicAuthDetector", "PrivateKeyDetector"]
        );
    }

    #[test]
    fn test_json_filters_exclude_defaults() {
        let s = fresh_settings();
        let j = s.json();
        let filters = j["filters_used"].as_array().unwrap();
        // All initial non-default filters should appear
        for f in filters {
            let path = f["path"].as_str().unwrap();
            assert!(
                !DEFAULT_FILTERS.contains(&path),
                "Default filter {path} should not appear in filters_used"
            );
        }
    }

    #[test]
    fn test_json_filters_sorted_by_path() {
        let s = fresh_settings();
        let j = s.json();
        let filters = j["filters_used"].as_array().unwrap();
        let paths: Vec<&str> = filters
            .iter()
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted);
    }

    #[test]
    fn test_json_plugin_with_limit() {
        let mut s = fresh_settings();
        s.configure_plugins(&[
            serde_json::json!({"name": "Base64HighEntropyString", "limit": 5.0}),
        ]);
        let j = s.json();
        let plugins = j["plugins_used"].as_array().unwrap();
        assert_eq!(plugins[0]["name"], "Base64HighEntropyString");
        // The plugin factory creates with limit=5.0, and plugin.json() returns limit
        assert_eq!(plugins[0]["limit"], serde_json::json!(5.0));
    }

    // ---- set ----

    #[test]
    fn test_set_replaces_settings() {
        let mut s1 = fresh_settings();
        s1.configure_plugins(&[serde_json::json!({"name": "AWSKeyDetector"})]);

        let mut s2 = fresh_settings();
        s2.set(&s1);
        assert!(s2.plugins.contains_key("AWSKeyDetector"));
    }

    // ---- active_filter_ids ----

    #[test]
    fn test_active_filter_ids() {
        let s = fresh_settings();
        let ids = s.active_filter_ids();
        assert!(ids.contains(&FilterId::IsInvalidFile));
        assert!(ids.contains(&FilterId::IsNonTextFile));
        assert!(ids.contains(&FilterId::IsSequentialString));
    }

    #[test]
    fn test_active_filter_ids_excludes_unknown() {
        let mut s = fresh_settings();
        s.filters
            .insert("some.custom.filter".to_string(), serde_json::json!({}));
        let ids = s.active_filter_ids();
        // Custom filter paths not in FilterId are ignored
        assert_eq!(ids.len(), INITIAL_FILTERS.len());
    }

    // ---- configure_settings_from_baseline ----

    #[test]
    fn test_configure_from_baseline_plugins() {
        let mut s = fresh_settings();
        let baseline = serde_json::json!({
            "plugins_used": [
                {"name": "AWSKeyDetector"},
                {"name": "Base64HighEntropyString", "limit": 4.0}
            ]
        });

        if let Some(plugins_used) = baseline.get("plugins_used").and_then(|v| v.as_array()) {
            s.configure_plugins(plugins_used);
        }

        assert!(s.plugins.contains_key("AWSKeyDetector"));
        assert!(s.plugins.contains_key("Base64HighEntropyString"));
        assert_eq!(
            s.plugins["Base64HighEntropyString"]["limit"],
            serde_json::json!(4.0)
        );
    }

    #[test]
    fn test_configure_from_baseline_filters() {
        let mut s = fresh_settings();
        let baseline = serde_json::json!({
            "filters_used": [
                {"path": "detect_secrets.filters.heuristic.is_sequential_string"},
                {"path": "detect_secrets.filters.regex.should_exclude_file", "pattern": "^test"}
            ]
        });

        if let Some(filters_used) = baseline.get("filters_used").and_then(|v| v.as_array()) {
            s.configure_filters(filters_used);
        }

        assert!(s
            .filters
            .contains_key("detect_secrets.filters.heuristic.is_sequential_string"));
        assert!(s
            .filters
            .contains_key("detect_secrets.filters.regex.should_exclude_file"));
    }

    // ---- all_plugin_class_names ----

    #[test]
    fn test_all_plugin_class_names() {
        let names = all_plugin_class_names();
        assert!(names.contains(&"AWSKeyDetector"));
        assert!(names.contains(&"Base64HighEntropyString"));
        assert!(names.contains(&"HexHighEntropyString"));
        assert!(names.contains(&"KeywordDetector"));
        assert!(names.contains(&"PrivateKeyDetector"));
        // Should be sorted
        for i in 1..names.len() {
            assert!(names[i - 1] <= names[i], "Names should be sorted");
        }
    }

    // ---- json round-trip ----

    #[test]
    fn test_json_roundtrip() {
        let mut s = fresh_settings();
        s.configure_plugins(&[
            serde_json::json!({"name": "AWSKeyDetector"}),
            serde_json::json!({"name": "Base64HighEntropyString", "limit": 4.5}),
        ]);
        s.configure_filters(&[
            serde_json::json!({"path": "detect_secrets.filters.heuristic.is_sequential_string"}),
            serde_json::json!({"path": "detect_secrets.filters.allowlist.is_line_allowlisted"}),
        ]);

        let j = s.json();

        // Reconstruct from JSON
        let mut s2 = fresh_settings();
        if let Some(plugins_used) = j.get("plugins_used").and_then(|v| v.as_array()) {
            s2.configure_plugins(plugins_used);
        }
        if let Some(filters_used) = j.get("filters_used").and_then(|v| v.as_array()) {
            s2.configure_filters(filters_used);
        }

        // Same plugins
        assert_eq!(s2.plugins.len(), 2);
        assert!(s2.plugins.contains_key("AWSKeyDetector"));
        assert!(s2.plugins.contains_key("Base64HighEntropyString"));

        // Same filters (2 defaults + 2 configured)
        assert!(s2
            .filters
            .contains_key("detect_secrets.filters.heuristic.is_sequential_string"));
        assert!(s2
            .filters
            .contains_key("detect_secrets.filters.allowlist.is_line_allowlisted"));
    }

    // ---- get_mapping_from_class_name ----

    #[test]
    fn test_get_mapping_has_all_plugins() {
        let mapping = get_mapping_from_class_name();
        assert!(mapping.contains_key("AWSKeyDetector"));
        assert!(mapping.contains_key("Base64HighEntropyString"));
        assert!(mapping.contains_key("HexHighEntropyString"));
        assert!(mapping.contains_key("KeywordDetector"));
        assert!(mapping.contains_key("BasicAuthDetector"));
        assert!(mapping.len() >= 20);
    }

    #[test]
    fn test_plugin_factory_creates_correct_type() {
        let mapping = get_mapping_from_class_name();
        let factory = mapping["AWSKeyDetector"];
        let plugin = factory(&serde_json::json!({}));
        assert_eq!(plugin.secret_type(), "AWS Access Key");
    }

    #[test]
    fn test_plugin_factory_with_params() {
        let mapping = get_mapping_from_class_name();
        let factory = mapping["Base64HighEntropyString"];
        let plugin = factory(&serde_json::json!({"limit": 5.0}));
        let j = plugin.json();
        assert_eq!(j["limit"], serde_json::json!(5.0));
    }

    // ---- External plugin registry ----

    #[test]
    fn test_register_external_plugin() {
        clear_external_plugins();

        let factory: ExternalPluginFactory = Arc::new(|_config| {
            struct DummyPlugin;
            impl SecretDetector for DummyPlugin {
                fn secret_type(&self) -> &str {
                    "Dummy Secret"
                }
                fn analyze_string(&self, _input: &str) -> Vec<String> {
                    vec![]
                }
            }
            Box::new(DummyPlugin)
        });

        register_external_plugin("DummyPlugin".to_string(), factory);

        let names = get_external_plugin_names();
        assert!(names.contains(&"DummyPlugin".to_string()));

        clear_external_plugins();
    }

    #[test]
    fn test_unregister_external_plugin() {
        clear_external_plugins();

        let factory: ExternalPluginFactory = Arc::new(|_config| {
            struct DummyPlugin;
            impl SecretDetector for DummyPlugin {
                fn secret_type(&self) -> &str {
                    "Dummy"
                }
                fn analyze_string(&self, _input: &str) -> Vec<String> {
                    vec![]
                }
            }
            Box::new(DummyPlugin)
        });

        register_external_plugin("DummyPlugin".to_string(), factory);
        assert!(get_external_plugin_names().contains(&"DummyPlugin".to_string()));

        unregister_external_plugin("DummyPlugin");
        assert!(!get_external_plugin_names().contains(&"DummyPlugin".to_string()));

        clear_external_plugins();
    }

    #[test]
    fn test_clear_external_plugins() {
        clear_external_plugins();

        let factory: ExternalPluginFactory = Arc::new(|_config| {
            struct DummyPlugin;
            impl SecretDetector for DummyPlugin {
                fn secret_type(&self) -> &str {
                    "Dummy"
                }
                fn analyze_string(&self, _input: &str) -> Vec<String> {
                    vec![]
                }
            }
            Box::new(DummyPlugin)
        });

        register_external_plugin("D1".to_string(), factory.clone());
        register_external_plugin("D2".to_string(), factory);

        assert_eq!(get_external_plugin_names().len(), 2);
        clear_external_plugins();
        assert_eq!(get_external_plugin_names().len(), 0);
    }

    #[test]
    fn test_get_plugins_includes_external() {
        let _serial = serial_test();
        let _guard = default_settings();
        clear_external_plugins();

        let factory: ExternalPluginFactory = Arc::new(|_config| {
            struct TestPlugin;
            impl SecretDetector for TestPlugin {
                fn secret_type(&self) -> &str {
                    "Test Secret"
                }
                fn analyze_string(&self, input: &str) -> Vec<String> {
                    if input.contains("test_secret_value") {
                        vec!["test_secret_value".to_string()]
                    } else {
                        vec![]
                    }
                }
            }
            Box::new(TestPlugin)
        });

        register_external_plugin("TestPlugin".to_string(), factory);

        // Add the plugin to settings
        {
            let mut settings = get_settings_mut();
            settings
                .plugins
                .insert("TestPlugin".to_string(), serde_json::json!({}));
        }

        let plugins = get_plugins();
        let has_test = plugins.iter().any(|p| p.secret_type() == "Test Secret");
        assert!(has_test, "get_plugins() should include external plugins");

        // Verify it can actually detect
        let test_plugin = plugins
            .iter()
            .find(|p| p.secret_type() == "Test Secret")
            .unwrap();
        let matches = test_plugin.analyze_string("contains test_secret_value here");
        assert_eq!(matches, vec!["test_secret_value"]);

        clear_external_plugins();
    }

    #[test]
    fn test_get_mapping_from_secret_type_to_class_builtin() {
        clear_external_plugins();

        let mapping = get_mapping_from_secret_type_to_class();

        assert_eq!(
            mapping.get("AWS Access Key").map(|s| s.as_str()),
            Some("AWSKeyDetector")
        );
        assert_eq!(
            mapping.get("Private Key").map(|s| s.as_str()),
            Some("PrivateKeyDetector")
        );
        assert_eq!(
            mapping
                .get("Base64 High Entropy String")
                .map(|s| s.as_str()),
            Some("Base64HighEntropyString")
        );
    }

    #[test]
    fn test_get_mapping_from_secret_type_to_class_includes_external() {
        clear_external_plugins();

        let factory: ExternalPluginFactory = Arc::new(|_config| {
            struct CustomPlugin;
            impl SecretDetector for CustomPlugin {
                fn secret_type(&self) -> &str {
                    "Custom Secret Type"
                }
                fn analyze_string(&self, _input: &str) -> Vec<String> {
                    vec![]
                }
            }
            Box::new(CustomPlugin)
        });

        register_external_plugin("CustomPlugin".to_string(), factory);

        let mapping = get_mapping_from_secret_type_to_class();
        assert_eq!(
            mapping.get("Custom Secret Type").map(|s| s.as_str()),
            Some("CustomPlugin")
        );

        // Built-in plugins should still be present
        assert!(mapping.contains_key("AWS Access Key"));

        clear_external_plugins();
    }
}
