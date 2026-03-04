//! File scanning pipeline for secret detection.
//!
//! Ported from `detect_secrets/core/scan.py`. Provides:
//! - [`scan_file`] — full pipeline: read file, iterate lines, apply plugins, apply filters
//! - [`scan_files`] — parallel file scanning with rayon
//! - [`scan_line`] — ad-hoc single-line scanning
//! - [`scan_diff`] — unified diff parsing and scanning
//! - [`get_files_to_scan`] — git-aware file discovery

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;

use crate::filters::allowlist;
use crate::filters::common;
use crate::filters::heuristic;
use crate::filters::regex_filter;
use crate::filters::registry::{get_filters_with_parameter, FilterId, FilterParam};
use crate::filters::wordlist::WordlistFilter;
use crate::plugin::SecretDetector;
use crate::potential_secret::PotentialSecret;
use crate::settings;

// ---------------------------------------------------------------------------
// External filter registry
// ---------------------------------------------------------------------------

/// Phase at which an external filter operates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterPhase {
    /// Applied before reading file (args: filename, "", "").
    File,
    /// Applied before plugin analysis (args: filename, line, "").
    Line,
    /// Applied after plugin detection (args: filename, line, secret).
    Secret,
}

/// A filter function: `fn(filename, line, secret) -> bool`.
///
/// Returns `true` if the item should be **excluded** (filtered out).
/// Only the arguments relevant to the filter's [`FilterPhase`] are populated;
/// the rest are empty strings.
pub type ExternalFilterFn = Arc<dyn Fn(&str, &str, &str) -> bool + Send + Sync>;

/// An external filter registered from Python (or any other host).
pub struct ExternalFilter {
    /// Python-style dotted path or `file://` URI identifying this filter.
    pub path: String,
    /// The filter function.
    pub filter_fn: ExternalFilterFn,
    /// Phase at which this filter operates.
    pub phase: FilterPhase,
}

static EXTERNAL_FILTER_REGISTRY: Lazy<Mutex<Vec<ExternalFilter>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

/// Register an external filter.
pub fn register_external_filter(filter: ExternalFilter) {
    EXTERNAL_FILTER_REGISTRY
        .lock()
        .expect("external filter registry poisoned")
        .push(filter);
}

/// Clear all external filters.
pub fn clear_external_filters() {
    EXTERNAL_FILTER_REGISTRY
        .lock()
        .expect("external filter registry poisoned")
        .clear();
}

// ---------------------------------------------------------------------------
// Code snippet context
// ---------------------------------------------------------------------------

/// Number of context lines before and after the target line.
const LINES_OF_CONTEXT: usize = 5;

/// Provides context around a target line, similar to Python's `CodeSnippet`.
struct CodeSnippet<'a> {
    lines: &'a [String],
    _start_line: usize,
    target_index: usize,
}

impl<'a> CodeSnippet<'a> {
    /// Get the previous line relative to the target (for allowlist detection).
    fn previous_line(&self) -> &str {
        if self.target_index > 0 {
            &self.lines[self.target_index - 1]
        } else {
            ""
        }
    }
}

/// Build a [`CodeSnippet`] for the given line number.
///
/// `all_lines` is the full file contents (0-indexed), `line_index` is the
/// 0-based index of the target line.
fn get_code_snippet<'a>(
    all_lines: &'a [String],
    line_index: usize,
    lines_of_context: usize,
) -> CodeSnippet<'a> {
    let start = line_index.saturating_sub(lines_of_context);
    let end = (line_index + lines_of_context + 1).min(all_lines.len());
    let target_index = line_index - start;

    CodeSnippet {
        lines: &all_lines[start..end],
        _start_line: start,
        target_index,
    }
}

// ---------------------------------------------------------------------------
// Filter application helpers
// ---------------------------------------------------------------------------

/// Context gathered from settings for filter application during scanning.
struct ScanFilterContext {
    active_filters: Vec<FilterId>,
    exclude_line_regexes: Vec<Regex>,
    exclude_file_regexes: Vec<Regex>,
    exclude_secret_regexes: Vec<Regex>,
    wordlist_filter: Option<WordlistFilter>,
    /// External file-level filters (from Python custom filters).
    external_file_filters: Vec<ExternalFilterFn>,
    /// External line-level filters.
    external_line_filters: Vec<ExternalFilterFn>,
    /// External secret-level filters.
    external_secret_filters: Vec<ExternalFilterFn>,
}

impl ScanFilterContext {
    /// Build from current settings.
    fn from_settings() -> Self {
        let s = settings::get_settings();
        let active_filters = s.active_filter_ids();

        // Compile regex filters from settings config
        let exclude_line_regexes =
            Self::compile_filter_patterns(&s, "detect_secrets.filters.regex.should_exclude_line");
        let exclude_file_regexes =
            Self::compile_filter_patterns(&s, "detect_secrets.filters.regex.should_exclude_file");
        let exclude_secret_regexes =
            Self::compile_filter_patterns(&s, "detect_secrets.filters.regex.should_exclude_secret");

        // Load wordlist filter if configured
        let wordlist_filter = Self::load_wordlist(&s);

        // Capture external filters by phase
        let mut external_file_filters = Vec::new();
        let mut external_line_filters = Vec::new();
        let mut external_secret_filters = Vec::new();
        {
            let ext_registry = EXTERNAL_FILTER_REGISTRY
                .lock()
                .expect("external filter registry poisoned");
            for filter in ext_registry.iter() {
                let f = filter.filter_fn.clone();
                match filter.phase {
                    FilterPhase::File => external_file_filters.push(f),
                    FilterPhase::Line => external_line_filters.push(f),
                    FilterPhase::Secret => external_secret_filters.push(f),
                }
            }
        }

        ScanFilterContext {
            active_filters,
            exclude_line_regexes,
            exclude_file_regexes,
            exclude_secret_regexes,
            wordlist_filter,
            external_file_filters,
            external_line_filters,
            external_secret_filters,
        }
    }

    fn compile_filter_patterns(s: &settings::Settings, filter_path: &str) -> Vec<Regex> {
        if let Some(config) = s.filters.get(filter_path) {
            if let Some(pattern) = config.get("pattern").and_then(|v| v.as_str()) {
                if let Ok(r) = Regex::new(pattern) {
                    return vec![r];
                }
            }
            // Also support array of patterns
            if let Some(patterns) = config.get("patterns").and_then(|v| v.as_array()) {
                let compiled: Vec<Regex> = patterns
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|p| Regex::new(p).ok())
                    .collect();
                if !compiled.is_empty() {
                    return compiled;
                }
            }
        }
        vec![]
    }

    fn load_wordlist(s: &settings::Settings) -> Option<WordlistFilter> {
        let config = s
            .filters
            .get("detect_secrets.filters.wordlist.should_exclude_secret")?;
        let filename = config.get("file_name").and_then(|v| v.as_str())?;
        let min_length = config
            .get("min_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(3) as usize;
        WordlistFilter::from_file(filename, min_length).ok()
    }
}

/// Check if a filename should be filtered out before scanning.
///
/// Applies filename-level filters from the active filter set.
/// When `skip_invalid_file_check` is true, the `IsInvalidFile` filter is
/// skipped — used by diff scanning where files may not exist on disk.
fn is_file_filtered_out(
    filename: &str,
    ctx: &ScanFilterContext,
    skip_invalid_file_check: bool,
) -> bool {
    let filename_filters =
        get_filters_with_parameter(&ctx.active_filters, &[FilterParam::Filename]);

    // Exclude filters that also require Line/Secret/Context (those are applied later)
    let file_only_filters: Vec<FilterId> = filename_filters
        .into_iter()
        .filter(|f| {
            let vars = f.injectable_variables();
            !vars.contains(&FilterParam::Line)
                && !vars.contains(&FilterParam::Secret)
                && !vars.contains(&FilterParam::Context)
        })
        .collect();

    for filter in &file_only_filters {
        let excluded = match filter {
            FilterId::IsInvalidFile => {
                if skip_invalid_file_check {
                    false
                } else {
                    common::is_invalid_file(filename)
                }
            }
            FilterId::IsNonTextFile => heuristic::is_non_text_file(filename),
            FilterId::IsLockFile => heuristic::is_lock_file(filename),
            FilterId::IsSwaggerFile => heuristic::is_swagger_file(filename),
            FilterId::ShouldExcludeFile => {
                regex_filter::should_exclude_file(filename, &ctx.exclude_file_regexes)
            }
            _ => false,
        };
        if excluded {
            return true;
        }
    }

    // Check external file filters
    for ext_filter in &ctx.external_file_filters {
        if ext_filter(filename, "", "") {
            return true;
        }
    }

    false
}

/// Check if a line should be filtered out before plugin analysis.
fn is_line_filtered_out(
    filename: &str,
    line: &str,
    snippet: &CodeSnippet,
    ctx: &ScanFilterContext,
) -> bool {
    let line_filters = get_filters_with_parameter(&ctx.active_filters, &[FilterParam::Line]);

    for filter in &line_filters {
        let excluded = match filter {
            FilterId::ShouldExcludeLine => {
                regex_filter::should_exclude_line(line, &ctx.exclude_line_regexes)
            }
            FilterId::IsIndirectReference => heuristic::is_indirect_reference(line),
            FilterId::IsLineAllowlisted => {
                allowlist::is_line_allowlisted(filename, line, snippet.previous_line())
            }
            _ => false,
        };
        if excluded {
            return true;
        }
    }

    // Check external line filters
    for ext_filter in &ctx.external_line_filters {
        if ext_filter(filename, line, "") {
            return true;
        }
    }

    false
}

/// Check if a detected secret should be filtered out after plugin detection.
fn is_secret_filtered_out(
    filename: &str,
    secret: &str,
    line: &str,
    is_regex_based_plugin: bool,
    ctx: &ScanFilterContext,
) -> bool {
    let secret_filters = get_filters_with_parameter(&ctx.active_filters, &[FilterParam::Secret]);

    for filter in &secret_filters {
        let excluded = match filter {
            FilterId::IsSequentialString => heuristic::is_sequential_string(secret),
            FilterId::IsPotentialUuid => heuristic::is_potential_uuid(secret),
            FilterId::IsTemplatedSecret => heuristic::is_templated_secret(secret),
            FilterId::IsPrefixedWithDollarSign => heuristic::is_prefixed_with_dollar_sign(secret),
            FilterId::IsNotAlphanumericString => heuristic::is_not_alphanumeric_string(secret),
            FilterId::ShouldExcludeSecret => {
                regex_filter::should_exclude_secret(secret, &ctx.exclude_secret_regexes)
            }
            FilterId::WordlistShouldExcludeSecret => ctx
                .wordlist_filter
                .as_ref()
                .is_some_and(|wl| wl.should_exclude_secret(secret)),
            FilterId::IsLikelyIdString => {
                heuristic::is_likely_id_string(secret, line, is_regex_based_plugin)
            }
            _ => false,
        };
        if excluded {
            return true;
        }
    }

    // Check external secret filters
    for ext_filter in &ctx.external_secret_filters {
        if ext_filter(filename, line, secret) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Plugin helpers
// ---------------------------------------------------------------------------

/// Check if a plugin is regex-based by examining its analyze_string behavior.
///
/// We use a heuristic: plugins whose secret_type indicates they are keyword or
/// entropy-based are NOT regex-based for the `is_likely_id_string` filter.
/// In practice, the Python code checks `isinstance(plugin, RegexBasedDetector)`.
/// We approximate this: High entropy + Keyword plugins are NOT regex-based;
/// everything else IS.
fn is_regex_based(plugin: &dyn SecretDetector) -> bool {
    let st = plugin.secret_type();
    // High entropy plugins and keyword plugin are NOT regex-based for this purpose
    !st.contains("High Entropy") && st != "Secret Keyword"
}

// ---------------------------------------------------------------------------
// Public scan functions
// ---------------------------------------------------------------------------

/// Scan a file for secrets.
///
/// Full pipeline: read file, iterate lines, apply filename/line/secret filters,
/// run all active plugins on each line, and return detected secrets.
///
/// Matches Python's `scan_file()` from `detect_secrets/core/scan.py`.
pub fn scan_file(filename: &str) -> Vec<PotentialSecret> {
    let ctx = ScanFilterContext::from_settings();
    let plugins = settings::get_plugins();

    if plugins.is_empty() {
        return vec![];
    }

    // Apply filename-level filters
    if is_file_filtered_out(filename, &ctx, false) {
        return vec![];
    }

    // Read file
    let content = match fs::read_to_string(filename) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let lines: Vec<String> = content.lines().map(String::from).collect();

    process_line_based_plugins(filename, &lines, &plugins, &ctx)
}

/// Scan lines for secrets given filename context, plugins, and filter context.
///
/// This is the core line-by-line processing engine, matching Python's
/// `_process_line_based_plugins()`.
fn process_line_based_plugins(
    filename: &str,
    lines: &[String],
    plugins: &[Box<dyn SecretDetector + Send + Sync>],
    ctx: &ScanFilterContext,
) -> Vec<PotentialSecret> {
    let mut results = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let line_number = (i + 1) as u64; // 1-based

        // Build code snippet for context
        let snippet = get_code_snippet(lines, i, LINES_OF_CONTEXT);

        // Apply line-level filters
        if is_line_filtered_out(filename, line, &snippet, ctx) {
            continue;
        }

        // Run each plugin on this line
        for plugin in plugins {
            let secrets = plugin.analyze_line(filename, line, line_number);

            for secret in secrets {
                // Get the secret value for filter checking
                let secret_value = secret.secret_value.as_deref().unwrap_or("");

                // Apply secret-level filters
                if !secret_value.is_empty()
                    && is_secret_filtered_out(
                        filename,
                        secret_value,
                        line,
                        is_regex_based(plugin.as_ref()),
                        ctx,
                    )
                {
                    continue;
                }

                results.push(secret);
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Parallel file scanning
// ---------------------------------------------------------------------------

/// Thread-safe scanning context that captures settings once for sharing
/// across rayon worker threads via `Arc`.
///
/// This avoids repeated global mutex acquisition during parallel scanning
/// and eliminates serialization — plugins and filters are shared in-memory.
struct ParallelScanContext {
    plugins: Arc<Vec<Box<dyn SecretDetector + Send + Sync>>>,
    filter_ctx: Arc<ScanFilterContext>,
}

impl ParallelScanContext {
    /// Capture the current global settings into a shareable context.
    fn from_settings() -> Self {
        ParallelScanContext {
            plugins: Arc::new(settings::get_plugins()),
            filter_ctx: Arc::new(ScanFilterContext::from_settings()),
        }
    }

    /// Scan a single file using the captured context (no global lock needed).
    fn scan_file(&self, filename: &str) -> Vec<PotentialSecret> {
        if self.plugins.is_empty() {
            return vec![];
        }

        // Apply filename-level filters
        if is_file_filtered_out(filename, &self.filter_ctx, false) {
            return vec![];
        }

        // Read file
        let content = match fs::read_to_string(filename) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        let lines: Vec<String> = content.lines().map(String::from).collect();

        process_line_based_plugins(filename, &lines, &self.plugins, &self.filter_ctx)
    }
}

/// Scan multiple files in parallel using rayon.
///
/// Captures settings once into an `Arc<Settings>`-style context, then
/// distributes file scanning across a rayon thread pool. No GIL contention
/// occurs during the Rust-side scanning.
///
/// - `filenames` — list of file paths to scan.
/// - `num_threads` — thread pool size; `None` defaults to `num_cpus`.
///
/// Returns a map of `filename → Vec<PotentialSecret>`.
pub fn scan_files(
    filenames: &[String],
    num_threads: Option<usize>,
) -> HashMap<String, Vec<PotentialSecret>> {
    if filenames.is_empty() {
        return HashMap::new();
    }

    // Capture settings once — no more global lock during scanning
    let ctx = ParallelScanContext::from_settings();

    if ctx.plugins.is_empty() {
        return HashMap::new();
    }

    // Build a rayon thread pool with the requested thread count
    let pool = match num_threads {
        Some(n) if n > 0 => rayon::ThreadPoolBuilder::new().num_threads(n).build().ok(),
        _ => None,
    };

    let do_scan = || {
        filenames
            .par_iter()
            .filter_map(|filename| {
                let secrets = ctx.scan_file(filename);
                if secrets.is_empty() {
                    None
                } else {
                    Some((filename.clone(), secrets))
                }
            })
            .collect::<HashMap<String, Vec<PotentialSecret>>>()
    };

    match pool {
        Some(ref p) => p.install(do_scan),
        None => do_scan(),
    }
}

/// Scan a single line of text for secrets (ad-hoc scanning).
///
/// Useful for testing or scanning individual strings without a file context.
/// Disables the `is_invalid_file` filter since there's no file.
///
/// Matches Python's `scan_line()` from `detect_secrets/core/scan.py`.
pub fn scan_line(line: &str) -> Vec<PotentialSecret> {
    let ctx = ScanFilterContext::from_settings();
    let plugins = settings::get_plugins();

    if plugins.is_empty() {
        return vec![];
    }

    let filename = "adhoc-line-scan";
    let lines = vec![line.to_string()];
    let snippet = get_code_snippet(&lines, 0, 0);

    let mut results = Vec::new();

    for plugin in &plugins {
        let secrets = plugin.analyze_line(filename, line, 0);

        for secret in secrets {
            let secret_value = secret.secret_value.as_deref().unwrap_or("");

            if !secret_value.is_empty()
                && is_secret_filtered_out(
                    filename,
                    secret_value,
                    line,
                    is_regex_based(plugin.as_ref()),
                    &ctx,
                )
            {
                continue;
            }

            results.push(secret);
        }
    }

    let _ = snippet; // used for consistency with scan_file pattern

    results
}

// ---------------------------------------------------------------------------
// Diff scanning
// ---------------------------------------------------------------------------

/// A parsed file entry from a unified diff.
struct DiffFile {
    filename: String,
    lines: Vec<(u64, String)>, // (line_number, content)
}

/// Parse a unified diff string into file entries, extracting only added lines.
///
/// Matches Python's `_get_lines_from_diff()`.
fn parse_diff(diff: &str) -> Vec<DiffFile> {
    let mut files: Vec<DiffFile> = Vec::new();
    let mut current_file: Option<DiffFile> = None;
    let mut current_line_number: u64 = 0;

    for line in diff.lines() {
        // New file header: +++ b/path/to/file
        if let Some(path) = line.strip_prefix("+++ b/") {
            // Save previous file
            if let Some(f) = current_file.take() {
                if !f.lines.is_empty() {
                    files.push(f);
                }
            }
            current_file = Some(DiffFile {
                filename: path.to_string(),
                lines: Vec::new(),
            });
            continue;
        }

        // Also handle +++ /dev/null (deleted files) — skip
        if line.starts_with("+++ ") {
            if let Some(f) = current_file.take() {
                if !f.lines.is_empty() {
                    files.push(f);
                }
            }
            current_file = None;
            continue;
        }

        // Skip --- header lines
        if line.starts_with("--- ") {
            continue;
        }

        // Hunk header: @@ -old,count +new,count @@
        if line.starts_with("@@ ") {
            if let Some(new_start) = parse_hunk_header(line) {
                current_line_number = new_start;
            }
            continue;
        }

        if current_file.is_none() {
            continue;
        }

        let file = current_file.as_mut().unwrap();

        if let Some(added) = line.strip_prefix('+') {
            // Added line
            file.lines.push((current_line_number, added.to_string()));
            current_line_number += 1;
        } else if line.starts_with('-') {
            // Removed line — skip, don't increment line number
        } else {
            // Context line — increment line number
            current_line_number += 1;
        }
    }

    // Save last file
    if let Some(f) = current_file {
        if !f.lines.is_empty() {
            files.push(f);
        }
    }

    files
}

/// Parse the new file start line from a hunk header.
///
/// Example: `@@ -1,5 +3,7 @@` → returns `3`.
fn parse_hunk_header(line: &str) -> Option<u64> {
    // Find +N,M or +N in the hunk header
    let plus_idx = line.find('+')?;
    let rest = &line[plus_idx + 1..];
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end].parse().ok()
}

/// Scan a unified diff string for secrets in added lines.
///
/// Only processes lines that were added (not removed or context lines).
///
/// Matches Python's `scan_diff()` from `detect_secrets/core/scan.py`.
pub fn scan_diff(diff: &str) -> Vec<PotentialSecret> {
    let ctx = ScanFilterContext::from_settings();
    let plugins = settings::get_plugins();

    if plugins.is_empty() {
        return vec![];
    }

    let diff_files = parse_diff(diff);
    let mut results = Vec::new();

    for diff_file in &diff_files {
        // Apply filename-level filters (skip is_invalid_file for diffs —
        // files in a diff may not exist locally)
        if is_file_filtered_out(&diff_file.filename, &ctx, true) {
            continue;
        }

        // Build the full lines array for context
        // For diff scanning, we only have the added lines — use them as the context
        let all_lines: Vec<String> = diff_file.lines.iter().map(|(_, l)| l.clone()).collect();

        for (idx, (line_number, line)) in diff_file.lines.iter().enumerate() {
            let snippet = get_code_snippet(&all_lines, idx, LINES_OF_CONTEXT);

            // Apply line-level filters
            if is_line_filtered_out(&diff_file.filename, line, &snippet, &ctx) {
                continue;
            }

            // Run each plugin
            for plugin in &plugins {
                let secrets = plugin.analyze_line(&diff_file.filename, line, *line_number);

                for secret in secrets {
                    let secret_value = secret.secret_value.as_deref().unwrap_or("");

                    if !secret_value.is_empty()
                        && is_secret_filtered_out(
                            &diff_file.filename,
                            secret_value,
                            line,
                            is_regex_based(plugin.as_ref()),
                            &ctx,
                        )
                    {
                        continue;
                    }

                    results.push(secret);
                }
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/// Discover files to scan, with git-aware filtering.
///
/// - If `paths` is empty, defaults to `root` directory.
/// - If a path is a file, it's included directly (no git filtering).
/// - If a path is a directory, uses `git ls-files` for tracked files.
/// - If `should_scan_all_files` is true, includes all files (not just git-tracked).
///
/// Matches Python's `get_files_to_scan()` from `detect_secrets/core/scan.py`.
pub fn get_files_to_scan(paths: &[String], should_scan_all_files: bool, root: &str) -> Vec<String> {
    let effective_paths = if paths.is_empty() {
        vec![root.to_string()]
    } else {
        paths.to_vec()
    };

    let mut result: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for path_str in &effective_paths {
        let path = Path::new(path_str);

        if path.is_file() {
            // Direct file — always include (principle of least surprise)
            let canonical = normalize_path(path_str, root);
            if seen.insert(canonical.clone()) {
                result.push(canonical);
            }
        } else if path.is_dir() {
            let dir_files = if should_scan_all_files {
                get_all_files(path_str)
            } else {
                get_git_tracked_files(path_str).unwrap_or_else(|| get_all_files(path_str))
            };

            for file in dir_files {
                let canonical = normalize_path(&file, root);
                if seen.insert(canonical.clone()) {
                    result.push(canonical);
                }
            }
        }
    }

    result.sort();
    result
}

/// Get all files recursively in a directory.
fn get_all_files(dir: &str) -> Vec<String> {
    let mut files = Vec::new();
    collect_files_recursive(Path::new(dir), &mut files);
    files
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip hidden directories
            if let Some(name) = path.file_name() {
                if name.to_string_lossy().starts_with('.') {
                    continue;
                }
            }
            collect_files_recursive(&path, files);
        } else if path.is_file() {
            files.push(path.to_string_lossy().to_string());
        }
    }
}

/// Get git-tracked files in a directory using `git ls-files`.
fn get_git_tracked_files(dir: &str) -> Option<Vec<String>> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<String> = stdout
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let path = Path::new(dir).join(s);
            path.to_string_lossy().to_string()
        })
        .filter(|p| Path::new(p).is_file())
        .collect();

    Some(files)
}

/// Normalize a file path relative to root, producing a relative path.
fn normalize_path(path: &str, root: &str) -> String {
    let abs = if Path::new(path).is_absolute() {
        path.to_string()
    } else {
        Path::new(root).join(path).to_string_lossy().to_string()
    };

    // Try to make it relative to root
    if let Ok(stripped) = Path::new(&abs).strip_prefix(root) {
        let s = stripped.to_string_lossy().to_string();
        if s.is_empty() {
            path.to_string()
        } else {
            s
        }
    } else {
        abs
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // --- parse_hunk_header ---

    #[test]
    fn test_parse_hunk_header_basic() {
        assert_eq!(parse_hunk_header("@@ -1,5 +3,7 @@"), Some(3));
    }

    #[test]
    fn test_parse_hunk_header_single_line() {
        assert_eq!(parse_hunk_header("@@ -1 +1 @@"), Some(1));
    }

    #[test]
    fn test_parse_hunk_header_large() {
        assert_eq!(parse_hunk_header("@@ -10,20 +100,30 @@ fn foo"), Some(100));
    }

    // --- parse_diff ---

    #[test]
    fn test_parse_diff_basic() {
        let diff = "\
diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1,3 +1,4 @@
 line1
+password = 'hunter2'
 line2
 line3";

        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "test.py");
        assert_eq!(files[0].lines.len(), 1);
        assert_eq!(files[0].lines[0].0, 2); // line number 2
        assert_eq!(files[0].lines[0].1, "password = 'hunter2'");
    }

    #[test]
    fn test_parse_diff_multiple_files() {
        let diff = "\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,2 +1,3 @@
 foo
+secret_a = 'abc'
 bar
diff --git a/b.py b/b.py
--- /dev/null
+++ b/b.py
@@ -0,0 +1,2 @@
+secret_b = 'xyz'
+other = 1";

        let files = parse_diff(diff);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].filename, "a.py");
        assert_eq!(files[0].lines.len(), 1);
        assert_eq!(files[1].filename, "b.py");
        assert_eq!(files[1].lines.len(), 2);
    }

    #[test]
    fn test_parse_diff_deleted_file_skipped() {
        let diff = "\
diff --git a/deleted.py b/deleted.py
--- a/deleted.py
+++ /dev/null
@@ -1,2 +0,0 @@
-old_secret = 'foo'
-other = 1";

        let files = parse_diff(diff);
        assert!(files.is_empty());
    }

    #[test]
    fn test_parse_diff_only_additions() {
        let diff = "\
diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1,3 +1,3 @@
-old_line
+new_line
 unchanged
 more";

        let files = parse_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].lines.len(), 1);
        assert_eq!(files[0].lines[0].1, "new_line");
    }

    // --- get_code_snippet ---

    #[test]
    fn test_code_snippet_middle() {
        let lines: Vec<String> = (0..10).map(|i| format!("line{}", i)).collect();
        let snippet = get_code_snippet(&lines, 5, 2);
        assert_eq!(snippet._start_line, 3);
        assert_eq!(snippet.target_index, 2);
        assert_eq!(snippet.lines.len(), 5);
        assert_eq!(snippet.previous_line(), "line4");
    }

    #[test]
    fn test_code_snippet_start() {
        let lines: Vec<String> = (0..10).map(|i| format!("line{}", i)).collect();
        let snippet = get_code_snippet(&lines, 0, 2);
        assert_eq!(snippet._start_line, 0);
        assert_eq!(snippet.target_index, 0);
        assert_eq!(snippet.previous_line(), "");
    }

    #[test]
    fn test_code_snippet_end() {
        let lines: Vec<String> = (0..10).map(|i| format!("line{}", i)).collect();
        let snippet = get_code_snippet(&lines, 9, 2);
        assert_eq!(snippet._start_line, 7);
        assert_eq!(snippet.target_index, 2);
        assert_eq!(snippet.lines.len(), 3);
    }

    // --- is_regex_based ---

    #[test]
    fn test_is_regex_based_aws() {
        let plugin = crate::cloud_detectors::AWSKeyDetector::default();
        assert!(is_regex_based(&plugin));
    }

    #[test]
    fn test_is_regex_based_keyword_is_not() {
        let plugin = crate::keyword_detector::KeywordDetector::default();
        assert!(!is_regex_based(&plugin));
    }

    #[test]
    fn test_is_regex_based_high_entropy_is_not() {
        let plugin = crate::high_entropy_strings::Base64HighEntropyString::default();
        assert!(!is_regex_based(&plugin));
    }

    // --- scan_file integration ---

    #[test]
    fn test_scan_file_with_secrets() {
        let _serial = settings::serial_test();
        // Set up settings with a simple plugin
        let _guard = settings::default_settings();

        // Create temp file with a known secret pattern
        let dir = std::env::temp_dir();
        let path = dir.join("test_scan_secrets.py");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "# config file").unwrap();
            writeln!(f, "aws_key = 'AKIAIOSFODNN7EXAMPLE'").unwrap();
            writeln!(f, "normal = 'hello world'").unwrap();
        }

        let secrets = scan_file(path.to_str().unwrap());

        // Should find at least the AWS key
        assert!(
            !secrets.is_empty(),
            "Should detect at least one secret in test file"
        );

        let has_aws = secrets.iter().any(|s| s.secret_type == "AWS Access Key");
        assert!(has_aws, "Should detect AWS Access Key");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_scan_file_nonexistent() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();
        let secrets = scan_file("/nonexistent/file.txt");
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_scan_file_non_text() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();
        let secrets = scan_file("test.png");
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_scan_file_allowlisted() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let dir = std::env::temp_dir();
        let path = dir.join("test_scan_allowlisted.py");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(
                f,
                "aws_key = 'AKIAIOSFODNN7EXAMPLE'  # pragma: allowlist secret"
            )
            .unwrap();
        }

        let secrets = scan_file(path.to_str().unwrap());

        // All secrets on allowlisted line should be filtered out
        assert!(secrets.is_empty(), "Allowlisted secrets should be filtered");

        std::fs::remove_file(path).ok();
    }

    // --- scan_line ---

    #[test]
    fn test_scan_line_with_secret() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();
        let secrets = scan_line("AKIAIOSFODNN7EXAMPLE");

        let has_aws = secrets.iter().any(|s| s.secret_type == "AWS Access Key");
        assert!(has_aws, "Should detect AWS Access Key in line");
    }

    #[test]
    fn test_scan_line_no_secret() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();
        let secrets = scan_line("hello world");
        // No secrets should be detected in plain text
        // (some heuristic plugins might match, but regular text shouldn't)
        let has_high_value = secrets
            .iter()
            .any(|s| s.secret_type == "AWS Access Key" || s.secret_type == "Private Key");
        assert!(!has_high_value);
    }

    // --- scan_diff ---

    #[test]
    fn test_scan_diff_detects_added_secrets() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let diff = "\
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,2 +1,3 @@
 import os
+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
 print('done')";

        let secrets = scan_diff(diff);
        let has_aws = secrets.iter().any(|s| s.secret_type == "AWS Access Key");
        assert!(has_aws, "Should detect AWS key in diff additions");
    }

    #[test]
    fn test_scan_diff_ignores_removed_lines() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let diff = "\
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,3 +1,2 @@
 import os
-AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
 print('done')";

        let secrets = scan_diff(diff);
        let has_aws = secrets.iter().any(|s| s.secret_type == "AWS Access Key");
        assert!(!has_aws, "Should NOT detect secrets in removed lines");
    }

    #[test]
    fn test_scan_diff_empty() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();
        let secrets = scan_diff("");
        assert!(secrets.is_empty());
    }

    // --- normalize_path ---

    #[test]
    fn test_normalize_path_relative() {
        let result = normalize_path("src/main.rs", "/project");
        assert_eq!(result, "src/main.rs");
    }

    #[test]
    fn test_normalize_path_absolute_under_root() {
        let result = normalize_path("/project/src/main.rs", "/project");
        assert_eq!(result, "src/main.rs");
    }

    #[test]
    fn test_normalize_path_absolute_outside_root() {
        let result = normalize_path("/other/file.rs", "/project");
        assert_eq!(result, "/other/file.rs");
    }

    // --- get_files_to_scan ---

    #[test]
    fn test_get_files_to_scan_single_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_get_files.txt");
        std::fs::File::create(&path).unwrap();

        let files = get_files_to_scan(
            &[path.to_string_lossy().to_string()],
            false,
            dir.to_str().unwrap(),
        );
        assert_eq!(files.len(), 1);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_get_files_to_scan_nonexistent_path() {
        let files = get_files_to_scan(&["/nonexistent/path".to_string()], false, "/tmp");
        assert!(files.is_empty());
    }

    // --- scan_files (parallel) ---

    #[test]
    fn test_scan_files_empty_list() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();
        let results = scan_files(&[], None);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_files_single_file() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let dir = std::env::temp_dir();
        let path = dir.join("test_par_single.py");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "aws_key = 'AKIAIOSFODNN7EXAMPLE'").unwrap();
        }

        let filenames = vec![path.to_string_lossy().to_string()];
        let results = scan_files(&filenames, Some(1));

        assert_eq!(results.len(), 1);
        let secrets = results.values().next().unwrap();
        let has_aws = secrets.iter().any(|s| s.secret_type == "AWS Access Key");
        assert!(has_aws, "Should detect AWS key in parallel scan");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_scan_files_multiple_files_parallel() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let dir = std::env::temp_dir();
        let paths: Vec<std::path::PathBuf> = (0..5)
            .map(|i| {
                let path = dir.join(format!("test_par_multi_{}.py", i));
                let mut f = std::fs::File::create(&path).unwrap();
                writeln!(f, "password_{} = 'AKIAIOSFODNN7EXAMPL{}'", i, i).unwrap();
                path
            })
            .collect();

        let filenames: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        let results = scan_files(&filenames, Some(4));

        // All files should produce results
        assert!(
            !results.is_empty(),
            "Parallel scan should detect secrets in multiple files"
        );

        // Clean up
        for path in &paths {
            std::fs::remove_file(path).ok();
        }
    }

    #[test]
    fn test_scan_files_parallel_matches_sequential() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let dir = std::env::temp_dir();
        let paths: Vec<std::path::PathBuf> = (0..3)
            .map(|i| {
                let path = dir.join(format!("test_par_vs_seq_{}.py", i));
                let mut f = std::fs::File::create(&path).unwrap();
                writeln!(f, "aws_key_{} = 'AKIAIOSFODNN7EXAMPL{}'", i, i).unwrap();
                writeln!(f, "normal = 'hello'").unwrap();
                path
            })
            .collect();

        let filenames: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        // Sequential: scan each file individually
        let mut sequential_results: HashMap<String, Vec<PotentialSecret>> = HashMap::new();
        for filename in &filenames {
            let secrets = scan_file(filename);
            if !secrets.is_empty() {
                sequential_results.insert(filename.clone(), secrets);
            }
        }

        // Parallel: scan all files at once
        let parallel_results = scan_files(&filenames, Some(2));

        // Same files should be detected
        assert_eq!(
            sequential_results.len(),
            parallel_results.len(),
            "Parallel and sequential should find secrets in same number of files"
        );

        // Same secrets should be detected per file
        for (filename, seq_secrets) in &sequential_results {
            let par_secrets = parallel_results
                .get(filename)
                .expect("Parallel results should contain same files as sequential");

            // Compare by secret identity (type + hash)
            let seq_set: HashSet<(&str, &str)> = seq_secrets
                .iter()
                .map(|s| (s.secret_type.as_str(), s.secret_hash.as_str()))
                .collect();
            let par_set: HashSet<(&str, &str)> = par_secrets
                .iter()
                .map(|s| (s.secret_type.as_str(), s.secret_hash.as_str()))
                .collect();

            assert_eq!(
                seq_set, par_set,
                "Parallel and sequential should detect same secrets in {}",
                filename
            );
        }

        // Clean up
        for path in &paths {
            std::fs::remove_file(path).ok();
        }
    }

    #[test]
    fn test_scan_files_with_custom_thread_count() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let dir = std::env::temp_dir();
        let path = dir.join("test_par_threads.py");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "aws_key = 'AKIAIOSFODNN7EXAMPLE'").unwrap();
        }

        let filenames = vec![path.to_string_lossy().to_string()];

        // Test with explicit thread count
        let results_1 = scan_files(&filenames, Some(1));
        let results_2 = scan_files(&filenames, Some(2));
        let results_default = scan_files(&filenames, None);

        // All should produce the same result
        assert_eq!(results_1.len(), results_2.len());
        assert_eq!(results_1.len(), results_default.len());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_scan_files_nonexistent_files() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let filenames = vec![
            "/nonexistent/file1.py".to_string(),
            "/nonexistent/file2.py".to_string(),
        ];

        let results = scan_files(&filenames, Some(2));
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_files_mixed_valid_and_invalid() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();

        let dir = std::env::temp_dir();
        let valid_path = dir.join("test_par_mixed_valid.py");
        {
            let mut f = std::fs::File::create(&valid_path).unwrap();
            writeln!(f, "aws_key = 'AKIAIOSFODNN7EXAMPLE'").unwrap();
        }

        let filenames = vec![
            valid_path.to_string_lossy().to_string(),
            "/nonexistent/file.py".to_string(),
        ];

        let results = scan_files(&filenames, Some(2));

        // Only the valid file should produce results
        assert_eq!(results.len(), 1);
        assert!(results.contains_key(valid_path.to_str().unwrap()));

        std::fs::remove_file(valid_path).ok();
    }

    // --- External filter registry ---

    #[test]
    fn test_register_external_filter() {
        clear_external_filters();

        let filter = ExternalFilter {
            path: "custom.filter.test".to_string(),
            filter_fn: Arc::new(|_filename, _line, _secret| false),
            phase: FilterPhase::Secret,
        };

        register_external_filter(filter);
        // Just verify no panic
        clear_external_filters();
    }

    #[test]
    fn test_external_secret_filter_excludes() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();
        clear_external_filters();

        // Create temp file with a known secret pattern
        let dir = std::env::temp_dir();
        let path = dir.join("test_ext_filter_exclude.py");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "aws_key = 'AKIAIOSFODNN7EXAMPLE'").unwrap();
        }

        // Register a filter that excludes all secrets
        register_external_filter(ExternalFilter {
            path: "test.exclude_all".to_string(),
            filter_fn: Arc::new(|_filename, _line, _secret| true),
            phase: FilterPhase::Secret,
        });

        let secrets = scan_file(path.to_str().unwrap());
        assert!(
            secrets.is_empty(),
            "External secret filter should exclude all secrets"
        );

        clear_external_filters();
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_external_file_filter_excludes() {
        let _serial = settings::serial_test();
        let _guard = settings::default_settings();
        clear_external_filters();

        let dir = std::env::temp_dir();
        let path = dir.join("test_ext_file_filter.py");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "aws_key = 'AKIAIOSFODNN7EXAMPLE'").unwrap();
        }

        // Register a filter that excludes all files
        register_external_filter(ExternalFilter {
            path: "test.exclude_all_files".to_string(),
            filter_fn: Arc::new(|_filename, _line, _secret| true),
            phase: FilterPhase::File,
        });

        let secrets = scan_file(path.to_str().unwrap());
        assert!(
            secrets.is_empty(),
            "External file filter should exclude all files"
        );

        clear_external_filters();
        std::fs::remove_file(path).ok();
    }
}
