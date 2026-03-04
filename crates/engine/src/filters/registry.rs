//! Filter registry and dependency injection system.
//!
//! Ported from detect_secrets/util/inject.py and detect_secrets/core/scan.py
//!
//! In Python, filters declare their accepted parameters via function signatures
//! and are invoked with dependency injection. In Rust, we model this with an
//! explicit parameter set per filter and a registry that can be queried.

use std::collections::HashSet;

/// Parameters that can be injected into filter functions.
///
/// Matches the parameter names used by Python's filter dependency injection:
/// `filename`, `line`, `secret`, `context`, `plugin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterParam {
    /// The filename being scanned.
    Filename,
    /// The current line of text.
    Line,
    /// The secret value that was detected.
    Secret,
    /// Code snippet context around the line.
    Context,
    /// The plugin that detected the secret.
    Plugin,
}

/// Identifies a built-in filter function.
///
/// Each variant corresponds to one filter function in the codebase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterId {
    // --- common ---
    IsInvalidFile,

    // --- heuristic ---
    IsNonTextFile,
    IsSequentialString,
    IsPotentialUuid,
    IsLikelyIdString,
    IsTemplatedSecret,
    IsPrefixedWithDollarSign,
    IsIndirectReference,
    IsLockFile,
    IsNotAlphanumericString,
    IsSwaggerFile,

    // --- allowlist ---
    IsLineAllowlisted,

    // --- regex ---
    ShouldExcludeLine,
    ShouldExcludeFile,
    ShouldExcludeSecret,

    // --- wordlist ---
    WordlistShouldExcludeSecret,
}

impl FilterId {
    /// Returns the Python-style dotted path for this filter.
    ///
    /// These paths match the baseline `filters_used[].path` format.
    pub fn path(&self) -> &'static str {
        match self {
            FilterId::IsInvalidFile => "detect_secrets.filters.common.is_invalid_file",
            FilterId::IsNonTextFile => "detect_secrets.filters.heuristic.is_non_text_file",
            FilterId::IsSequentialString => "detect_secrets.filters.heuristic.is_sequential_string",
            FilterId::IsPotentialUuid => "detect_secrets.filters.heuristic.is_potential_uuid",
            FilterId::IsLikelyIdString => "detect_secrets.filters.heuristic.is_likely_id_string",
            FilterId::IsTemplatedSecret => "detect_secrets.filters.heuristic.is_templated_secret",
            FilterId::IsPrefixedWithDollarSign => {
                "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign"
            }
            FilterId::IsIndirectReference => {
                "detect_secrets.filters.heuristic.is_indirect_reference"
            }
            FilterId::IsLockFile => "detect_secrets.filters.heuristic.is_lock_file",
            FilterId::IsNotAlphanumericString => {
                "detect_secrets.filters.heuristic.is_not_alphanumeric_string"
            }
            FilterId::IsSwaggerFile => "detect_secrets.filters.heuristic.is_swagger_file",
            FilterId::IsLineAllowlisted => "detect_secrets.filters.allowlist.is_line_allowlisted",
            FilterId::ShouldExcludeLine => "detect_secrets.filters.regex.should_exclude_line",
            FilterId::ShouldExcludeFile => "detect_secrets.filters.regex.should_exclude_file",
            FilterId::ShouldExcludeSecret => "detect_secrets.filters.regex.should_exclude_secret",
            FilterId::WordlistShouldExcludeSecret => {
                "detect_secrets.filters.wordlist.should_exclude_secret"
            }
        }
    }

    /// Returns the set of parameters this filter accepts.
    ///
    /// This is the Rust equivalent of Python's `get_injectable_variables()`.
    pub fn injectable_variables(&self) -> HashSet<FilterParam> {
        match self {
            // File-level filters: accept `filename`
            FilterId::IsInvalidFile => [FilterParam::Filename].into(),
            FilterId::IsNonTextFile => [FilterParam::Filename].into(),
            FilterId::IsLockFile => [FilterParam::Filename].into(),
            FilterId::IsSwaggerFile => [FilterParam::Filename].into(),
            FilterId::ShouldExcludeFile => [FilterParam::Filename].into(),

            // Line-level filters: accept `line` (+ optionally `filename`, `context`)
            FilterId::ShouldExcludeLine => [FilterParam::Line].into(),
            FilterId::IsIndirectReference => [FilterParam::Line].into(),
            FilterId::IsLineAllowlisted => [
                FilterParam::Filename,
                FilterParam::Line,
                FilterParam::Context,
            ]
            .into(),

            // Secret-level filters: accept `secret` (+ optionally others)
            FilterId::IsSequentialString => [FilterParam::Secret].into(),
            FilterId::IsPotentialUuid => [FilterParam::Secret].into(),
            FilterId::IsTemplatedSecret => [FilterParam::Secret].into(),
            FilterId::IsPrefixedWithDollarSign => [FilterParam::Secret].into(),
            FilterId::IsNotAlphanumericString => [FilterParam::Secret].into(),
            FilterId::ShouldExcludeSecret => [FilterParam::Secret].into(),
            FilterId::WordlistShouldExcludeSecret => [FilterParam::Secret].into(),

            // Context-level filters: accept `secret` + more (plugin, line, context)
            FilterId::IsLikelyIdString => {
                [FilterParam::Secret, FilterParam::Line, FilterParam::Plugin].into()
            }
        }
    }

    /// Look up a filter by its Python-style dotted path.
    pub fn from_path(path: &str) -> Option<FilterId> {
        ALL_FILTERS.iter().find(|f| f.path() == path).copied()
    }
}

/// All registered built-in filter IDs.
pub const ALL_FILTERS: &[FilterId] = &[
    FilterId::IsInvalidFile,
    FilterId::IsNonTextFile,
    FilterId::IsSequentialString,
    FilterId::IsPotentialUuid,
    FilterId::IsLikelyIdString,
    FilterId::IsTemplatedSecret,
    FilterId::IsPrefixedWithDollarSign,
    FilterId::IsIndirectReference,
    FilterId::IsLockFile,
    FilterId::IsNotAlphanumericString,
    FilterId::IsSwaggerFile,
    FilterId::IsLineAllowlisted,
    FilterId::ShouldExcludeLine,
    FilterId::ShouldExcludeFile,
    FilterId::ShouldExcludeSecret,
    FilterId::WordlistShouldExcludeSecret,
];

/// Returns the subset of `active_filters` whose injectable variables
/// are a superset of `required_params`.
///
/// Matches Python's `get_filters_with_parameter(*parameters)`.
///
/// # Example
///
/// ```
/// use engine::filters::registry::{FilterId, FilterParam, get_filters_with_parameter};
///
/// let active = vec![
///     FilterId::IsSequentialString,
///     FilterId::IsLikelyIdString,
///     FilterId::ShouldExcludeLine,
/// ];
///
/// // Only filters that accept at least `Secret`
/// let result = get_filters_with_parameter(&active, &[FilterParam::Secret]);
/// assert!(result.contains(&FilterId::IsSequentialString));
/// assert!(result.contains(&FilterId::IsLikelyIdString));
/// assert!(!result.contains(&FilterId::ShouldExcludeLine));
/// ```
pub fn get_filters_with_parameter(
    active_filters: &[FilterId],
    required_params: &[FilterParam],
) -> Vec<FilterId> {
    let minimum: HashSet<FilterParam> = required_params.iter().copied().collect();

    active_filters
        .iter()
        .filter(|filter| minimum.is_subset(&filter.injectable_variables()))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_filters_have_unique_paths() {
        let mut paths: HashSet<&str> = HashSet::new();
        for filter in ALL_FILTERS {
            assert!(
                paths.insert(filter.path()),
                "Duplicate path: {}",
                filter.path()
            );
        }
    }

    #[test]
    fn test_from_path_known() {
        assert_eq!(
            FilterId::from_path("detect_secrets.filters.heuristic.is_sequential_string"),
            Some(FilterId::IsSequentialString)
        );
        assert_eq!(
            FilterId::from_path("detect_secrets.filters.regex.should_exclude_file"),
            Some(FilterId::ShouldExcludeFile)
        );
    }

    #[test]
    fn test_from_path_unknown() {
        assert_eq!(FilterId::from_path("nonexistent.filter"), None);
    }

    #[test]
    fn test_get_filters_with_secret_param() {
        let active = vec![
            FilterId::IsSequentialString,
            FilterId::IsLikelyIdString,
            FilterId::ShouldExcludeLine,
            FilterId::IsInvalidFile,
        ];

        let result = get_filters_with_parameter(&active, &[FilterParam::Secret]);
        assert!(result.contains(&FilterId::IsSequentialString));
        assert!(result.contains(&FilterId::IsLikelyIdString));
        assert!(!result.contains(&FilterId::ShouldExcludeLine));
        assert!(!result.contains(&FilterId::IsInvalidFile));
    }

    #[test]
    fn test_get_filters_with_filename_param() {
        let active = vec![
            FilterId::IsInvalidFile,
            FilterId::IsNonTextFile,
            FilterId::IsSequentialString,
            FilterId::IsLineAllowlisted,
        ];

        let result = get_filters_with_parameter(&active, &[FilterParam::Filename]);
        assert!(result.contains(&FilterId::IsInvalidFile));
        assert!(result.contains(&FilterId::IsNonTextFile));
        assert!(result.contains(&FilterId::IsLineAllowlisted));
        assert!(!result.contains(&FilterId::IsSequentialString));
    }

    #[test]
    fn test_get_filters_with_line_param() {
        let active = vec![
            FilterId::ShouldExcludeLine,
            FilterId::IsIndirectReference,
            FilterId::IsLineAllowlisted,
            FilterId::IsSequentialString,
        ];

        let result = get_filters_with_parameter(&active, &[FilterParam::Line]);
        assert!(result.contains(&FilterId::ShouldExcludeLine));
        assert!(result.contains(&FilterId::IsIndirectReference));
        assert!(result.contains(&FilterId::IsLineAllowlisted));
        assert!(!result.contains(&FilterId::IsSequentialString));
    }

    #[test]
    fn test_get_filters_with_multiple_params() {
        let active = vec![
            FilterId::IsLikelyIdString,
            FilterId::IsSequentialString,
            FilterId::ShouldExcludeLine,
        ];

        // Require both Secret and Line — only IsLikelyIdString has both
        let result = get_filters_with_parameter(&active, &[FilterParam::Secret, FilterParam::Line]);
        assert!(result.contains(&FilterId::IsLikelyIdString));
        assert!(!result.contains(&FilterId::IsSequentialString));
        assert!(!result.contains(&FilterId::ShouldExcludeLine));
    }

    #[test]
    fn test_get_filters_empty_active() {
        let result = get_filters_with_parameter(&[], &[FilterParam::Secret]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_filters_empty_params() {
        let active = vec![
            FilterId::IsSequentialString,
            FilterId::IsInvalidFile,
            FilterId::ShouldExcludeLine,
        ];

        // Empty required params → all filters match (empty set is subset of everything)
        let result = get_filters_with_parameter(&active, &[]);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_injectable_variables_file_filters() {
        let vars = FilterId::IsInvalidFile.injectable_variables();
        assert!(vars.contains(&FilterParam::Filename));
        assert!(!vars.contains(&FilterParam::Secret));
    }

    #[test]
    fn test_injectable_variables_secret_filters() {
        let vars = FilterId::IsSequentialString.injectable_variables();
        assert!(vars.contains(&FilterParam::Secret));
        assert!(!vars.contains(&FilterParam::Filename));
    }

    #[test]
    fn test_injectable_variables_context_filter() {
        let vars = FilterId::IsLineAllowlisted.injectable_variables();
        assert!(vars.contains(&FilterParam::Filename));
        assert!(vars.contains(&FilterParam::Line));
        assert!(vars.contains(&FilterParam::Context));
    }

    #[test]
    fn test_injectable_variables_likely_id_has_plugin() {
        let vars = FilterId::IsLikelyIdString.injectable_variables();
        assert!(vars.contains(&FilterParam::Secret));
        assert!(vars.contains(&FilterParam::Line));
        assert!(vars.contains(&FilterParam::Plugin));
    }
}
