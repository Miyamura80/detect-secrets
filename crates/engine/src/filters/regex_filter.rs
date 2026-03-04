//! Regex-based exclusion filters.
//!
//! Ported from detect_secrets/filters/regex.py
//!
//! Provides three filter functions that check whether a line, filename,
//! or secret value matches any of a set of user-provided regex patterns.
//! If a match is found, the item should be excluded (filtered out).

use regex::Regex;

/// Check if a line matches any of the exclusion regex patterns.
///
/// Matches Python's `should_exclude_line()`.
/// Returns `true` if the line should be excluded (matches a pattern).
pub fn should_exclude_line(line: &str, regexes: &[Regex]) -> bool {
    for regex in regexes {
        if regex.is_match(line) {
            return true;
        }
    }
    false
}

/// Check if a filename matches any of the exclusion regex patterns.
///
/// Matches Python's `should_exclude_file()`.
/// Returns `true` if the file should be excluded (matches a pattern).
pub fn should_exclude_file(filename: &str, regexes: &[Regex]) -> bool {
    for regex in regexes {
        if regex.is_match(filename) {
            return true;
        }
    }
    false
}

/// Check if a secret value matches any of the exclusion regex patterns.
///
/// Matches Python's `should_exclude_secret()`.
/// Returns `true` if the secret should be excluded (matches a pattern).
pub fn should_exclude_secret(secret: &str, regexes: &[Regex]) -> bool {
    for regex in regexes {
        if regex.is_match(secret) {
            return true;
        }
    }
    false
}

/// Compile a list of regex pattern strings into compiled `Regex` objects.
///
/// Returns `Err` if any pattern is invalid.
pub fn compile_regexes(patterns: &[String]) -> Result<Vec<Regex>, regex::Error> {
    patterns.iter().map(|p| Regex::new(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regexes(patterns: &[&str]) -> Vec<Regex> {
        patterns.iter().map(|p| Regex::new(p).unwrap()).collect()
    }

    // --- should_exclude_line ---

    #[test]
    fn test_exclude_line_match() {
        let regexes = make_regexes(&[r"TODO", r"FIXME"]);
        assert!(should_exclude_line("// TODO: fix this later", &regexes));
    }

    #[test]
    fn test_exclude_line_no_match() {
        let regexes = make_regexes(&[r"TODO", r"FIXME"]);
        assert!(!should_exclude_line("password = 'hunter2'", &regexes));
    }

    #[test]
    fn test_exclude_line_regex_pattern() {
        let regexes = make_regexes(&[r"^test.*data$"]);
        assert!(should_exclude_line("test_secret_data", &regexes));
        assert!(!should_exclude_line("production_data_test", &regexes));
    }

    #[test]
    fn test_exclude_line_empty_regexes() {
        let regexes: Vec<Regex> = vec![];
        assert!(!should_exclude_line("anything", &regexes));
    }

    #[test]
    fn test_exclude_line_multiple_patterns() {
        let regexes = make_regexes(&[r"^#", r"^//"]);
        assert!(should_exclude_line("# comment line", &regexes));
        assert!(should_exclude_line("// another comment", &regexes));
        assert!(!should_exclude_line("password = secret", &regexes));
    }

    // --- should_exclude_file ---

    #[test]
    fn test_exclude_file_match() {
        let regexes = make_regexes(&[r"test.*"]);
        assert!(should_exclude_file("test_config.py", &regexes));
    }

    #[test]
    fn test_exclude_file_no_match() {
        let regexes = make_regexes(&[r"test.*"]);
        assert!(!should_exclude_file("production.py", &regexes));
    }

    #[test]
    fn test_exclude_file_path_pattern() {
        let regexes = make_regexes(&[r"\.env$", r"fixtures/"]);
        assert!(should_exclude_file("config/.env", &regexes));
        assert!(should_exclude_file("tests/fixtures/data.json", &regexes));
        assert!(!should_exclude_file("main.py", &regexes));
    }

    #[test]
    fn test_exclude_file_empty_regexes() {
        let regexes: Vec<Regex> = vec![];
        assert!(!should_exclude_file("anything.py", &regexes));
    }

    // --- should_exclude_secret ---

    #[test]
    fn test_exclude_secret_match() {
        let regexes = make_regexes(&[r"^EXAMPLE"]);
        assert!(should_exclude_secret("EXAMPLE_KEY_12345", &regexes));
    }

    #[test]
    fn test_exclude_secret_no_match() {
        let regexes = make_regexes(&[r"^EXAMPLE"]);
        assert!(!should_exclude_secret("AKIAIOSFODNN7REAL", &regexes));
    }

    #[test]
    fn test_exclude_secret_multiple() {
        let regexes = make_regexes(&[r"^test", r"^fake", r"^dummy"]);
        assert!(should_exclude_secret("test_key_123", &regexes));
        assert!(should_exclude_secret("fake_secret", &regexes));
        assert!(should_exclude_secret("dummy_password", &regexes));
        assert!(!should_exclude_secret("real_secret_abc", &regexes));
    }

    #[test]
    fn test_exclude_secret_empty_regexes() {
        let regexes: Vec<Regex> = vec![];
        assert!(!should_exclude_secret("anything", &regexes));
    }

    // --- compile_regexes ---

    #[test]
    fn test_compile_regexes_valid() {
        let patterns = vec!["^test".to_string(), r"\d+".to_string()];
        let result = compile_regexes(&patterns);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_compile_regexes_invalid() {
        let patterns = vec!["[invalid".to_string()];
        let result = compile_regexes(&patterns);
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_regexes_empty() {
        let patterns: Vec<String> = vec![];
        let result = compile_regexes(&patterns);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
