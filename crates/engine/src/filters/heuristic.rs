//! Heuristic-based filters for reducing false positives.
//!
//! Ported from detect_secrets/filters/heuristic.py

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

/// Check if a secret looks like a sequential alphabet/digit pattern (likely false positive).
///
/// Matches Python's `is_sequential_string()`.
pub fn is_sequential_string(secret: &str) -> bool {
    // Build the same sequences as Python
    let uppercase_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let digits = "0123456789";
    let hex_upper = "0123456789ABCDEF";

    let sequences: Vec<String> = vec![
        // Base64 letters first
        format!("{}{}{}+/", uppercase_letters, uppercase_letters, digits),
        // Base64 numbers first
        format!("{}{}{}+/", digits, uppercase_letters, uppercase_letters),
        // Alphanumeric sequences (repeated twice)
        format!(
            "{}{}{}{}",
            digits, uppercase_letters, digits, uppercase_letters
        ),
        // Capturing any number sequences
        format!("{}{}", digits, digits),
        // Hex digits (upper, repeated twice)
        format!("{}{}", hex_upper, hex_upper),
        // Assignment operators
        format!("{}=/", uppercase_letters),
    ];

    let uppercased = secret.to_uppercase();
    for seq in &sequences {
        if seq.contains(&uppercased) {
            return true;
        }
    }
    false
}

static UUID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}").unwrap()
});

/// Check if a secret matches UUID format (likely false positive).
///
/// Matches Python's `is_potential_uuid()`.
pub fn is_potential_uuid(secret: &str) -> bool {
    UUID_REGEX.is_match(secret)
}

static ID_DETECTOR_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(^(id|myid|userid)|_id)s?[^a-z0-9]").unwrap());

/// Check if a secret is preceded by variable/parameter name patterns indicating it's an ID.
///
/// Matches Python's `is_likely_id_string()`.
/// `is_regex_based_plugin` should be true if the plugin is a RegexBasedDetector.
pub fn is_likely_id_string(secret: &str, line: &str, is_regex_based_plugin: bool) -> bool {
    if is_regex_based_plugin {
        return false;
    }
    if let Some(index) = line.find(secret) {
        let prefix = &line[..index];
        ID_DETECTOR_REGEX.is_match(prefix)
    } else {
        false
    }
}

/// Set of file extensions considered non-text (binary, archives, images, etc.).
///
/// Matches Python's `IGNORED_FILE_EXTENSIONS`.
static IGNORED_FILE_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        ".7z", ".bin", ".bmp", ".bz2", ".class", ".css", ".dmg", ".doc", ".eot", ".exe", ".gif",
        ".gz", ".ico", ".iml", ".ipr", ".iws", ".jar", ".jpg", ".jpeg", ".lock", ".map", ".mo",
        ".pdf", ".png", ".prefs", ".psd", ".rar", ".realm", ".s7z", ".sum", ".svg", ".tar", ".tif",
        ".tiff", ".ttf", ".webp", ".woff", ".xls", ".xlsx", ".zip",
    ]
    .into_iter()
    .collect()
});

/// Check if file has a binary/non-text extension.
///
/// Matches Python's `is_non_text_file()`.
pub fn is_non_text_file(filename: &str) -> bool {
    let path = Path::new(filename);
    if let Some(ext) = path.extension() {
        let dot_ext = format!(".{}", ext.to_string_lossy());
        IGNORED_FILE_EXTENSIONS.contains(dot_ext.as_str())
    } else {
        false
    }
}

/// Check if a secret looks like a template placeholder: {secret}, <secret>, or ${secret}.
///
/// Matches Python's `is_templated_secret()`.
pub fn is_templated_secret(secret: &str) -> bool {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 1 {
        // Any single-char (or empty) secret is highly likely a false positive
        return true;
    }
    let first = chars[0];
    let last = chars[chars.len() - 1];
    if first == '{' && last == '}' {
        return true;
    }
    if first == '<' && last == '>' {
        return true;
    }
    if first == '$' && chars.len() > 2 && chars[1] == '{' && last == '}' {
        return true;
    }
    false
}

/// Check if a secret starts with `$` (variable reference).
///
/// Matches Python's `is_prefixed_with_dollar_sign()`.
pub fn is_prefixed_with_dollar_sign(secret: &str) -> bool {
    !secret.is_empty() && secret.starts_with('$')
}

static INDIRECT_REFERENCE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([^\x0B=!:]*)\s*(:=?|[!=]{1,3})\s*([\w.\-]+[\[\(][^\x0B]*[\]\)])").unwrap()
});

/// Check if a line contains an indirect secret reference (function call, dict access).
///
/// Matches Python's `is_indirect_reference()`.
pub fn is_indirect_reference(line: &str) -> bool {
    // Constrain line length to avoid catastrophic backtracking
    if line.len() > 1000 {
        return false;
    }
    INDIRECT_REFERENCE_REGEX.is_match(line)
}

/// Set of lock file basenames.
static LOCK_FILES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "Brewfile.lock.json",
        "Cartfile.resolved",
        "composer.lock",
        "Gemfile.lock",
        "Package.resolved",
        "package-lock.json",
        "Podfile.lock",
        "yarn.lock",
        "Pipfile.lock",
        "poetry.lock",
        "Cargo.lock",
        "packages.lock.json",
    ]
    .into_iter()
    .collect()
});

/// Check if a file is a package lock file.
///
/// Matches Python's `is_lock_file()`.
pub fn is_lock_file(filename: &str) -> bool {
    let path = Path::new(filename);
    if let Some(name) = path.file_name() {
        LOCK_FILES.contains(name.to_string_lossy().as_ref())
    } else {
        false
    }
}

/// Check if a secret contains no ASCII letters (symbols only, like `*****`).
///
/// Matches Python's `is_not_alphanumeric_string()`.
pub fn is_not_alphanumeric_string(secret: &str) -> bool {
    !secret.chars().any(|c| c.is_ascii_alphabetic())
}

static SWAGGER_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r".*swagger.*").unwrap());

/// Check if a file is a Swagger/OpenAPI documentation file.
///
/// Matches Python's `is_swagger_file()`.
pub fn is_swagger_file(filename: &str) -> bool {
    SWAGGER_REGEX.is_match(filename)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_sequential_string ---

    #[test]
    fn test_sequential_base64_letters() {
        assert!(is_sequential_string("ABCDEFGH"));
    }

    #[test]
    fn test_sequential_digits() {
        assert!(is_sequential_string("0123456789"));
    }

    #[test]
    fn test_sequential_hex() {
        assert!(is_sequential_string("0123456789ABCDEF"));
    }

    #[test]
    fn test_sequential_case_insensitive() {
        assert!(is_sequential_string("abcdefgh"));
    }

    #[test]
    fn test_not_sequential_random() {
        assert!(!is_sequential_string("xK9#mP2$vL"));
    }

    #[test]
    fn test_not_sequential_real_secret() {
        assert!(!is_sequential_string("AKIAxyz12345RANDOM"));
    }

    // --- is_potential_uuid ---

    #[test]
    fn test_uuid_match() {
        assert!(is_potential_uuid("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_uuid_uppercase() {
        assert!(is_potential_uuid("550E8400-E29B-41D4-A716-446655440000"));
    }

    #[test]
    fn test_uuid_embedded() {
        assert!(is_potential_uuid(
            "prefix-550e8400-e29b-41d4-a716-446655440000-suffix"
        ));
    }

    #[test]
    fn test_not_uuid() {
        assert!(!is_potential_uuid("not-a-uuid-string"));
    }

    // --- is_likely_id_string ---

    #[test]
    fn test_id_string_with_prefix_id() {
        assert!(is_likely_id_string("12345", "id = 12345", false));
    }

    #[test]
    fn test_id_string_with_user_id() {
        assert!(is_likely_id_string("abc", "user_id = abc", false));
    }

    #[test]
    fn test_id_string_plural() {
        assert!(is_likely_id_string("abc", "user_ids = abc", false));
    }

    #[test]
    fn test_id_string_skips_regex_plugin() {
        assert!(!is_likely_id_string("12345", "id = 12345", true));
    }

    #[test]
    fn test_id_string_not_id() {
        assert!(!is_likely_id_string("secret", "password = secret", false));
    }

    #[test]
    fn test_id_string_secret_not_in_line() {
        assert!(!is_likely_id_string("nothere", "id = something", false));
    }

    // --- is_non_text_file ---

    #[test]
    fn test_non_text_png() {
        assert!(is_non_text_file("image.png"));
    }

    #[test]
    fn test_non_text_zip() {
        assert!(is_non_text_file("archive.zip"));
    }

    #[test]
    fn test_non_text_lock() {
        assert!(is_non_text_file("something.lock"));
    }

    #[test]
    fn test_text_file_py() {
        assert!(!is_non_text_file("script.py"));
    }

    #[test]
    fn test_text_file_rs() {
        assert!(!is_non_text_file("main.rs"));
    }

    // --- is_templated_secret ---

    #[test]
    fn test_templated_curly_braces() {
        assert!(is_templated_secret("{secret_value}"));
    }

    #[test]
    fn test_templated_angle_brackets() {
        assert!(is_templated_secret("<secret_value>"));
    }

    #[test]
    fn test_templated_dollar_curly() {
        assert!(is_templated_secret("${secret_value}"));
    }

    #[test]
    fn test_templated_single_char() {
        assert!(is_templated_secret("x"));
    }

    #[test]
    fn test_templated_empty() {
        assert!(is_templated_secret(""));
    }

    #[test]
    fn test_not_templated_normal() {
        assert!(!is_templated_secret("real_secret_123"));
    }

    // --- is_prefixed_with_dollar_sign ---

    #[test]
    fn test_dollar_prefix() {
        assert!(is_prefixed_with_dollar_sign("$variable"));
    }

    #[test]
    fn test_no_dollar_prefix() {
        assert!(!is_prefixed_with_dollar_sign("variable"));
    }

    #[test]
    fn test_dollar_prefix_empty() {
        assert!(!is_prefixed_with_dollar_sign(""));
    }

    // --- is_indirect_reference ---

    #[test]
    fn test_indirect_function_call() {
        assert!(is_indirect_reference("secret = get_secret_key()"));
    }

    #[test]
    fn test_indirect_dict_access() {
        assert!(is_indirect_reference("secret = request.headers['apikey']"));
    }

    #[test]
    fn test_indirect_walrus_operator() {
        assert!(is_indirect_reference("val := config.get('key')"));
    }

    #[test]
    fn test_not_indirect_simple_assignment() {
        assert!(!is_indirect_reference("secret = 'hunter2'"));
    }

    #[test]
    fn test_indirect_long_line_skipped() {
        let long_line = "a".repeat(1001);
        assert!(!is_indirect_reference(&long_line));
    }

    // --- is_lock_file ---

    #[test]
    fn test_lock_file_package_lock() {
        assert!(is_lock_file("package-lock.json"));
    }

    #[test]
    fn test_lock_file_cargo_lock() {
        assert!(is_lock_file("path/to/Cargo.lock"));
    }

    #[test]
    fn test_lock_file_yarn() {
        assert!(is_lock_file("yarn.lock"));
    }

    #[test]
    fn test_not_lock_file() {
        assert!(!is_lock_file("package.json"));
    }

    #[test]
    fn test_lock_file_poetry() {
        assert!(is_lock_file("poetry.lock"));
    }

    // --- is_not_alphanumeric_string ---

    #[test]
    fn test_not_alphanumeric_symbols() {
        assert!(is_not_alphanumeric_string("*****"));
    }

    #[test]
    fn test_not_alphanumeric_digits_only() {
        assert!(is_not_alphanumeric_string("12345"));
    }

    #[test]
    fn test_alphanumeric_has_letters() {
        assert!(!is_not_alphanumeric_string("abc123"));
    }

    #[test]
    fn test_alphanumeric_all_letters() {
        assert!(!is_not_alphanumeric_string("secret"));
    }

    // --- is_swagger_file ---

    #[test]
    fn test_swagger_html() {
        assert!(is_swagger_file("swagger-ui.html"));
    }

    #[test]
    fn test_swagger_directory() {
        assert!(is_swagger_file("/api/swagger/docs"));
    }

    #[test]
    fn test_not_swagger() {
        assert!(!is_swagger_file("main.py"));
    }
}
