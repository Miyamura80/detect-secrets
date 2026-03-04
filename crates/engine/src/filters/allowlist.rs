//! Allowlist filter — pragma-based comment allowlisting.
//!
//! Ported from detect_secrets/filters/allowlist.py
//!
//! Supports comment pragmas like:
//!   `# pragma: allowlist secret`
//!   `// pragma: whitelist secret`
//!   `# pragma: allowlist nextline secret` (on previous line)

use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Comment syntax definitions: (start_pattern, end_pattern).
/// Empty end_pattern means single-line comment to end of line.
static COMMENT_TUPLES: Lazy<Vec<(&str, &str)>> = Lazy::new(|| {
    vec![
        (r"#", ""),                   // Python, YAML, shell
        (r"//", ""),                  // Go, C++, Java
        (r"/\*", r" *\*/"),           // C, CSS
        (r"'", ""),                   // Visual Basic .NET
        (r"--", ""),                  // SQL
        (r"<!--[# \t]*?", r" *?-->"), // XML, HTML
    ]
});

/// File extension to comment tuple index mapping.
fn file_extension_to_comment_index(ext: &str) -> Option<usize> {
    match ext {
        "yaml" | "yml" => Some(0), // '#' comment
        _ => None,
    }
}

/// Build an allowlist regex for a given comment tuple and nextline mode.
fn build_allowlist_regex(start: &str, end: &str, nextline: bool) -> Regex {
    let anchor = if nextline { "^" } else { "" };
    let keyword = if nextline {
        "allowlist"
    } else {
        "(allow|white)list"
    };
    let nextline_part = if nextline { "[ -]nextline" } else { "" };

    let pattern = format!(
        r"{}[ \t]*{} *pragma: ?{}{}[ -]secret.*?{}[ \t]*$",
        anchor, start, keyword, nextline_part, end
    );
    Regex::new(&pattern).unwrap()
}

/// Pre-compiled allowlist regexes: [same_line_regexes, nextline_regexes] for each comment tuple.
struct AllowlistRegexes {
    same_line: Vec<Regex>,
    nextline: Vec<Regex>,
}

static ALL_REGEXES: Lazy<AllowlistRegexes> = Lazy::new(|| {
    let mut same_line = Vec::new();
    let mut nextline = Vec::new();
    for (start, end) in COMMENT_TUPLES.iter() {
        same_line.push(build_allowlist_regex(start, end, false));
        nextline.push(build_allowlist_regex(start, end, true));
    }
    AllowlistRegexes {
        same_line,
        nextline,
    }
});

/// Check if a line (or its previous line) contains an allowlist pragma comment.
///
/// Matches Python's `is_line_allowlisted()`.
///
/// - `filename`: Used to determine which comment syntaxes to check.
/// - `line`: The current line being scanned.
/// - `previous_line`: The line before the current line (for nextline pragmas).
pub fn is_line_allowlisted(filename: &str, line: &str, previous_line: &str) -> bool {
    let ext = Path::new(filename)
        .extension()
        .map(|e| e.to_string_lossy().to_string());
    let ext_str = ext.as_deref().unwrap_or("");

    // If we have a specific file type mapping, only check that comment syntax
    if let Some(idx) = file_extension_to_comment_index(ext_str) {
        // Check same-line regex
        if ALL_REGEXES.same_line[idx].is_match(line) {
            return true;
        }
        // Check nextline regex against previous line
        if ALL_REGEXES.nextline[idx].is_match(previous_line) {
            return true;
        }
    } else {
        // Check all comment syntaxes
        for regex in &ALL_REGEXES.same_line {
            if regex.is_match(line) {
                return true;
            }
        }
        for regex in &ALL_REGEXES.nextline {
            if regex.is_match(previous_line) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Same-line allowlist pragmas ---

    #[test]
    fn test_python_allowlist() {
        assert!(is_line_allowlisted(
            "config.py",
            "password = 'hunter2'  # pragma: allowlist secret",
            ""
        ));
    }

    #[test]
    fn test_python_whitelist() {
        assert!(is_line_allowlisted(
            "config.py",
            "password = 'hunter2'  # pragma: whitelist secret",
            ""
        ));
    }

    #[test]
    fn test_golang_allowlist() {
        assert!(is_line_allowlisted(
            "main.go",
            "secret := \"value\" // pragma: allowlist secret",
            ""
        ));
    }

    #[test]
    fn test_c_style_allowlist() {
        assert!(is_line_allowlisted(
            "main.c",
            "char *s = \"val\"; /* pragma: allowlist secret */",
            ""
        ));
    }

    #[test]
    fn test_sql_allowlist() {
        assert!(is_line_allowlisted(
            "schema.sql",
            "INSERT INTO t VALUES('secret') -- pragma: allowlist secret",
            ""
        ));
    }

    #[test]
    fn test_vb_allowlist() {
        assert!(is_line_allowlisted(
            "module.vb",
            "Dim s As String = \"secret\" ' pragma: allowlist secret",
            ""
        ));
    }

    #[test]
    fn test_xml_allowlist() {
        assert!(is_line_allowlisted(
            "config.xml",
            "<password>secret</password> <!-- pragma: allowlist secret -->",
            ""
        ));
    }

    #[test]
    fn test_hyphen_separator() {
        assert!(is_line_allowlisted(
            "config.py",
            "password = 'hunter2'  # pragma: allowlist-secret",
            ""
        ));
    }

    #[test]
    fn test_no_pragma_no_match() {
        assert!(!is_line_allowlisted(
            "config.py",
            "password = 'hunter2'",
            ""
        ));
    }

    // --- Nextline allowlist pragmas ---

    #[test]
    fn test_nextline_python() {
        assert!(is_line_allowlisted(
            "config.py",
            "password = 'hunter2'",
            "# pragma: allowlist nextline secret"
        ));
    }

    #[test]
    fn test_nextline_golang() {
        assert!(is_line_allowlisted(
            "main.go",
            "secret := \"value\"",
            "// pragma: allowlist nextline secret"
        ));
    }

    #[test]
    fn test_nextline_must_start_at_beginning() {
        // Nextline pragma requires ^ anchor - must be at line start
        assert!(is_line_allowlisted(
            "config.py",
            "password = 'hunter2'",
            "  # pragma: allowlist nextline secret"
        ));
    }

    #[test]
    fn test_nextline_no_whitelist() {
        // Nextline does NOT accept "whitelist", only "allowlist"
        assert!(!is_line_allowlisted(
            "config.py",
            "password = 'hunter2'",
            "# pragma: whitelist nextline secret"
        ));
    }

    #[test]
    fn test_nextline_hyphen_separator() {
        assert!(is_line_allowlisted(
            "config.py",
            "password = 'hunter2'",
            "# pragma: allowlist-nextline-secret"
        ));
    }

    // --- YAML-specific optimization ---

    #[test]
    fn test_yaml_uses_hash_comment_only() {
        // YAML files should match # comments
        assert!(is_line_allowlisted(
            "config.yaml",
            "key: value  # pragma: allowlist secret",
            ""
        ));
    }

    #[test]
    fn test_yaml_skips_non_hash_comments() {
        // YAML files should NOT match // comments (optimization)
        assert!(!is_line_allowlisted(
            "config.yaml",
            "key: value  // pragma: allowlist secret",
            ""
        ));
    }

    #[test]
    fn test_yml_extension() {
        assert!(is_line_allowlisted(
            "config.yml",
            "key: value  # pragma: allowlist secret",
            ""
        ));
    }
}
