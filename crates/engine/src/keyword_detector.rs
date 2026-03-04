//! KeywordDetector plugin — detects secret-sounding variable names.
//!
//! Ports Python's `detect_secrets.plugins.keyword.KeywordDetector`.
//! Uses file-type-aware regex selection to match assignment patterns
//! containing denylisted keywords (e.g. `password`, `api_key`, `secret`).
//!
//! Python's patterns use backreferences (`\1`) for quote matching, which
//! Rust's `regex` crate doesn't support. We generate separate patterns
//! for each quote type (single, double) and use named capture groups.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::plugin::SecretDetector;
use crate::potential_secret::PotentialSecret;

// ---------------------------------------------------------------------------
// Denylist keywords (all lowercase, regex fragments)
// ---------------------------------------------------------------------------

const DENYLIST: &[&str] = &[
    "api_?key",
    "auth_?key",
    "service_?key",
    "account_?key",
    "db_?key",
    "database_?key",
    "priv_?key",
    "private_?key",
    "client_?key",
    "db_?pass",
    "database_?pass",
    "key_?pass",
    "password",
    "passwd",
    "pwd",
    "secret",
    "contrase\u{f1}a", // contraseña
    "contrasena",
];

// ---------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------

const CLOSING: &str = r#"[]\'"]{0,2}"#;
const AFFIX_REGEX: &str = r"\w*";
const OPTIONAL_WHITESPACE: &str = r"\s*";
const OPTIONAL_NON_WHITESPACE: &str = r#"[^\s]{0,50}?"#;
const SECRET: &str = r#"[^\v'"]*\w[^\v'"]*[^\v,'"` ]"#;

fn denylist_regex() -> String {
    let joined = DENYLIST.join("|");
    format!("(?:{}){}", joined, AFFIX_REGEX)
}

fn denylist_regex_with_prefix() -> String {
    let joined = DENYLIST.join("|");
    format!("{}(?:{}){}", AFFIX_REGEX, joined, AFFIX_REGEX)
}

// ---------------------------------------------------------------------------
// File type classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    Cls,
    Example,
    Go,
    Java,
    JavaScript,
    Php,
    ObjectiveC,
    Python,
    Swift,
    Terraform,
    Yaml,
    CSharp,
    C,
    CPlusPlus,
    Config,
    Ini,
    Properties,
    Toml,
    Other,
}

pub fn determine_file_type(filename: &str) -> FileType {
    let ext = filename
        .rsplit('.')
        .next()
        .map(|e| format!(".{}", e.to_lowercase()));

    match ext.as_deref() {
        Some(".cls") => FileType::Cls,
        Some(".example") => FileType::Example,
        Some(".eyaml") | Some(".yaml") | Some(".yml") => FileType::Yaml,
        Some(".go") => FileType::Go,
        Some(".java") => FileType::Java,
        Some(".js") => FileType::JavaScript,
        Some(".m") => FileType::ObjectiveC,
        Some(".php") => FileType::Php,
        Some(".py") | Some(".pyi") => FileType::Python,
        Some(".swift") => FileType::Swift,
        Some(".tf") => FileType::Terraform,
        Some(".cs") => FileType::CSharp,
        Some(".c") => FileType::C,
        Some(".cpp") => FileType::CPlusPlus,
        Some(".cnf") | Some(".conf") | Some(".cfg") | Some(".cf") => FileType::Config,
        Some(".ini") => FileType::Ini,
        Some(".properties") => FileType::Properties,
        Some(".toml") => FileType::Toml,
        _ => FileType::Other,
    }
}

// ---------------------------------------------------------------------------
// Pattern extraction helpers
//
// Each function builds regex variants (one per quote type) to avoid
// backreferences. All use a named group `secret` for the matched value.
// ---------------------------------------------------------------------------

/// Extract the first `secret` named group match from any of the regexes.
fn extract_secret(regexes: &[Regex], input: &str) -> Option<String> {
    for re in regexes {
        if let Some(caps) = re.captures(input) {
            if let Some(m) = caps.name("secret") {
                let val = m.as_str();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

// -- FOLLOWED_BY_COLON_EQUAL_SIGNS: password := "bar" --

fn build_colon_equal_signs() -> Vec<Regex> {
    let dl = denylist_regex();
    let ws = OPTIONAL_WHITESPACE;
    let cl = CLOSING;
    let s = SECRET;
    vec![
        // Double-quoted
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?{ws}:={ws}"(?P<secret>{s})""#)).unwrap(),
        // Single-quoted
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?{ws}:={ws}'(?P<secret>{s})'"#)).unwrap(),
        // No quote
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?{ws}:={ws}(?P<secret>{s})"#)).unwrap(),
    ]
}

// -- FOLLOWED_BY_COLON: api_key: foo --

fn build_colon() -> Vec<Regex> {
    let dl = denylist_regex();
    let ws = OPTIONAL_WHITESPACE;
    let cl = CLOSING;
    let s = SECRET;
    vec![
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?:{ws}"(?P<secret>{s})""#)).unwrap(),
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?:{ws}'(?P<secret>{s})'"#)).unwrap(),
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?:{ws}(?P<secret>{s})"#)).unwrap(),
    ]
}

// -- FOLLOWED_BY_COLON_QUOTES_REQUIRED: api_key: "foo" --

fn build_colon_quotes_required() -> Vec<Regex> {
    let dl = denylist_regex();
    let ws = OPTIONAL_WHITESPACE;
    let cl = CLOSING;
    let s = SECRET;
    vec![
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?:{ws}"(?P<secret>{s})""#)).unwrap(),
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?:{ws}'(?P<secret>{s})'"#)).unwrap(),
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?:{ws}`(?P<secret>{s})`"#)).unwrap(),
    ]
}

// -- FOLLOWED_BY_EQUAL_SIGNS_OPTIONAL_BRACKETS: password[] = "bar" --

fn build_equal_signs_optional_brackets_quotes_required() -> Vec<Regex> {
    let dl = denylist_regex();
    let ws = OPTIONAL_WHITESPACE;
    let s = SECRET;
    // Only double-quote variant (Python uses literal `"`)
    vec![Regex::new(&format!(
        r#"(?i){dl}(?:\[[0-9]*\])?{ws}[!=]{{1,2}}{ws}(?:@)?"(?P<secret>{s})""#
    ))
    .unwrap()]
}

// -- FOLLOWED_BY_OPTIONAL_ASSIGN_QUOTES_REQUIRED: secret("bar") --

fn build_optional_assign_quotes_required() -> Vec<Regex> {
    let dl = denylist_regex();
    let s = SECRET;
    // Only double-quote variant (Python uses literal `"`)
    vec![Regex::new(&format!(r#"{dl}(?:\.assign)?\("(?P<secret>{s})""#)).unwrap()]
}

// -- FOLLOWED_BY_EQUAL_SIGNS: password = bar --

fn build_equal_signs() -> Vec<Regex> {
    let dl = denylist_regex();
    let ws = OPTIONAL_WHITESPACE;
    let cl = CLOSING;
    let s = SECRET;
    vec![
        Regex::new(&format!(
            r#"(?i){dl}(?:{cl})?{ws}(?:={{1,3}}|!==?){ws}"(?P<secret>{s})""#
        ))
        .unwrap(),
        Regex::new(&format!(
            r#"(?i){dl}(?:{cl})?{ws}(?:={{1,3}}|!==?){ws}'(?P<secret>{s})'"#
        ))
        .unwrap(),
        Regex::new(&format!(
            r#"(?i){dl}(?:{cl})?{ws}(?:={{1,3}}|!==?){ws}(?P<secret>{s})"#
        ))
        .unwrap(),
    ]
}

// -- FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED: password = "bar" --

fn build_equal_signs_quotes_required() -> Vec<Regex> {
    let dl = denylist_regex();
    let ws = OPTIONAL_WHITESPACE;
    let cl = CLOSING;
    let s = SECRET;
    vec![
        Regex::new(&format!(
            r#"(?i){dl}(?:{cl})?{ws}(?:={{1,3}}|!==?){ws}"(?P<secret>{s})""#
        ))
        .unwrap(),
        Regex::new(&format!(
            r#"(?i){dl}(?:{cl})?{ws}(?:={{1,3}}|!==?){ws}'(?P<secret>{s})'"#
        ))
        .unwrap(),
        Regex::new(&format!(
            r#"(?i){dl}(?:{cl})?{ws}(?:={{1,3}}|!==?){ws}`(?P<secret>{s})`"#
        ))
        .unwrap(),
    ]
}

// -- PRECEDED_BY_EQUAL_COMPARISON: "bar" == my_password --

fn build_preceded_by_equal_comparison_quotes_required() -> Vec<Regex> {
    let dl = denylist_regex_with_prefix();
    let ws = OPTIONAL_WHITESPACE;
    let s = SECRET;
    vec![
        Regex::new(&format!(r#""(?P<secret>{s})"{ws}[!=]{{2,3}}{ws}{dl}"#)).unwrap(),
        Regex::new(&format!(r#"'(?P<secret>{s})'{ws}[!=]{{2,3}}{ws}{dl}"#)).unwrap(),
        Regex::new(&format!(r#"`(?P<secret>{s})`{ws}[!=]{{2,3}}{ws}{dl}"#)).unwrap(),
    ]
}

// -- FOLLOWED_BY_QUOTES_AND_SEMICOLON: private_key "something"; --

fn build_quotes_and_semicolon() -> Vec<Regex> {
    let dl = denylist_regex();
    let ws = OPTIONAL_WHITESPACE;
    let nws = OPTIONAL_NON_WHITESPACE;
    let s = SECRET;
    vec![
        Regex::new(&format!(r#"(?i){dl}{nws}{ws}"(?P<secret>{s})";"#)).unwrap(),
        Regex::new(&format!(r#"(?i){dl}{nws}{ws}'(?P<secret>{s})';"#)).unwrap(),
        Regex::new(&format!(r#"(?i){dl}{nws}{ws}`(?P<secret>{s})`;"#)).unwrap(),
    ]
}

// -- FOLLOWED_BY_ARROW_FUNCTION_SIGN_QUOTES_REQUIRED: password => "bar" --

fn build_arrow_function_quotes_required() -> Vec<Regex> {
    let dl = denylist_regex();
    let ws = OPTIONAL_WHITESPACE;
    let cl = CLOSING;
    let s = SECRET;
    vec![
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?{ws}=>?{ws}"(?P<secret>{s})""#)).unwrap(),
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?{ws}=>?{ws}'(?P<secret>{s})'"#)).unwrap(),
        Regex::new(&format!(r#"(?i){dl}(?:{cl})?{ws}=>?{ws}`(?P<secret>{s})`"#)).unwrap(),
    ]
}

// ---------------------------------------------------------------------------
// Regex set types — each file type maps to a set of patterns
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegexSet {
    Config,
    Golang,
    CommonC,
    CPlusPlus,
    QuotesRequired,
}

fn regex_set_for_filetype(ft: FileType) -> RegexSet {
    match ft {
        FileType::Go => RegexSet::Golang,
        FileType::ObjectiveC | FileType::CSharp | FileType::C => RegexSet::CommonC,
        FileType::CPlusPlus => RegexSet::CPlusPlus,
        FileType::Cls
        | FileType::Java
        | FileType::JavaScript
        | FileType::Python
        | FileType::Swift
        | FileType::Terraform => RegexSet::QuotesRequired,
        FileType::Yaml
        | FileType::Config
        | FileType::Ini
        | FileType::Properties
        | FileType::Toml => RegexSet::Config,
        _ => RegexSet::QuotesRequired,
    }
}

/// A group of regex variants for one pattern type.
type PatternGroup = Vec<Regex>;

// Cached (compile-once) pattern groups per regex set.
static CONFIG_PATTERNS: Lazy<Vec<PatternGroup>> = Lazy::new(|| {
    vec![
        build_colon(),
        build_preceded_by_equal_comparison_quotes_required(),
        build_equal_signs(),
        build_quotes_and_semicolon(),
    ]
});

static GOLANG_PATTERNS: Lazy<Vec<PatternGroup>> = Lazy::new(|| {
    vec![
        build_colon_equal_signs(),
        build_preceded_by_equal_comparison_quotes_required(),
        build_equal_signs(),
        build_quotes_and_semicolon(),
    ]
});

static COMMONC_PATTERNS: Lazy<Vec<PatternGroup>> =
    Lazy::new(|| vec![build_equal_signs_optional_brackets_quotes_required()]);

static CPLUSPLUS_PATTERNS: Lazy<Vec<PatternGroup>> = Lazy::new(|| {
    vec![
        build_optional_assign_quotes_required(),
        build_equal_signs_quotes_required(),
    ]
});

static QUOTES_REQUIRED_PATTERNS: Lazy<Vec<PatternGroup>> = Lazy::new(|| {
    vec![
        build_colon_quotes_required(),
        build_preceded_by_equal_comparison_quotes_required(),
        build_equal_signs_quotes_required(),
        build_quotes_and_semicolon(),
        build_arrow_function_quotes_required(),
    ]
});

fn cached_pattern_groups(set: RegexSet) -> &'static [PatternGroup] {
    match set {
        RegexSet::Config => &CONFIG_PATTERNS,
        RegexSet::Golang => &GOLANG_PATTERNS,
        RegexSet::CommonC => &COMMONC_PATTERNS,
        RegexSet::CPlusPlus => &CPLUSPLUS_PATTERNS,
        RegexSet::QuotesRequired => &QUOTES_REQUIRED_PATTERNS,
    }
}

// ---------------------------------------------------------------------------
// KeywordDetector
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct KeywordDetector {
    keyword_exclude: Option<Regex>,
}

impl KeywordDetector {
    pub fn new(keyword_exclude: Option<&str>) -> Self {
        let keyword_exclude = keyword_exclude.and_then(|pat| {
            if pat.is_empty() {
                None
            } else {
                Regex::new(&format!("(?i){}", pat)).ok()
            }
        });
        Self { keyword_exclude }
    }

    /// Run pattern groups against input, returning matched secret strings.
    /// Deduplicates results (Python uses `set()` for this).
    fn analyze_with_groups(&self, input: &str, groups: &[PatternGroup]) -> Vec<String> {
        if let Some(ref exclude) = self.keyword_exclude {
            if exclude.is_match(input) {
                return Vec::new();
            }
        }

        let mut seen = std::collections::HashSet::new();
        let mut results = Vec::new();
        for group in groups {
            if let Some(secret) = extract_secret(group, input) {
                if seen.insert(secret.clone()) {
                    results.push(secret);
                }
            }
        }
        results
    }

    /// Analyze using the default regex set (QuotesRequired).
    pub fn analyze_string_default(&self, input: &str) -> Vec<String> {
        let groups = cached_pattern_groups(RegexSet::QuotesRequired);
        self.analyze_with_groups(input, groups)
    }

    /// Analyze a line using file-type-specific regex set.
    pub fn analyze_line_for_file(
        &self,
        filename: &str,
        line: &str,
        line_number: u64,
    ) -> Vec<PotentialSecret> {
        let ft = determine_file_type(filename);
        let rs = regex_set_for_filetype(ft);
        let groups = cached_pattern_groups(rs);
        let matches = self.analyze_with_groups(line, groups);

        matches
            .into_iter()
            .map(|secret| {
                PotentialSecret::new(
                    self.secret_type(),
                    filename,
                    &secret,
                    line_number,
                    None,
                    false,
                )
            })
            .collect()
    }
}

impl Default for KeywordDetector {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SecretDetector for KeywordDetector {
    fn secret_type(&self) -> &str {
        "Secret Keyword"
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        self.analyze_string_default(input)
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PotentialSecret> {
        self.analyze_line_for_file(filename, line, line_number)
    }

    fn json(&self) -> serde_json::Value {
        let exclude_str = self
            .keyword_exclude
            .as_ref()
            .map(|r| {
                r.as_str()
                    .strip_prefix("(?i)")
                    .unwrap_or(r.as_str())
                    .to_string()
            })
            .unwrap_or_default();
        serde_json::json!({
            "keyword_exclude": exclude_str,
            "name": "KeywordDetector",
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_type() {
        let d = KeywordDetector::default();
        assert_eq!(d.secret_type(), "Secret Keyword");
    }

    #[test]
    fn test_default_no_exclude() {
        let d = KeywordDetector::default();
        assert!(d.keyword_exclude.is_none());
    }

    #[test]
    fn test_keyword_exclude() {
        let d = KeywordDetector::new(Some("test_"));
        assert!(d.keyword_exclude.is_some());
    }

    #[test]
    fn test_empty_exclude_is_none() {
        let d = KeywordDetector::new(Some(""));
        assert!(d.keyword_exclude.is_none());
    }

    // ---- Python file (quotes required) ----

    #[test]
    fn test_python_password_double_quotes() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("test.py", r#"password = "mysecretvalue""#, 1);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("mysecretvalue"));
    }

    #[test]
    fn test_python_api_key_double_quotes() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("test.py", r#"api_key = "abc123def""#, 2);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("abc123def"));
    }

    #[test]
    fn test_python_single_quotes() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("test.py", "secret = 'hunter2'", 3);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("hunter2"));
    }

    #[test]
    fn test_python_no_match_without_quotes() {
        let d = KeywordDetector::default();
        // Quotes required for Python files — function call not quoted
        let secrets = d.analyze_line("test.py", "password = get_password()", 1);
        assert!(secrets.is_empty());
    }

    // ---- YAML file (config) ----

    #[test]
    fn test_yaml_colon_unquoted() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("config.yaml", "password: mysecretvalue", 1);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("mysecretvalue"));
    }

    #[test]
    fn test_yaml_colon_quoted() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("config.yml", r#"api_key: "abc123""#, 1);
        assert!(!secrets.is_empty());
    }

    // ---- Go file (golang) ----

    #[test]
    fn test_go_walrus_operator() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("main.go", r#"password := "secret_value""#, 10);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("secret_value"));
    }

    // ---- C file (common C) ----

    #[test]
    fn test_c_double_quote_assignment() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("main.c", r#"password = "mypassword""#, 1);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("mypassword"));
    }

    #[test]
    fn test_c_sharp_double_quote() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("Program.cs", r#"password = "secretval""#, 5);
        assert_eq!(secrets.len(), 1);
    }

    // ---- C++ file ----

    #[test]
    fn test_cpp_string_constructor() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("main.cpp", r#"secret("bar_value")"#, 1);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("bar_value"));
    }

    #[test]
    fn test_cpp_assign_method() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("main.cpp", r#"secret.assign("bar_value")"#, 1);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("bar_value"));
    }

    // ---- Reverse comparison ----

    #[test]
    fn test_reverse_comparison() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("test.py", r#""bar_value" == my_password"#, 1);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("bar_value"));
    }

    // ---- Arrow function ----

    #[test]
    fn test_arrow_function() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("test.js", r#"password => "arrow_secret""#, 1);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_value.as_deref(), Some("arrow_secret"));
    }

    // ---- Semicolon pattern ----

    #[test]
    fn test_quotes_and_semicolon() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("nginx.conf", r#"private_key "cert_value";"#, 1);
        assert!(!secrets.is_empty());
    }

    // ---- keyword_exclude filter ----

    #[test]
    fn test_keyword_exclude_filters() {
        let d = KeywordDetector::new(Some("test_"));
        let secrets = d.analyze_line("test.py", r#"test_password = "value""#, 1);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_keyword_exclude_allows_non_matching() {
        let d = KeywordDetector::new(Some("test_"));
        let secrets = d.analyze_line("test.py", r#"password = "value""#, 1);
        assert_eq!(secrets.len(), 1);
    }

    // ---- No match ----

    #[test]
    fn test_no_match_plain_text() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("test.py", "just some normal code", 1);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_no_match_keyword_without_assignment() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("test.py", "password", 1);
        assert!(secrets.is_empty());
    }

    // ---- FileType detection ----

    #[test]
    fn test_determine_file_type_python() {
        assert_eq!(determine_file_type("test.py"), FileType::Python);
        assert_eq!(determine_file_type("stub.pyi"), FileType::Python);
    }

    #[test]
    fn test_determine_file_type_go() {
        assert_eq!(determine_file_type("main.go"), FileType::Go);
    }

    #[test]
    fn test_determine_file_type_yaml() {
        assert_eq!(determine_file_type("config.yaml"), FileType::Yaml);
        assert_eq!(determine_file_type("config.yml"), FileType::Yaml);
        assert_eq!(determine_file_type("secrets.eyaml"), FileType::Yaml);
    }

    #[test]
    fn test_determine_file_type_c_family() {
        assert_eq!(determine_file_type("main.c"), FileType::C);
        assert_eq!(determine_file_type("main.cpp"), FileType::CPlusPlus);
        assert_eq!(determine_file_type("Program.cs"), FileType::CSharp);
        assert_eq!(
            determine_file_type("ViewController.m"),
            FileType::ObjectiveC
        );
    }

    #[test]
    fn test_determine_file_type_config() {
        assert_eq!(determine_file_type("my.cnf"), FileType::Config);
        assert_eq!(determine_file_type("app.conf"), FileType::Config);
        assert_eq!(determine_file_type("settings.cfg"), FileType::Config);
        assert_eq!(determine_file_type("proxy.cf"), FileType::Config);
    }

    #[test]
    fn test_determine_file_type_other() {
        assert_eq!(determine_file_type("readme.md"), FileType::Other);
        assert_eq!(determine_file_type("data.json"), FileType::Other);
    }

    #[test]
    fn test_determine_file_type_various() {
        assert_eq!(determine_file_type("Test.cls"), FileType::Cls);
        assert_eq!(determine_file_type("App.java"), FileType::Java);
        assert_eq!(determine_file_type("app.js"), FileType::JavaScript);
        assert_eq!(determine_file_type("main.swift"), FileType::Swift);
        assert_eq!(determine_file_type("infra.tf"), FileType::Terraform);
        assert_eq!(determine_file_type("app.ini"), FileType::Ini);
        assert_eq!(determine_file_type("app.properties"), FileType::Properties);
        assert_eq!(determine_file_type("Cargo.toml"), FileType::Toml);
    }

    // ---- JSON serialization ----

    #[test]
    fn test_json_no_exclude() {
        let d = KeywordDetector::default();
        let j = d.json();
        assert_eq!(j["name"], "KeywordDetector");
        assert_eq!(j["keyword_exclude"], "");
    }

    #[test]
    fn test_json_with_exclude() {
        let d = KeywordDetector::new(Some("test_"));
        let j = d.json();
        assert_eq!(j["name"], "KeywordDetector");
        assert_eq!(j["keyword_exclude"], "test_");
    }

    // ---- Multiple keywords ----

    #[test]
    fn test_various_keywords() {
        let d = KeywordDetector::default();
        for keyword in &["password", "secret", "api_key", "passwd", "pwd"] {
            let line = format!(r#"{} = "testvalue""#, keyword);
            let secrets = d.analyze_line("test.py", &line, 1);
            assert!(
                !secrets.is_empty(),
                "Expected match for keyword: {}",
                keyword
            );
        }
    }

    #[test]
    fn test_keyword_with_suffix() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("test.py", r#"password_secure = "testvalue""#, 1);
        assert_eq!(secrets.len(), 1);
    }

    // ---- Metadata ----

    #[test]
    fn test_line_metadata() {
        let d = KeywordDetector::default();
        let secrets = d.analyze_line("app.py", r#"password = "val""#, 42);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].filename, "app.py");
        assert_eq!(secrets[0].line_number, 42);
        assert_eq!(secrets[0].secret_type, "Secret Keyword");
    }
}
