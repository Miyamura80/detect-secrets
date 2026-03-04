//! Filters for reducing false positives in secret detection.
//!
//! Ported from Python detect-secrets filters:
//! - heuristic: Various heuristic checks (sequential strings, UUIDs, templates, etc.)
//! - allowlist: Pragma-based comment allowlisting
//! - common: File validation filters (invalid file, non-text file)
//! - regex_filter: Regex-based exclusion filters (line, file, secret)
//! - wordlist: Wordlist-based exclusion filter (Aho-Corasick)
//! - registry: Filter dependency injection and parameter introspection

pub mod allowlist;
pub mod common;
pub mod heuristic;
pub mod regex_filter;
pub mod registry;
pub mod wordlist;
