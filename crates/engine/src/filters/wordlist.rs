//! Wordlist-based exclusion filter.
//!
//! Ported from detect_secrets/filters/wordlist.py
//!
//! Filters secrets that contain known false-positive words (e.g., "AKIATEST"
//! for AWS keys). Uses the Aho-Corasick algorithm for efficient multi-pattern
//! substring matching.

use aho_corasick::AhoCorasick;
use sha1::{Digest, Sha1};
use std::fs;
use std::io;
use std::path::Path;

/// A compiled wordlist filter backed by an Aho-Corasick automaton.
///
/// All matching is case-insensitive.
#[derive(Clone)]
pub struct WordlistFilter {
    automaton: AhoCorasick,
    /// The file name the wordlist was loaded from.
    pub file_name: String,
    /// SHA1 hash of the wordlist file contents.
    pub file_hash: String,
    /// Minimum word length threshold used when loading.
    pub min_length: usize,
}

impl WordlistFilter {
    /// Initialize a wordlist filter from a file.
    ///
    /// Matches Python's `wordlist.initialize()`.
    ///
    /// - `wordlist_filename`: Path to a text file with one word per line.
    /// - `min_length`: Words shorter than this are ignored (default: 3).
    ///
    /// Returns the compiled filter or an error if the file cannot be read.
    pub fn from_file(wordlist_filename: &str, min_length: usize) -> io::Result<Self> {
        let content = fs::read_to_string(wordlist_filename)?;
        let file_hash = compute_file_hash(wordlist_filename)?;
        let words = Self::parse_words(&content, min_length);
        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&words)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(WordlistFilter {
            automaton,
            file_name: wordlist_filename.to_string(),
            file_hash,
            min_length,
        })
    }

    /// Initialize a wordlist filter from a list of words directly.
    ///
    /// Useful for testing or when the word list is already in memory.
    pub fn from_words(words: &[&str], min_length: usize) -> Result<Self, String> {
        let filtered: Vec<String> = words
            .iter()
            .map(|w| w.trim().to_lowercase())
            .filter(|w| w.len() >= min_length)
            .collect();

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&filtered)
            .map_err(|e| e.to_string())?;

        Ok(WordlistFilter {
            automaton,
            file_name: String::new(),
            file_hash: String::new(),
            min_length,
        })
    }

    /// Check if a secret contains any word from the wordlist.
    ///
    /// Matches Python's `wordlist.should_exclude_secret()`.
    /// Returns `true` if the secret should be excluded (contains a wordlist word).
    pub fn should_exclude_secret(&self, secret: &str) -> bool {
        // Case-insensitive matching is handled by the automaton
        self.automaton.is_match(secret)
    }

    /// Parse words from file content, filtering by minimum length.
    fn parse_words(content: &str, min_length: usize) -> Vec<String> {
        content
            .lines()
            .map(|line| line.trim().to_lowercase())
            .filter(|word| word.len() >= min_length)
            .collect()
    }
}

/// Compute the SHA1 hash of a file's contents.
///
/// Matches Python's `util.compute_file_hash()`.
pub fn compute_file_hash(filename: &str) -> io::Result<String> {
    let path = Path::new(filename);
    let content = fs::read(path)?;
    let mut hasher = Sha1::new();
    hasher.update(&content);
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_filter(words: &[&str]) -> WordlistFilter {
        WordlistFilter::from_words(words, 3).unwrap()
    }

    // --- should_exclude_secret ---

    #[test]
    fn test_exclude_known_word() {
        let filter = make_filter(&["test", "example", "fake"]);
        assert!(filter.should_exclude_secret("AKIATEST12345"));
    }

    #[test]
    fn test_exclude_case_insensitive() {
        let filter = make_filter(&["test"]);
        assert!(filter.should_exclude_secret("TestKey12345"));
        assert!(filter.should_exclude_secret("TESTKEY12345"));
        assert!(filter.should_exclude_secret("testkey12345"));
    }

    #[test]
    fn test_no_exclude_unknown() {
        let filter = make_filter(&["test", "example", "fake"]);
        assert!(!filter.should_exclude_secret("AKIAIOSFODNN7REAL"));
    }

    #[test]
    fn test_exclude_substring_match() {
        let filter = make_filter(&["example"]);
        assert!(filter.should_exclude_secret("this_is_an_example_key"));
    }

    #[test]
    fn test_empty_wordlist() {
        let filter = make_filter(&[]);
        assert!(!filter.should_exclude_secret("anything"));
    }

    #[test]
    fn test_min_length_filter() {
        // Words shorter than min_length are excluded from the automaton
        let filter = WordlistFilter::from_words(&["ab", "test", "x"], 3).unwrap();
        // "ab" (len 2) and "x" (len 1) are too short, should not match
        assert!(!filter.should_exclude_secret("ab"));
        assert!(!filter.should_exclude_secret("x"));
        // "test" (len 4) is long enough
        assert!(filter.should_exclude_secret("test_key"));
    }

    #[test]
    fn test_multiple_words_match() {
        let filter = make_filter(&["test", "fake", "dummy"]);
        assert!(filter.should_exclude_secret("fake_api_key"));
        assert!(filter.should_exclude_secret("dummy_secret"));
    }

    // --- from_file ---

    #[test]
    fn test_from_file() {
        // Create a temporary wordlist file
        let dir = std::env::temp_dir();
        let path = dir.join("test_wordlist.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "test").unwrap();
            writeln!(f, "example").unwrap();
            writeln!(f, "ab").unwrap(); // too short (min_length=3)
            writeln!(f, "fake").unwrap();
        }

        let filter = WordlistFilter::from_file(path.to_str().unwrap(), 3).unwrap();
        assert!(filter.should_exclude_secret("test_key"));
        assert!(filter.should_exclude_secret("example_secret"));
        assert!(filter.should_exclude_secret("fake_api"));
        assert!(!filter.should_exclude_secret("ab")); // too short
        assert!(!filter.should_exclude_secret("real_secret"));

        assert!(!filter.file_hash.is_empty());
        assert_eq!(filter.min_length, 3);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_from_file_nonexistent() {
        let result = WordlistFilter::from_file("/nonexistent/wordlist.txt", 3);
        assert!(result.is_err());
    }

    // --- compute_file_hash ---

    #[test]
    fn test_compute_file_hash() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_hash_file.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            write!(f, "hello world").unwrap();
        }

        let hash = compute_file_hash(path.to_str().unwrap()).unwrap();
        // SHA1 of "hello world"
        assert_eq!(hash, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_compute_file_hash_nonexistent() {
        let result = compute_file_hash("/nonexistent/file.txt");
        assert!(result.is_err());
    }
}
