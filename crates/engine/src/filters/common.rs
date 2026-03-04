//! Common file validation filters.
//!
//! Ported from detect_secrets/filters/common.py

use std::path::Path;

/// Check if a file path points to a valid, existing file.
///
/// Matches Python's `is_invalid_file()`.
pub fn is_invalid_file(filename: &str) -> bool {
    let path = Path::new(filename);
    !path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_file_nonexistent() {
        assert!(is_invalid_file("/nonexistent/path/to/file.txt"));
    }

    #[test]
    fn test_invalid_file_directory() {
        assert!(is_invalid_file("/tmp"));
    }

    #[test]
    fn test_valid_file_exists() {
        // Cargo.toml should exist at the workspace root
        assert!(!is_invalid_file(&format!(
            "{}/Cargo.toml",
            env!("CARGO_MANIFEST_DIR")
        )));
    }
}
