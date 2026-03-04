//! Engine crate – shared backend logic for the Tauri template app.
//!
//! This crate contains all real backend logic and OS integrations behind
//! traits. It does NOT depend on Tauri runtime types, so it can be used
//! by both the GUI wrapper and the headless CLI test harness.
//!
//! Also provides the core detect-secrets-rs functionality (pure Rust).

/// detect-secrets-rs version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the detect-secrets-rs version.
pub fn version() -> &'static str {
    VERSION
}

pub mod auth_detectors;
pub mod baseline;
pub mod cloud_detectors;
pub mod commands;
pub mod context;
pub mod doctor;
pub mod entropy;
pub mod filters;
pub mod high_entropy_strings;
pub mod keyword_detector;
pub mod platform;
pub mod plugin;
pub mod potential_secret;
pub mod probes;
pub mod saas_detectors;
pub mod scan;
pub mod scenario;
pub mod secrets_collection;
pub mod settings;
pub mod traits;
pub mod types;

// Re-exports for convenience
pub use commands::CommandRegistry;
pub use context::AppContext;
pub use types::{CommandResult, ErrorCode, ErrorInfo, Status};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_returns_package_version() {
        assert_eq!(version(), "0.1.0");
    }
}
