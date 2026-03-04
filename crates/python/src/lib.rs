use pyo3::prelude::*;

mod auth_detectors;
mod baseline;
mod cloud_detectors;
mod custom_plugins;
mod entropy;
mod filters;
mod high_entropy_strings;
mod keyword_detector;
mod plugin;
mod potential_secret;
mod saas_detectors;
mod scan;
mod secrets_collection;
mod settings;

/// Returns the detect-secrets-rs version string.
#[pyfunction]
fn version() -> &'static str {
    engine::version()
}

/// Compute SHA-1 hex digest of a secret string.
#[pyfunction]
fn hash_secret(secret: &str) -> String {
    engine::potential_secret::hash_secret(secret)
}

/// detect_secrets_rs – Rust-backed drop-in replacement for Yelp/detect-secrets.
#[pymodule]
fn detect_secrets_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(hash_secret, m)?)?;
    m.add_class::<potential_secret::PyPotentialSecret>()?;
    entropy::register(m)?;
    plugin::register(m)?;
    custom_plugins::register(m)?;
    high_entropy_strings::register(m)?;
    cloud_detectors::register(m)?;
    auth_detectors::register(m)?;
    saas_detectors::register(m)?;
    keyword_detector::register(m)?;
    filters::register(m)?;
    scan::register(m)?;
    secrets_collection::register(m)?;
    settings::register(m)?;
    baseline::register(m)?;
    Ok(())
}
