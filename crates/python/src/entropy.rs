//! PyO3 bindings for Shannon entropy calculation.

use pyo3::prelude::*;

/// Calculate Shannon entropy of `data` over the given `charset`.
///
/// Produces identical results to Python's
/// `HighEntropyStringsPlugin.calculate_shannon_entropy()`.
#[pyfunction]
pub fn calculate_shannon_entropy(data: &str, charset: &str) -> f64 {
    engine::entropy::calculate_shannon_entropy(data, charset)
}

/// Calculate Shannon entropy for hex strings with numeric-only reduction.
///
/// Matches Python's `HexHighEntropyString.calculate_shannon_entropy()`.
#[pyfunction]
pub fn calculate_hex_shannon_entropy(data: &str) -> f64 {
    engine::entropy::calculate_hex_shannon_entropy(data)
}

/// Register entropy functions and constants on the parent module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(calculate_shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_hex_shannon_entropy, m)?)?;
    m.add("BASE64_CHARSET", engine::entropy::BASE64_CHARSET)?;
    m.add("HEX_CHARSET", engine::entropy::HEX_CHARSET)?;
    Ok(())
}
