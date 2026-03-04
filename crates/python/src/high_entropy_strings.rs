//! PyO3 wrappers for the high-entropy string plugins.
//!
//! Exposes `Base64HighEntropyString` and `HexHighEntropyString` to Python,
//! matching the interface of `detect_secrets.plugins.high_entropy_strings`.

use engine::high_entropy_strings;
use engine::plugin::SecretDetector;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::potential_secret::PyPotentialSecret;

/// Base64 high-entropy string detector.
///
/// Detects quoted strings of base64 characters with Shannon entropy above
/// the configured threshold (default 4.5).
#[pyclass(name = "Base64HighEntropyString")]
#[derive(Clone)]
pub struct PyBase64HighEntropyString {
    inner: high_entropy_strings::Base64HighEntropyString,
}

#[pymethods]
impl PyBase64HighEntropyString {
    /// Create a new Base64HighEntropyString detector.
    ///
    /// Args:
    ///     limit: Entropy threshold (default 4.5). Strings with entropy above
    ///         this are flagged as potential secrets.
    #[new]
    #[pyo3(signature = (limit=4.5))]
    fn new(limit: f64) -> Self {
        Self {
            inner: high_entropy_strings::Base64HighEntropyString::new(limit),
        }
    }

    /// The secret type string.
    #[getter]
    fn secret_type(&self) -> &str {
        self.inner.secret_type()
    }

    /// The entropy threshold.
    #[getter]
    fn limit(&self) -> f64 {
        self.inner.limit()
    }

    /// Calculate Shannon entropy of a string using the Base64 charset.
    ///
    /// Matches Python's `Base64HighEntropyString.calculate_shannon_entropy(data)`.
    fn calculate_shannon_entropy(&self, data: &str) -> f64 {
        engine::entropy::calculate_shannon_entropy(data, engine::entropy::BASE64_CHARSET)
    }

    /// Analyze a string and return all matched secret values above the entropy threshold.
    fn analyze_string(&self, input: &str) -> Vec<String> {
        SecretDetector::analyze_string(&self.inner, input)
    }

    /// Analyze a line and return potential secrets.
    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PyPotentialSecret> {
        SecretDetector::analyze_line(&self.inner, filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    /// Serialize plugin configuration to a Python dict.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let value = SecretDetector::json(&self.inner);
        json_value_to_pydict(py, &value)
    }
}

/// Hex high-entropy string detector.
///
/// Detects quoted strings of hex characters with Shannon entropy above
/// the configured threshold (default 3.0). Applies numeric-only reduction
/// to reduce false positives from all-digit strings.
#[pyclass(name = "HexHighEntropyString")]
#[derive(Clone)]
pub struct PyHexHighEntropyString {
    inner: high_entropy_strings::HexHighEntropyString,
}

#[pymethods]
impl PyHexHighEntropyString {
    /// Create a new HexHighEntropyString detector.
    ///
    /// Args:
    ///     limit: Entropy threshold (default 3.0). Strings with entropy above
    ///         this are flagged as potential secrets.
    #[new]
    #[pyo3(signature = (limit=3.0))]
    fn new(limit: f64) -> Self {
        Self {
            inner: high_entropy_strings::HexHighEntropyString::new(limit),
        }
    }

    /// The secret type string.
    #[getter]
    fn secret_type(&self) -> &str {
        self.inner.secret_type()
    }

    /// The entropy threshold.
    #[getter]
    fn limit(&self) -> f64 {
        self.inner.limit()
    }

    /// Calculate Shannon entropy of a string using the Hex charset.
    ///
    /// Matches Python's `HexHighEntropyString.calculate_shannon_entropy(data)`.
    fn calculate_shannon_entropy(&self, data: &str) -> f64 {
        engine::entropy::calculate_shannon_entropy(data, engine::entropy::HEX_CHARSET)
    }

    /// Analyze a string and return all matched secret values above the entropy threshold.
    fn analyze_string(&self, input: &str) -> Vec<String> {
        SecretDetector::analyze_string(&self.inner, input)
    }

    /// Analyze a line and return potential secrets.
    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PyPotentialSecret> {
        SecretDetector::analyze_line(&self.inner, filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    /// Serialize plugin configuration to a Python dict.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let value = SecretDetector::json(&self.inner);
        json_value_to_pydict(py, &value)
    }
}

/// Convert a serde_json `Value` (expected to be an Object) to a Python dict.
fn json_value_to_pydict<'py>(
    py: Python<'py>,
    value: &serde_json::Value,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if let serde_json::Value::Object(map) = value {
        for (k, v) in map {
            match v {
                serde_json::Value::Null => dict.set_item(k, py.None())?,
                serde_json::Value::Bool(b) => dict.set_item(k, *b)?,
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        dict.set_item(k, i)?;
                    } else if let Some(f) = n.as_f64() {
                        dict.set_item(k, f)?;
                    }
                }
                serde_json::Value::String(s) => dict.set_item(k, s.as_str())?,
                _ => dict.set_item(k, format!("{v}"))?,
            }
        }
    }
    Ok(dict)
}

/// Register high-entropy string plugin classes on the Python module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBase64HighEntropyString>()?;
    m.add_class::<PyHexHighEntropyString>()?;
    Ok(())
}
