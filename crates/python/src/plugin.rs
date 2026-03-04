//! PyO3 wrappers for the plugin framework.
//!
//! Exposes the plugin traits and helper functions to Python, including:
//! - `VerifiedResult` enum
//! - `build_assignment_regex` function
//! - `PyRegexBasedDetector` base class that Python can use to test the framework

use engine::plugin::{
    build_assignment_regex, regex_analyze_string, RegexBasedDetector, SecretDetector,
    VerifiedResult,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;

use crate::potential_secret::PyPotentialSecret;

/// Python wrapper for [`VerifiedResult`].
#[pyclass(name = "VerifiedResult", eq, eq_int)]
#[derive(Clone, PartialEq, Eq)]
pub enum PyVerifiedResult {
    VerifiedFalse = 1,
    Unverified = 2,
    VerifiedTrue = 3,
}

impl From<VerifiedResult> for PyVerifiedResult {
    fn from(v: VerifiedResult) -> Self {
        match v {
            VerifiedResult::VerifiedFalse => PyVerifiedResult::VerifiedFalse,
            VerifiedResult::Unverified => PyVerifiedResult::Unverified,
            VerifiedResult::VerifiedTrue => PyVerifiedResult::VerifiedTrue,
        }
    }
}

/// A concrete regex-based detector exposed to Python for testing the framework.
///
/// Create with a `secret_type` and a list of regex pattern strings.
#[pyclass(name = "RegexBasedDetector")]
#[derive(Clone)]
pub struct PyRegexBasedDetector {
    type_name: String,
    patterns: Vec<Regex>,
}

#[pymethods]
impl PyRegexBasedDetector {
    #[new]
    fn new(secret_type: String, patterns: Vec<String>) -> PyResult<Self> {
        let compiled: Result<Vec<Regex>, _> = patterns.iter().map(|p| Regex::new(p)).collect();
        let compiled =
            compiled.map_err(|e| PyValueError::new_err(format!("invalid regex: {e}")))?;
        Ok(Self {
            type_name: secret_type,
            patterns: compiled,
        })
    }

    /// The secret type string.
    #[getter]
    fn secret_type(&self) -> &str {
        &self.type_name
    }

    /// Analyze a string and return all matched secret values.
    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }

    /// Analyze a line and return potential secrets.
    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PyPotentialSecret> {
        SecretDetector::analyze_line(self, filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    /// Verify a secret (always returns Unverified for test detector).
    fn verify(&self, secret: &str) -> PyVerifiedResult {
        SecretDetector::verify(self, secret).into()
    }
}

impl SecretDetector for PyRegexBasedDetector {
    fn secret_type(&self) -> &str {
        &self.type_name
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        regex_analyze_string(self, input)
    }
}

impl RegexBasedDetector for PyRegexBasedDetector {
    fn denylist(&self) -> &[Regex] {
        &self.patterns
    }
}

/// Build an assignment regex from prefix, keyword, and secret pattern components.
///
/// Returns the compiled regex pattern string, or raises ValueError on failure.
#[pyfunction]
#[pyo3(name = "build_assignment_regex")]
fn py_build_assignment_regex(
    prefix_regex: &str,
    secret_keyword_regex: &str,
    secret_regex: &str,
) -> PyResult<String> {
    let regex = build_assignment_regex(prefix_regex, secret_keyword_regex, secret_regex)
        .ok_or_else(|| PyValueError::new_err("failed to compile assignment regex"))?;
    Ok(regex.as_str().to_string())
}

/// Register plugin-related classes and functions into the Python module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyVerifiedResult>()?;
    m.add_class::<PyRegexBasedDetector>()?;
    m.add_function(wrap_pyfunction!(py_build_assignment_regex, m)?)?;
    Ok(())
}
