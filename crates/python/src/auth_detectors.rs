//! PyO3 wrappers for auth and token secret detectors.
//!
//! Exposes the following plugins to Python:
//! - `BasicAuthDetector`
//! - `DiscordBotTokenDetector`
//! - `GitHubTokenDetector`
//! - `GitLabTokenDetector`
//! - `JwtTokenDetector`
//! - `PrivateKeyDetector`

use engine::auth_detectors;
use engine::plugin::SecretDetector;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::potential_secret::PyPotentialSecret;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// BasicAuthDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "BasicAuthDetector")]
#[derive(Clone)]
pub struct PyBasicAuthDetector {
    inner: auth_detectors::BasicAuthDetector,
}

#[pymethods]
impl PyBasicAuthDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: auth_detectors::BasicAuthDetector::new(),
        }
    }

    #[getter]
    fn secret_type(&self) -> &str {
        self.inner.secret_type()
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        SecretDetector::analyze_string(&self.inner, input)
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PyPotentialSecret> {
        SecretDetector::analyze_line(&self.inner, filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_pydict(py, &SecretDetector::json(&self.inner))
    }
}

// ---------------------------------------------------------------------------
// DiscordBotTokenDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "DiscordBotTokenDetector")]
#[derive(Clone)]
pub struct PyDiscordBotTokenDetector {
    inner: auth_detectors::DiscordBotTokenDetector,
}

#[pymethods]
impl PyDiscordBotTokenDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: auth_detectors::DiscordBotTokenDetector::new(),
        }
    }

    #[getter]
    fn secret_type(&self) -> &str {
        self.inner.secret_type()
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        SecretDetector::analyze_string(&self.inner, input)
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PyPotentialSecret> {
        SecretDetector::analyze_line(&self.inner, filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_pydict(py, &SecretDetector::json(&self.inner))
    }
}

// ---------------------------------------------------------------------------
// GitHubTokenDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "GitHubTokenDetector")]
#[derive(Clone)]
pub struct PyGitHubTokenDetector {
    inner: auth_detectors::GitHubTokenDetector,
}

#[pymethods]
impl PyGitHubTokenDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: auth_detectors::GitHubTokenDetector::new(),
        }
    }

    #[getter]
    fn secret_type(&self) -> &str {
        self.inner.secret_type()
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        SecretDetector::analyze_string(&self.inner, input)
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PyPotentialSecret> {
        SecretDetector::analyze_line(&self.inner, filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_pydict(py, &SecretDetector::json(&self.inner))
    }
}

// ---------------------------------------------------------------------------
// GitLabTokenDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "GitLabTokenDetector")]
#[derive(Clone)]
pub struct PyGitLabTokenDetector {
    inner: auth_detectors::GitLabTokenDetector,
}

#[pymethods]
impl PyGitLabTokenDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: auth_detectors::GitLabTokenDetector::new(),
        }
    }

    #[getter]
    fn secret_type(&self) -> &str {
        self.inner.secret_type()
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        SecretDetector::analyze_string(&self.inner, input)
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PyPotentialSecret> {
        SecretDetector::analyze_line(&self.inner, filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_pydict(py, &SecretDetector::json(&self.inner))
    }
}

// ---------------------------------------------------------------------------
// JwtTokenDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "JwtTokenDetector")]
#[derive(Clone)]
pub struct PyJwtTokenDetector {
    inner: auth_detectors::JwtTokenDetector,
}

#[pymethods]
impl PyJwtTokenDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: auth_detectors::JwtTokenDetector::new(),
        }
    }

    #[getter]
    fn secret_type(&self) -> &str {
        self.inner.secret_type()
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        SecretDetector::analyze_string(&self.inner, input)
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PyPotentialSecret> {
        SecretDetector::analyze_line(&self.inner, filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_pydict(py, &SecretDetector::json(&self.inner))
    }

    /// Check if a JWT token is structurally valid (base64 + JSON).
    #[staticmethod]
    fn is_formally_valid(token: &str) -> bool {
        auth_detectors::JwtTokenDetector::is_formally_valid(token)
    }
}

// ---------------------------------------------------------------------------
// PrivateKeyDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "PrivateKeyDetector")]
#[derive(Clone)]
pub struct PyPrivateKeyDetector {
    inner: auth_detectors::PrivateKeyDetector,
}

#[pymethods]
impl PyPrivateKeyDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: auth_detectors::PrivateKeyDetector::new(),
        }
    }

    #[getter]
    fn secret_type(&self) -> &str {
        self.inner.secret_type()
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        SecretDetector::analyze_string(&self.inner, input)
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PyPotentialSecret> {
        SecretDetector::analyze_line(&self.inner, filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_pydict(py, &SecretDetector::json(&self.inner))
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Register auth/token detector classes on the Python module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBasicAuthDetector>()?;
    m.add_class::<PyDiscordBotTokenDetector>()?;
    m.add_class::<PyGitHubTokenDetector>()?;
    m.add_class::<PyGitLabTokenDetector>()?;
    m.add_class::<PyJwtTokenDetector>()?;
    m.add_class::<PyPrivateKeyDetector>()?;
    Ok(())
}
