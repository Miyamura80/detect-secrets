//! PyO3 wrappers for cloud and infrastructure secret detectors.
//!
//! Exposes the following plugins to Python:
//! - `AWSKeyDetector`
//! - `AzureStorageKeyDetector`
//! - `ArtifactoryDetector`
//! - `CloudantDetector`
//! - `IbmCloudIamDetector`
//! - `IbmCosHmacDetector`
//! - `SoftlayerDetector`

use engine::cloud_detectors;
use engine::plugin::SecretDetector;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::potential_secret::PyPotentialSecret;

// ---------------------------------------------------------------------------
// Helper (same as in high_entropy_strings.rs)
// ---------------------------------------------------------------------------

/// Convert a serde_json `Value` (expected Object) to a Python dict.
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
// AWSKeyDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "AWSKeyDetector")]
#[derive(Clone)]
pub struct PyAWSKeyDetector {
    inner: cloud_detectors::AWSKeyDetector,
}

#[pymethods]
impl PyAWSKeyDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: cloud_detectors::AWSKeyDetector::new(),
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
// AzureStorageKeyDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "AzureStorageKeyDetector")]
#[derive(Clone)]
pub struct PyAzureStorageKeyDetector {
    inner: cloud_detectors::AzureStorageKeyDetector,
}

#[pymethods]
impl PyAzureStorageKeyDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: cloud_detectors::AzureStorageKeyDetector::new(),
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
// ArtifactoryDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "ArtifactoryDetector")]
#[derive(Clone)]
pub struct PyArtifactoryDetector {
    inner: cloud_detectors::ArtifactoryDetector,
}

#[pymethods]
impl PyArtifactoryDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: cloud_detectors::ArtifactoryDetector::new(),
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
// CloudantDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "CloudantDetector")]
#[derive(Clone)]
pub struct PyCloudantDetector {
    inner: cloud_detectors::CloudantDetector,
}

#[pymethods]
impl PyCloudantDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: cloud_detectors::CloudantDetector::new(),
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
// IbmCloudIamDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "IbmCloudIamDetector")]
#[derive(Clone)]
pub struct PyIbmCloudIamDetector {
    inner: cloud_detectors::IbmCloudIamDetector,
}

#[pymethods]
impl PyIbmCloudIamDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: cloud_detectors::IbmCloudIamDetector::new(),
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
// IbmCosHmacDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "IbmCosHmacDetector")]
#[derive(Clone)]
pub struct PyIbmCosHmacDetector {
    inner: cloud_detectors::IbmCosHmacDetector,
}

#[pymethods]
impl PyIbmCosHmacDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: cloud_detectors::IbmCosHmacDetector::new(),
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
// SoftlayerDetector
// ---------------------------------------------------------------------------

#[pyclass(name = "SoftlayerDetector")]
#[derive(Clone)]
pub struct PySoftlayerDetector {
    inner: cloud_detectors::SoftlayerDetector,
}

#[pymethods]
impl PySoftlayerDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: cloud_detectors::SoftlayerDetector::new(),
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

/// Register cloud detector classes on the Python module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyAWSKeyDetector>()?;
    m.add_class::<PyAzureStorageKeyDetector>()?;
    m.add_class::<PyArtifactoryDetector>()?;
    m.add_class::<PyCloudantDetector>()?;
    m.add_class::<PyIbmCloudIamDetector>()?;
    m.add_class::<PyIbmCosHmacDetector>()?;
    m.add_class::<PySoftlayerDetector>()?;
    Ok(())
}
