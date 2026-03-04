//! PyO3 bindings for the SecretsCollection.
//!
//! Exposes `SecretsCollection` as a Python class with `scan_file`, `merge`,
//! `trim`, `json`, `load_from_baseline`, and comparison operators.

use engine::secrets_collection::SecretsCollection;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};
use serde_json::{Map, Value};

use crate::potential_secret::PyPotentialSecret;

/// Python-visible wrapper around the Rust `SecretsCollection`.
///
/// Exposed as `detect_secrets_rs.SecretsCollection`.
#[pyclass(name = "SecretsCollection")]
#[derive(Clone)]
pub struct PySecretsCollection {
    inner: SecretsCollection,
}

#[pymethods]
impl PySecretsCollection {
    #[new]
    #[pyo3(signature = (root="".to_string()))]
    fn new(root: String) -> Self {
        Self {
            inner: SecretsCollection::with_root(root),
        }
    }

    /// The root directory for relative path resolution.
    #[getter]
    fn root(&self) -> &str {
        &self.inner.root
    }

    /// Returns the set of filenames that have entries.
    #[getter]
    fn files(&self) -> Vec<String> {
        let mut files: Vec<String> = self.inner.data.keys().cloned().collect();
        files.sort();
        files
    }

    /// Load a SecretsCollection from a baseline dict.
    #[staticmethod]
    fn load_from_baseline(baseline: &Bound<'_, PyDict>) -> PyResult<Self> {
        let json_val = pydict_to_json_value(baseline)?;
        let inner = SecretsCollection::load_from_baseline(&json_val)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        Ok(Self { inner })
    }

    /// Get secrets for a filename. Returns a list of PotentialSecret.
    fn __getitem__(&self, filename: &str) -> Vec<PyPotentialSecret> {
        match self.inner.get(filename) {
            Some(secrets) => secrets
                .iter()
                .map(|s| PyPotentialSecret::from_inner(s.clone()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Set secrets for a filename from a list of PotentialSecret.
    fn __setitem__(&mut self, filename: String, secrets: Vec<PyPotentialSecret>) {
        let set = secrets.into_iter().map(|ps| ps.inner().clone()).collect();
        self.inner.data.insert(filename, set);
    }

    /// Add a single secret to the collection.
    fn add_secret(&mut self, secret: &PyPotentialSecret) {
        self.inner.add_secret(secret.inner().clone());
    }

    /// Scan a single file for secrets and add results to the collection.
    fn scan_file(&mut self, filename: &str) {
        let secrets = engine::scan::scan_file(filename);
        let set = self.inner.data.entry(filename.to_string()).or_default();
        for secret in secrets {
            set.insert(secret);
        }
    }

    /// Scan multiple files in parallel and store results.
    ///
    /// Uses rayon thread pool for parallel scanning — no GIL contention
    /// during Rust-side scanning.
    ///
    /// Args:
    ///     filenames: List of file paths to scan.
    ///     num_threads: Thread pool size (default: num_cpus).
    #[pyo3(signature = (filenames, num_threads=None))]
    fn scan_files(&mut self, py: Python<'_>, filenames: Vec<String>, num_threads: Option<usize>) {
        // Release GIL during Rust-side parallel scanning
        let results = py.allow_threads(|| engine::scan::scan_files(&filenames, num_threads));

        for (filename, secrets) in results {
            let set = self.inner.data.entry(filename).or_default();
            for secret in secrets {
                set.insert(secret);
            }
        }
    }

    /// Merge old baseline results, preserving audit/verification metadata.
    fn merge(&mut self, old_results: &PySecretsCollection) {
        self.inner.merge(&old_results.inner);
    }

    /// Trim the collection against fresh scan results.
    #[pyo3(signature = (scanned_results=None, filelist=None))]
    fn trim(
        &mut self,
        scanned_results: Option<&PySecretsCollection>,
        filelist: Option<Vec<String>>,
    ) {
        self.inner
            .trim(scanned_results.map(|sr| &sr.inner), filelist.as_deref());
    }

    /// Serialize to a Python dict matching the results JSON format.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let json_val = self.inner.json();
        json_value_to_pydict_nested(py, &json_val)
    }

    /// Iterate over (filename, PotentialSecret) tuples in sorted order.
    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let items: Vec<Bound<'py, PyTuple>> = self
            .inner
            .iter()
            .map(|(filename, secret)| {
                let py_secret = PyPotentialSecret::from_inner(secret.clone());
                PyTuple::new(
                    py,
                    &[
                        filename.into_pyobject(py).unwrap().into_any(),
                        py_secret.into_pyobject(py).unwrap().into_any(),
                    ],
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        PyList::new(py, items)
    }

    /// Total number of secrets across all files.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// True if collection has any secrets.
    fn __bool__(&self) -> bool {
        !self.inner.is_empty()
    }

    /// Loose equality (same files, same secret identities).
    fn __eq__(&self, other: &PySecretsCollection) -> bool {
        self.inner == other.inner
    }

    /// Set subtraction: self - other.
    fn __sub__(&self, other: &PySecretsCollection) -> PySecretsCollection {
        PySecretsCollection {
            inner: self.inner.subtract(&other.inner),
        }
    }

    /// Strict equality (also compares line_number, is_secret, is_verified).
    fn exactly_equals(&self, other: &PySecretsCollection) -> bool {
        self.inner.eq_strict(&other.inner)
    }

    /// Support `copy.copy()`.
    fn __copy__(&self) -> Self {
        self.clone()
    }

    /// Support `copy.deepcopy()`.
    fn __deepcopy__(&self, _memo: &Bound<'_, PyDict>) -> Self {
        self.clone()
    }
}

impl PySecretsCollection {
    /// Create from an engine-level SecretsCollection.
    pub fn from_inner(inner: SecretsCollection) -> Self {
        Self { inner }
    }

    /// Borrow the underlying engine-level SecretsCollection.
    pub fn inner(&self) -> &SecretsCollection {
        &self.inner
    }
}

/// Register the SecretsCollection class with the module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySecretsCollection>()?;
    Ok(())
}

// --- JSON <-> Python conversion helpers ---

/// Convert a serde_json Value to a nested Python dict (handles arrays and nested objects).
fn json_value_to_pydict_nested<'py>(
    py: Python<'py>,
    value: &Value,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if let Value::Object(map) = value {
        for (k, v) in map {
            let py_val = json_value_to_py(py, v)?;
            dict.set_item(k, py_val)?;
        }
    }
    Ok(dict)
}

/// Convert a serde_json Value to a Python object.
fn json_value_to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any())
            } else {
                Ok(py.None().into_bound(py))
            }
        }
        Value::String(s) => Ok(s.into_pyobject(py)?.into_any()),
        Value::Array(arr) => {
            let items: Vec<Bound<'py, PyAny>> = arr
                .iter()
                .map(|v| json_value_to_py(py, v))
                .collect::<PyResult<_>>()?;
            let list = PyList::new(py, items)?;
            Ok(list.into_any())
        }
        Value::Object(_) => {
            let dict = json_value_to_pydict_nested(py, value)?;
            Ok(dict.into_any())
        }
    }
}

/// Convert a Python dict to a serde_json Value.
fn pydict_to_json_value(dict: &Bound<'_, PyDict>) -> PyResult<Value> {
    let mut map = Map::new();
    for (key, val) in dict.iter() {
        let k: String = key.extract()?;
        let v = py_to_json_value(&val)?;
        map.insert(k, v);
    }
    Ok(Value::Object(map))
}

/// Convert a Python object to a serde_json Value.
fn py_to_json_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        Ok(Value::Null)
    } else if let Ok(b) = obj.extract::<bool>() {
        Ok(Value::Bool(b))
    } else if let Ok(i) = obj.extract::<i64>() {
        Ok(Value::Number(i.into()))
    } else if let Ok(f) = obj.extract::<f64>() {
        Ok(serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null))
    } else if let Ok(s) = obj.extract::<String>() {
        Ok(Value::String(s))
    } else if let Ok(dict) = obj.downcast::<PyDict>() {
        pydict_to_json_value(dict)
    } else if let Ok(list) = obj.downcast::<PyList>() {
        let arr: Vec<Value> = list
            .iter()
            .map(|item| py_to_json_value(&item))
            .collect::<PyResult<_>>()?;
        Ok(Value::Array(arr))
    } else {
        Ok(Value::String(obj.str()?.to_string()))
    }
}
