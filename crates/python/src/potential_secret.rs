use engine::potential_secret::{hash_secret, PotentialSecret};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::{Map, Value};

/// Python-visible wrapper around the Rust `PotentialSecret`.
///
/// Exposed as `detect_secrets_rs.PotentialSecret` and mirrors the interface
/// of `detect_secrets.core.potential_secret.PotentialSecret`.
#[pyclass(name = "PotentialSecret")]
#[derive(Clone)]
pub struct PyPotentialSecret {
    inner: PotentialSecret,
}

#[pymethods]
impl PyPotentialSecret {
    /// Create a new PotentialSecret, hashing the plaintext secret.
    #[new]
    #[pyo3(signature = (secret_type, filename, secret, line_number=0, is_secret=None, is_verified=false))]
    fn new(
        secret_type: String,
        filename: String,
        secret: String,
        line_number: u64,
        is_secret: Option<bool>,
        is_verified: bool,
    ) -> Self {
        Self {
            inner: PotentialSecret::new(
                secret_type,
                filename,
                &secret,
                line_number,
                is_secret,
                is_verified,
            ),
        }
    }

    /// The type of secret (e.g. "High Entropy String").
    #[getter]
    fn secret_type(&self) -> &str {
        &self.inner.secret_type
    }

    /// Alias matching Python's `type` attribute.
    #[getter(r#type)]
    fn type_(&self) -> &str {
        &self.inner.secret_type
    }

    /// The filename where the secret was found.
    #[getter]
    fn filename(&self) -> &str {
        &self.inner.filename
    }

    /// SHA-1 hex digest of the plaintext secret.
    #[getter]
    fn secret_hash(&self) -> &str {
        &self.inner.secret_hash
    }

    /// Line number in the file.
    #[getter]
    fn line_number(&self) -> u64 {
        self.inner.line_number
    }

    #[setter]
    fn set_line_number(&mut self, value: u64) {
        self.inner.line_number = value;
    }

    /// Whether this is a confirmed secret (True), false positive (False), or unknown (None).
    #[getter]
    fn is_secret(&self) -> Option<bool> {
        self.inner.is_secret
    }

    #[setter]
    fn set_is_secret(&mut self, value: Option<bool>) {
        self.inner.is_secret = value;
    }

    /// Whether the secret has been externally verified.
    #[getter]
    fn is_verified(&self) -> bool {
        self.inner.is_verified
    }

    #[setter]
    fn set_is_verified(&mut self, value: bool) {
        self.inner.is_verified = value;
    }

    /// The plaintext secret value (in-memory only, never serialized).
    #[getter]
    fn secret_value(&self) -> Option<&str> {
        self.inner.secret_value.as_deref()
    }

    /// Update the secret value and recompute the hash.
    fn set_secret(&mut self, secret: &str) {
        self.inner.secret_hash = hash_secret(secret);
        self.inner.secret_value = Some(secret.to_string());
    }

    /// Compute SHA-1 hex digest of a secret string.
    #[staticmethod]
    fn hash_secret(secret: &str) -> String {
        hash_secret(secret)
    }

    /// Serialize to a Python dict matching the baseline JSON format.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let json_value = self.inner.to_json();
        json_value_to_pydict(py, &json_value)
    }

    /// Deserialize from a Python dict (baseline format).
    #[staticmethod]
    fn load_secret_from_dict(data: &Bound<'_, PyDict>) -> PyResult<Self> {
        let json_value = pydict_to_json_value(data)?;
        let inner = PotentialSecret::load_from_dict(&json_value)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        Ok(Self { inner })
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.inner.hash(&mut hasher);
        hasher.finish()
    }

    fn __str__(&self) -> String {
        format!(
            "Secret Type: {}\nLocation:    {}:{}",
            self.inner.secret_type, self.inner.filename, self.inner.line_number
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "PotentialSecret(type={:?}, filename={:?}, line_number={})",
            self.inner.secret_type, self.inner.filename, self.inner.line_number
        )
    }
}

impl PyPotentialSecret {
    /// Create a `PyPotentialSecret` from an engine-level `PotentialSecret`.
    pub fn from_inner(inner: PotentialSecret) -> Self {
        Self { inner }
    }

    /// Borrow the underlying engine-level `PotentialSecret`.
    pub fn inner(&self) -> &PotentialSecret {
        &self.inner
    }
}

/// Convert a serde_json `Value` (expected to be an Object) to a Python dict.
fn json_value_to_pydict<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if let Value::Object(map) = value {
        for (k, v) in map {
            match v {
                Value::Null => dict.set_item(k, py.None())?,
                Value::Bool(b) => dict.set_item(k, *b)?,
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        dict.set_item(k, i)?;
                    } else if let Some(f) = n.as_f64() {
                        dict.set_item(k, f)?;
                    }
                }
                Value::String(s) => dict.set_item(k, s.as_str())?,
                _ => dict.set_item(k, format!("{v}"))?,
            }
        }
    }
    Ok(dict)
}

/// Convert a Python dict to a serde_json `Value::Object`.
fn pydict_to_json_value(dict: &Bound<'_, PyDict>) -> PyResult<Value> {
    let mut map = Map::new();
    for (key, val) in dict.iter() {
        let k: String = key.extract()?;
        let v = py_to_json_value(&val)?;
        map.insert(k, v);
    }
    Ok(Value::Object(map))
}

/// Convert a single Python object to a serde_json `Value`.
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
    } else {
        Ok(Value::String(obj.str()?.to_string()))
    }
}
