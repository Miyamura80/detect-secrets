//! PyO3 bindings for the baseline management module.
//!
//! Exposes `baseline_create`, `baseline_load`, `baseline_load_from_file`,
//! `baseline_format_for_output`, `baseline_save_to_file`, `baseline_upgrade`,
//! and the `BASELINE_VERSION` constant to Python.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::Value;

use crate::secrets_collection::PySecretsCollection;

// ---------------------------------------------------------------------------
// JSON ↔ Python helpers
// ---------------------------------------------------------------------------

/// Convert a Python dict to a serde_json Value.
fn pydict_to_json_value(dict: &Bound<'_, PyDict>) -> PyResult<Value> {
    let json_str = dict
        .py()
        .import("json")?
        .call_method1("dumps", (dict,))?
        .extract::<String>()?;
    serde_json::from_str(&json_str)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("JSON error: {e}")))
}

/// Convert a serde_json Value to a Python object.
fn json_value_to_py(py: Python<'_>, val: &Value) -> PyResult<PyObject> {
    match val {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any().unbind()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(py.None())
            }
        }
        Value::String(s) => Ok(s.into_pyobject(py)?.into_any().unbind()),
        Value::Array(arr) => {
            let py_list = pyo3::types::PyList::empty(py);
            for item in arr {
                py_list.append(json_value_to_py(py, item)?)?;
            }
            Ok(py_list.into_any().unbind())
        }
        Value::Object(map) => {
            let py_dict = PyDict::new(py);
            for (k, v) in map {
                py_dict.set_item(k, json_value_to_py(py, v)?)?;
            }
            Ok(py_dict.into_any().unbind())
        }
    }
}

// ---------------------------------------------------------------------------
// Exposed functions
// ---------------------------------------------------------------------------

/// Create a new baseline by scanning files.
///
/// Args:
///     paths: List of file/directory paths to scan.
///     should_scan_all_files: If True, include all files (not just git-tracked).
///     root: Root directory for scanning.
///
/// Returns:
///     SecretsCollection with detected secrets.
#[pyfunction]
#[pyo3(signature = (paths=None, should_scan_all_files=false, root=""))]
fn baseline_create(
    paths: Option<Vec<String>>,
    should_scan_all_files: bool,
    root: &str,
) -> PyResult<PySecretsCollection> {
    let paths = paths.unwrap_or_default();
    let inner = engine::baseline::create(&paths, should_scan_all_files, root);
    Ok(PySecretsCollection::from_inner(inner))
}

/// Load a baseline dict, configure settings, and return its secrets.
///
/// Args:
///     baseline: Dict with version, plugins_used, filters_used, results.
///     filename: Optional baseline filename (for is_baseline_file filter).
///
/// Returns:
///     SecretsCollection loaded from the baseline.
#[pyfunction]
#[pyo3(signature = (baseline, filename=""))]
fn baseline_load(baseline: &Bound<'_, PyDict>, filename: &str) -> PyResult<PySecretsCollection> {
    let json_val = pydict_to_json_value(baseline)?;
    let inner = engine::baseline::load(&json_val, filename)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(PySecretsCollection::from_inner(inner))
}

/// Read and parse a baseline JSON file from disk.
///
/// Returns:
///     Dict with the parsed baseline contents.
#[pyfunction]
fn baseline_load_from_file(py: Python<'_>, filename: &str) -> PyResult<PyObject> {
    let json_val = engine::baseline::load_from_file(filename)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    json_value_to_py(py, &json_val)
}

/// Format a SecretsCollection for baseline output.
///
/// Returns:
///     Dict with version, plugins_used, filters_used, results, and optionally generated_at.
#[pyfunction]
#[pyo3(signature = (secrets, is_slim_mode=false))]
fn baseline_format_for_output(
    py: Python<'_>,
    secrets: &PySecretsCollection,
    is_slim_mode: bool,
) -> PyResult<PyObject> {
    let json_val = engine::baseline::format_for_output(secrets.inner(), is_slim_mode);
    json_value_to_py(py, &json_val)
}

/// Save a baseline dict to a JSON file with 2-space indent.
///
/// Args:
///     output: Dict to save (already formatted via format_for_output).
///     filename: Output file path.
#[pyfunction]
fn baseline_save_to_file(output: &Bound<'_, PyDict>, filename: &str) -> PyResult<()> {
    let json_val = pydict_to_json_value(output)?;
    engine::baseline::save_to_file(&json_val, filename)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))
}

/// Upgrade a baseline dict to the current format version.
///
/// Returns:
///     Upgraded baseline dict.
#[pyfunction]
fn baseline_upgrade(py: Python<'_>, baseline: &Bound<'_, PyDict>) -> PyResult<PyObject> {
    let json_val = pydict_to_json_value(baseline)?;
    let upgraded = engine::baseline::upgrade(&json_val);
    json_value_to_py(py, &upgraded)
}

/// Get the baseline format version string.
#[pyfunction]
fn baseline_version() -> &'static str {
    engine::baseline::BASELINE_VERSION
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Register baseline functions on the module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(baseline_create, m)?)?;
    m.add_function(wrap_pyfunction!(baseline_load, m)?)?;
    m.add_function(wrap_pyfunction!(baseline_load_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(baseline_format_for_output, m)?)?;
    m.add_function(wrap_pyfunction!(baseline_save_to_file, m)?)?;
    m.add_function(wrap_pyfunction!(baseline_upgrade, m)?)?;
    m.add_function(wrap_pyfunction!(baseline_version, m)?)?;
    Ok(())
}
