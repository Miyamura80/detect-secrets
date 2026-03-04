//! PyO3 bindings for the Settings configuration system.
//!
//! Exposes `Settings` as a Python class and provides module-level functions
//! for `get_settings`, `configure_settings_from_baseline`, `default_settings`,
//! `transient_settings`, `cache_bust`, `get_plugins`, `all_plugin_class_names`.

use engine::settings;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::{Map, Value};

/// Python-visible wrapper around the Rust `Settings`.
///
/// Exposed as `detect_secrets_rs.Settings`.
#[pyclass(name = "Settings")]
#[derive(Clone)]
pub struct PySettings {
    inner: settings::Settings,
}

#[pymethods]
impl PySettings {
    #[new]
    fn new() -> Self {
        Self {
            inner: settings::Settings::new(),
        }
    }

    /// Reset to defaults (no plugins, default filters).
    fn clear(&mut self) {
        self.inner.clear();
    }

    /// Replace settings from another Settings object.
    fn set(&mut self, other: &PySettings) {
        self.inner.set(&other.inner);
    }

    /// Configure plugins from a list of dicts: `[{"name": "ClassName", ...params}]`.
    fn configure_plugins(&mut self, config: &Bound<'_, PyList>) -> PyResult<()> {
        let json_config = pylist_to_json_array(config)?;
        if let Value::Array(arr) = json_config {
            self.inner.configure_plugins(&arr);
        }
        Ok(())
    }

    /// Disable plugins by class name.
    fn disable_plugins(&mut self, plugin_names: Vec<String>) {
        let refs: Vec<&str> = plugin_names.iter().map(|s| s.as_str()).collect();
        self.inner.disable_plugins(&refs);
    }

    /// Configure filters from a list of dicts: `[{"path": "dotted.path", ...params}]`.
    fn configure_filters(&mut self, config: &Bound<'_, PyList>) -> PyResult<()> {
        let json_config = pylist_to_json_array(config)?;
        if let Value::Array(arr) = json_config {
            self.inner.configure_filters(&arr);
        }
        Ok(())
    }

    /// Disable filters by path.
    fn disable_filters(&mut self, filter_paths: Vec<String>) {
        let refs: Vec<&str> = filter_paths.iter().map(|s| s.as_str()).collect();
        self.inner.disable_filters(&refs);
    }

    /// Serialize to baseline JSON dict: `{"plugins_used": [...], "filters_used": [...]}`.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let json_value = self.inner.json();
        json_value_to_pydict(py, &json_value)
    }

    /// Number of active plugins.
    #[getter]
    fn plugin_count(&self) -> usize {
        self.inner.plugins.len()
    }

    /// Number of active filters.
    #[getter]
    fn filter_count(&self) -> usize {
        self.inner.filters.len()
    }

    /// Get dict of active plugins: `{class_name: {config...}}`.
    #[getter]
    fn plugins<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (name, config) in &self.inner.plugins {
            let config_dict = json_value_to_pydict(py, config)?;
            dict.set_item(name.as_str(), config_dict)?;
        }
        Ok(dict)
    }

    /// Get dict of active filters: `{path: {config...}}`.
    #[getter]
    fn filters<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (path, config) in &self.inner.filters {
            let config_dict = json_value_to_pydict(py, config)?;
            dict.set_item(path.as_str(), config_dict)?;
        }
        Ok(dict)
    }

    fn __repr__(&self) -> String {
        format!(
            "Settings(plugins={}, filters={})",
            self.inner.plugins.len(),
            self.inner.filters.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Get the global singleton settings.
#[pyfunction]
fn get_settings() -> PySettings {
    let settings = settings::get_settings();
    PySettings {
        inner: settings.clone(),
    }
}

/// Configure settings from a baseline dict.
#[pyfunction]
#[pyo3(signature = (baseline, filename=""))]
fn configure_settings_from_baseline(
    baseline: &Bound<'_, PyDict>,
    filename: &str,
) -> PyResult<PySettings> {
    let json_baseline = pydict_to_json_value(baseline)?;
    settings::configure_settings_from_baseline(&json_baseline, filename);
    Ok(get_settings())
}

/// Reset the global settings singleton to defaults.
#[pyfunction]
fn cache_bust() {
    settings::cache_bust();
}

/// Get all built-in plugin class names, sorted.
#[pyfunction]
fn all_plugin_class_names() -> Vec<&'static str> {
    settings::all_plugin_class_names()
}

// ---------------------------------------------------------------------------
// Global settings mutation helpers (for CLI)
// ---------------------------------------------------------------------------

/// Disable plugins by class name on the global singleton.
#[pyfunction]
fn global_disable_plugins(names: Vec<String>) {
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    settings::get_settings_mut().disable_plugins(&refs);
}

/// Disable filters by path on the global singleton.
#[pyfunction]
fn global_disable_filters(paths: Vec<String>) {
    let refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
    settings::get_settings_mut().disable_filters(&refs);
}

/// Set a filter config on the global singleton: `settings.filters[path] = config`.
#[pyfunction]
fn global_set_filter(path: String, config: &Bound<'_, PyDict>) -> PyResult<()> {
    let json_config = pydict_to_json_value(config)?;
    settings::get_settings_mut()
        .filters
        .insert(path, json_config);
    Ok(())
}

/// Set a plugin config float value on the global singleton.
/// e.g. `global_set_plugin_limit("Base64HighEntropyString", "limit", 4.5)`
#[pyfunction]
fn global_set_plugin_limit(class_name: &str, key: &str, value: f64) {
    let mut s = settings::get_settings_mut();
    if let Some(plugin_config) = s.plugins.get_mut(class_name) {
        if let Some(obj) = plugin_config.as_object_mut() {
            obj.insert(
                key.to_string(),
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
            );
        }
    }
}

/// Get list of active plugin class names from the global singleton.
#[pyfunction]
fn global_get_plugin_names() -> Vec<String> {
    settings::get_settings().plugins.keys().cloned().collect()
}

/// Initialize the global singleton with all built-in plugins enabled.
/// Equivalent to Python's `initialize_plugin_settings`.
#[pyfunction]
fn global_initialize_all_plugins() {
    let all_names = settings::all_plugin_class_names();
    let config: Vec<Value> = all_names
        .into_iter()
        .map(|name| serde_json::json!({ "name": name }))
        .collect();
    settings::get_settings_mut().configure_plugins(&config);
}

/// Clear all plugins from global settings (keeping filters).
#[pyfunction]
fn global_clear_plugins() {
    settings::get_settings_mut().plugins.clear();
}

/// Register all settings-related types and functions with the PyO3 module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySettings>()?;
    m.add_function(wrap_pyfunction!(get_settings, m)?)?;
    m.add_function(wrap_pyfunction!(configure_settings_from_baseline, m)?)?;
    m.add_function(wrap_pyfunction!(cache_bust, m)?)?;
    m.add_function(wrap_pyfunction!(all_plugin_class_names, m)?)?;
    m.add_function(wrap_pyfunction!(global_disable_plugins, m)?)?;
    m.add_function(wrap_pyfunction!(global_disable_filters, m)?)?;
    m.add_function(wrap_pyfunction!(global_set_filter, m)?)?;
    m.add_function(wrap_pyfunction!(global_set_plugin_limit, m)?)?;
    m.add_function(wrap_pyfunction!(global_get_plugin_names, m)?)?;
    m.add_function(wrap_pyfunction!(global_initialize_all_plugins, m)?)?;
    m.add_function(wrap_pyfunction!(global_clear_plugins, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON ↔ Python conversion helpers
// ---------------------------------------------------------------------------

/// Convert a serde_json `Value` to a Python dict (handles nested structures).
fn json_value_to_pydict<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if let Value::Object(map) = value {
        for (k, v) in map {
            let py_val = json_value_to_py(py, v)?;
            dict.set_item(k, py_val)?;
        }
    }
    Ok(dict)
}

/// Convert a serde_json `Value` to a Python object.
fn json_value_to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<PyObject> {
    match value {
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
            let list = PyList::empty(py);
            for item in arr {
                let py_item = json_value_to_py(py, item)?;
                list.append(py_item)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(_) => {
            let d = json_value_to_pydict(py, value)?;
            Ok(d.into_any().unbind())
        }
    }
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

/// Convert a Python list to a serde_json `Value::Array`.
fn pylist_to_json_array(list: &Bound<'_, PyList>) -> PyResult<Value> {
    let mut arr = Vec::new();
    for item in list.iter() {
        arr.push(py_to_json_value(&item)?);
    }
    Ok(Value::Array(arr))
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
    } else if let Ok(dict) = obj.downcast::<PyDict>() {
        pydict_to_json_value(dict)
    } else if let Ok(list) = obj.downcast::<PyList>() {
        pylist_to_json_array(list)
    } else {
        Ok(Value::String(obj.str()?.to_string()))
    }
}
