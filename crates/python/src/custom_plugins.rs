//! PyO3 bindings for custom Python plugin and filter loading.
//!
//! Supports:
//! - Loading custom Python plugins from file paths (`file://path/to/plugin.py`)
//! - Loading custom Python plugins from import paths (`my_module.MyPlugin`)
//! - Loading custom Python filters from file paths (`file://path/to/filters.py::func_name`)
//! - Loading custom Python filters from import paths (`my.module.func_name`)
//! - `get_mapping_from_secret_type_to_class()` returning both Rust and Python plugins

use std::sync::Arc;

use engine::plugin::SecretDetector;
use engine::potential_secret::PotentialSecret;
use engine::scan::{ExternalFilter, FilterPhase};
use engine::settings;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::Value;

// ---------------------------------------------------------------------------
// PyCustomPlugin — adapter wrapping a Python plugin object
// ---------------------------------------------------------------------------

/// Adapter that wraps a Python plugin class instance and implements
/// [`SecretDetector`].
///
/// The Python object must have:
/// - `secret_type` — property or attribute returning a `str`
/// - `analyze_string(input: str) -> Iterable[str]` — method
///
/// The `secret_type` is cached at construction time to avoid GIL acquisition
/// on the hot path.
struct PyCustomPlugin {
    /// Python plugin instance (e.g. `MyPlugin()`).
    py_obj: PyObject,
    /// Cached `secret_type` string — avoids GIL for this common accessor.
    cached_secret_type: String,
    /// Python class name (used for JSON serialization).
    class_name: String,
}

impl PyCustomPlugin {
    /// Construct a new adapter by instantiating `py_class` with `config` kwargs.
    fn new(py: Python<'_>, py_class: &PyObject, config: &Value) -> PyResult<Self> {
        let class_name: String = py_class.getattr(py, "__name__")?.extract(py)?;

        // Build keyword args from config, skipping "name" and "path"
        let kwargs = PyDict::new(py);
        if let Value::Object(map) = config {
            for (k, v) in map {
                if k == "name" || k == "path" {
                    continue;
                }
                let py_val = json_value_to_py_simple(py, v);
                kwargs.set_item(k, py_val)?;
            }
        }

        let py_obj = if kwargs.is_empty() {
            py_class.call0(py)?
        } else {
            py_class.call(py, (), Some(&kwargs))?
        };

        let cached_secret_type: String = py_obj.getattr(py, "secret_type")?.extract(py)?;

        Ok(Self {
            py_obj,
            cached_secret_type,
            class_name,
        })
    }
}

impl SecretDetector for PyCustomPlugin {
    fn secret_type(&self) -> &str {
        &self.cached_secret_type
    }

    fn analyze_string(&self, input: &str) -> Vec<String> {
        Python::with_gil(|py| {
            match self.py_obj.call_method1(py, "analyze_string", (input,)) {
                Ok(result) => {
                    // The Python method returns a generator/iterable of strings.
                    // Use PyAny::iter() to handle both lists and generators.
                    let bound = result.bind(py);
                    match bound.try_iter() {
                        Ok(iter) => iter
                            .filter_map(|item| item.ok().and_then(|i| i.extract::<String>().ok()))
                            .collect(),
                        Err(_) => vec![],
                    }
                }
                Err(_) => vec![],
            }
        })
    }

    fn analyze_line(&self, filename: &str, line: &str, line_number: u64) -> Vec<PotentialSecret> {
        // Try calling the Python plugin's analyze_line directly — it may have
        // custom per-line logic (e.g. KeywordDetector).  Fall back to the
        // default SecretDetector implementation if the method doesn't exist
        // or returns something we can't parse.
        Python::with_gil(|py| {
            match self
                .py_obj
                .call_method1(py, "analyze_line", (filename, line, line_number))
            {
                Ok(result) => {
                    let bound = result.bind(py);
                    match bound.try_iter() {
                        Ok(iter) => {
                            let mut secrets = Vec::new();
                            for item in iter.flatten() {
                                // Each item should be a PotentialSecret-like object
                                // with secret_type, filename, secret_value, line_number
                                if let (Ok(st), Ok(sv)) = (
                                    item.getattr("secret_type")
                                        .and_then(|v| v.extract::<String>()),
                                    item.getattr("secret_value")
                                        .and_then(|v| v.extract::<String>()),
                                ) {
                                    let ln = item
                                        .getattr("line_number")
                                        .and_then(|v| v.extract::<u64>())
                                        .unwrap_or(line_number);
                                    let fn_ = item
                                        .getattr("filename")
                                        .and_then(|v| v.extract::<String>())
                                        .unwrap_or_else(|_| filename.to_string());
                                    secrets.push(PotentialSecret::new(
                                        &st, &fn_, &sv, ln, None, false,
                                    ));
                                }
                            }
                            if secrets.is_empty() {
                                // Fall back to default behavior
                                self.default_analyze_line(filename, line, line_number)
                            } else {
                                secrets
                            }
                        }
                        Err(_) => self.default_analyze_line(filename, line, line_number),
                    }
                }
                Err(_) => self.default_analyze_line(filename, line, line_number),
            }
        })
    }

    fn json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("name".to_string(), Value::String(self.class_name.clone()));
        Value::Object(obj)
    }
}

impl PyCustomPlugin {
    /// Default analyze_line: call analyze_string and wrap results.
    fn default_analyze_line(
        &self,
        filename: &str,
        line: &str,
        line_number: u64,
    ) -> Vec<PotentialSecret> {
        self.analyze_string(line)
            .into_iter()
            .map(|secret| {
                PotentialSecret::new(
                    self.secret_type(),
                    filename,
                    &secret,
                    line_number,
                    None,
                    false,
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// No-op plugin for error recovery
// ---------------------------------------------------------------------------

/// A plugin that never detects anything. Used as a fallback when a custom
/// plugin fails to load.
struct NoOpPlugin {
    class_name: String,
}

impl SecretDetector for NoOpPlugin {
    fn secret_type(&self) -> &str {
        &self.class_name
    }
    fn analyze_string(&self, _input: &str) -> Vec<String> {
        vec![]
    }
}

// ---------------------------------------------------------------------------
// Factory creation
// ---------------------------------------------------------------------------

/// Create an [`ExternalPluginFactory`] from a Python class object.
///
/// The returned factory captures the Python class and, when called,
/// instantiates it with the given config kwargs via [`PyCustomPlugin`].
fn create_custom_plugin_factory(py_class: PyObject) -> settings::ExternalPluginFactory {
    Arc::new(
        move |config: &Value| -> Box<dyn SecretDetector + Send + Sync> {
            Python::with_gil(|py| {
                let result: Box<dyn SecretDetector + Send + Sync> =
                    match PyCustomPlugin::new(py, &py_class, config) {
                        Ok(plugin) => Box::new(plugin),
                        Err(e) => {
                            eprintln!("detect-secrets-rs: failed to create custom plugin: {e}");
                            let class_name = py_class
                                .getattr(py, "__name__")
                                .and_then(|n| n.extract::<String>(py))
                                .unwrap_or_else(|_| "UnknownPlugin".to_string());
                            Box::new(NoOpPlugin { class_name })
                        }
                    };
                result
            })
        },
    )
}

// ---------------------------------------------------------------------------
// Helper: find plugin classes in a Python module
// ---------------------------------------------------------------------------

/// Scan a Python module for classes that look like detect-secrets plugins.
///
/// A valid plugin class must:
/// 1. Be a class (not a function or module).
/// 2. Have an `analyze_string` method.
/// 3. Have a `secret_type` attribute that resolves to a concrete `str`
///    (abstract properties will fail extraction).
fn find_plugin_classes_in_module(
    py: Python<'_>,
    module: &Bound<'_, PyAny>,
) -> PyResult<Vec<(String, PyObject)>> {
    let inspect = py.import("inspect")?;
    let mut plugins = Vec::new();

    let builtins = py.import("builtins")?;
    let names: Vec<String> = builtins.getattr("dir")?.call1((module,))?.extract()?;

    for name in names {
        if name.starts_with('_') {
            continue;
        }

        let attr = match module.getattr(name.as_str()) {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Must be a class
        let is_class: bool = inspect
            .call_method1("isclass", (&attr,))
            .and_then(|r| r.extract())
            .unwrap_or(false);
        if !is_class {
            continue;
        }

        // Must have analyze_string method
        if attr.getattr("analyze_string").is_err() {
            continue;
        }

        // Must have a concrete secret_type (not abstract)
        match attr.getattr("secret_type") {
            Ok(st) => {
                if st.extract::<String>().is_err() {
                    continue;
                }
            }
            Err(_) => continue,
        }

        plugins.push((name, attr.unbind()));
    }

    Ok(plugins)
}

/// Import a Python file as a module using `importlib.util`.
fn import_file_as_module<'py>(py: Python<'py>, filename: &str) -> PyResult<Bound<'py, PyAny>> {
    let importlib_util = py.import("importlib.util")?;

    let basename = std::path::Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("custom_plugin");

    let spec = importlib_util.call_method1("spec_from_file_location", (basename, filename))?;
    if spec.is_none() {
        return Err(pyo3::exceptions::PyFileNotFoundError::new_err(format!(
            "Cannot load module from {}",
            filename
        )));
    }

    let module = importlib_util.call_method1("module_from_spec", (&spec,))?;
    let loader = spec.getattr("loader")?;
    loader.call_method1("exec_module", (&module,))?;

    Ok(module)
}

// ---------------------------------------------------------------------------
// Helper: simple JSON→Python value conversion
// ---------------------------------------------------------------------------

fn json_value_to_py_simple(py: Python<'_>, v: &Value) -> PyObject {
    match v {
        Value::Null => py.None(),
        Value::Bool(b) => b.into_pyobject(py).unwrap().to_owned().into_any().unbind(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_pyobject(py).unwrap().into_any().unbind()
            } else if let Some(f) = n.as_f64() {
                f.into_pyobject(py).unwrap().into_any().unbind()
            } else {
                py.None()
            }
        }
        Value::String(s) => s.into_pyobject(py).unwrap().into_any().unbind(),
        _ => py.None(),
    }
}

// ---------------------------------------------------------------------------
// PyO3 functions — plugin loading
// ---------------------------------------------------------------------------

/// Load plugin classes from a Python file and register them.
///
/// Scans the file for classes that implement the detect-secrets plugin
/// interface (have `analyze_string` and `secret_type`), and registers
/// each as an external plugin.
///
/// Returns the list of class names that were registered.
#[pyfunction]
fn load_plugins_from_file(py: Python<'_>, filename: &str) -> PyResult<Vec<String>> {
    let module = import_file_as_module(py, filename)?;
    let plugin_classes = find_plugin_classes_in_module(py, &module)?;

    let mut class_names = Vec::new();
    for (class_name, py_class) in plugin_classes {
        let factory = create_custom_plugin_factory(py_class);
        settings::register_external_plugin(class_name.clone(), factory);
        class_names.push(class_name);
    }

    Ok(class_names)
}

/// Load plugin classes from a Python import path and register them.
///
/// Import path should be a dotted module path (e.g. `my_module.plugins`).
/// All valid plugin classes in the module are registered.
///
/// Returns the list of class names that were registered.
#[pyfunction]
fn load_plugin_from_import_path(py: Python<'_>, import_path: &str) -> PyResult<Vec<String>> {
    let importlib = py.import("importlib")?;
    let module = importlib.call_method1("import_module", (import_path,))?;
    let plugin_classes = find_plugin_classes_in_module(py, &module)?;

    let mut class_names = Vec::new();
    for (class_name, py_class) in plugin_classes {
        let factory = create_custom_plugin_factory(py_class);
        settings::register_external_plugin(class_name.clone(), factory);
        class_names.push(class_name);
    }

    Ok(class_names)
}

/// Register a single Python class as a custom plugin.
///
/// The class must have `secret_type` (str) and `analyze_string(str)`.
#[pyfunction]
fn register_custom_plugin(py: Python<'_>, class_name: String, py_class: PyObject) -> PyResult<()> {
    // Validate that the class looks like a plugin
    let bound = py_class.bind(py);
    if bound.getattr("analyze_string").is_err() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Plugin class must have an analyze_string method",
        ));
    }
    match bound.getattr("secret_type") {
        Ok(st) => {
            if st.extract::<String>().is_err() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "Plugin class must have a concrete secret_type string attribute",
                ));
            }
        }
        Err(_) => {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Plugin class must have a secret_type attribute",
            ));
        }
    }

    let factory = create_custom_plugin_factory(py_class);
    settings::register_external_plugin(class_name, factory);
    Ok(())
}

/// Clear all registered custom plugins.
#[pyfunction]
fn clear_custom_plugins() {
    settings::clear_external_plugins();
}

// ---------------------------------------------------------------------------
// PyO3 functions — filter loading
// ---------------------------------------------------------------------------

/// Determine the filter phase from a Python function's parameter names.
fn determine_filter_phase(py: Python<'_>, func: &Bound<'_, PyAny>) -> PyResult<FilterPhase> {
    let inspect = py.import("inspect")?;
    let sig = inspect.call_method1("signature", (func,))?;
    let params = sig.getattr("parameters")?;
    // Convert odict_keys to a list before extracting
    let builtins = py.import("builtins")?;
    let keys_list = builtins
        .getattr("list")?
        .call1((params.call_method0("keys")?,))?;
    let param_names: Vec<String> = keys_list.extract()?;

    Ok(if param_names.contains(&"secret".to_string()) {
        FilterPhase::Secret
    } else if param_names.contains(&"line".to_string()) {
        FilterPhase::Line
    } else {
        FilterPhase::File
    })
}

/// Create an external filter from a Python function.
fn create_external_filter(path: String, func_obj: PyObject, phase: FilterPhase) -> ExternalFilter {
    let filter_fn: engine::scan::ExternalFilterFn =
        Arc::new(move |filename: &str, line: &str, secret: &str| {
            Python::with_gil(|py| {
                let kwargs = PyDict::new(py);
                match phase {
                    FilterPhase::File => {
                        let _ = kwargs.set_item("filename", filename);
                    }
                    FilterPhase::Line => {
                        let _ = kwargs.set_item("filename", filename);
                        let _ = kwargs.set_item("line", line);
                    }
                    FilterPhase::Secret => {
                        let _ = kwargs.set_item("secret", secret);
                    }
                }
                func_obj
                    .call(py, (), Some(&kwargs))
                    .and_then(|r| r.extract::<bool>(py))
                    .unwrap_or(false)
            })
        });

    ExternalFilter {
        path,
        filter_fn,
        phase,
    }
}

/// Load a custom filter from a file path.
///
/// Path format: `file://path/to/filters.py::function_name`
/// (the `file://` prefix is optional).
///
/// Returns the full registered path.
#[pyfunction]
fn load_custom_filter_from_file(py: Python<'_>, path: &str) -> PyResult<String> {
    let path_str = path.strip_prefix("file://").unwrap_or(path);
    let parts: Vec<&str> = path_str.split("::").collect();
    if parts.len() != 2 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Expected format: file://path/to/file.py::function_name (or without file:// prefix)",
        ));
    }
    let filename = parts[0];
    let function_name = parts[1];

    let module = import_file_as_module(py, filename)?;
    let func = module.getattr(function_name)?;
    let phase = determine_filter_phase(py, &func)?;

    let full_path = format!("file://{path_str}");
    let filter = create_external_filter(full_path.clone(), func.unbind(), phase);
    engine::scan::register_external_filter(filter);

    Ok(full_path)
}

/// Load a custom filter from a Python import path.
///
/// Path format: `module.path.function_name`
/// (last component is the function name, rest is the module path).
///
/// Returns the full registered path.
#[pyfunction]
fn load_custom_filter_from_import(py: Python<'_>, path: &str) -> PyResult<String> {
    let (module_path, function_name) = path.rsplit_once('.').ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("Expected format: module.path.function_name")
    })?;

    let importlib = py.import("importlib")?;
    let module = importlib.call_method1("import_module", (module_path,))?;
    let func = module.getattr(function_name)?;
    let phase = determine_filter_phase(py, &func)?;

    let filter = create_external_filter(path.to_string(), func.unbind(), phase);
    engine::scan::register_external_filter(filter);

    Ok(path.to_string())
}

/// Clear all registered custom filters.
#[pyfunction]
fn clear_custom_filters() {
    engine::scan::clear_external_filters();
}

// ---------------------------------------------------------------------------
// PyO3 functions — mapping
// ---------------------------------------------------------------------------

/// Returns a mapping from `secret_type` → `class_name` for all plugins
/// (both built-in Rust plugins and registered custom Python plugins).
///
/// Matches Python's `get_mapping_from_secret_type_to_class()` from
/// `detect_secrets.core.plugins.util`.
#[pyfunction]
fn get_mapping_from_secret_type_to_class() -> std::collections::HashMap<String, String> {
    settings::get_mapping_from_secret_type_to_class()
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(load_plugins_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(load_plugin_from_import_path, m)?)?;
    m.add_function(wrap_pyfunction!(register_custom_plugin, m)?)?;
    m.add_function(wrap_pyfunction!(clear_custom_plugins, m)?)?;
    m.add_function(wrap_pyfunction!(load_custom_filter_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(load_custom_filter_from_import, m)?)?;
    m.add_function(wrap_pyfunction!(clear_custom_filters, m)?)?;
    m.add_function(wrap_pyfunction!(get_mapping_from_secret_type_to_class, m)?)?;
    Ok(())
}
