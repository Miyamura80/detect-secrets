//! PyO3 bindings for all filter functions.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

// --- Heuristic filters ---

#[pyfunction]
fn is_sequential_string(secret: &str) -> bool {
    engine::filters::heuristic::is_sequential_string(secret)
}

#[pyfunction]
fn is_potential_uuid(secret: &str) -> bool {
    engine::filters::heuristic::is_potential_uuid(secret)
}

#[pyfunction]
#[pyo3(signature = (secret, line, is_regex_based_plugin=false))]
fn is_likely_id_string(secret: &str, line: &str, is_regex_based_plugin: bool) -> bool {
    engine::filters::heuristic::is_likely_id_string(secret, line, is_regex_based_plugin)
}

#[pyfunction]
fn is_non_text_file(filename: &str) -> bool {
    engine::filters::heuristic::is_non_text_file(filename)
}

#[pyfunction]
fn is_templated_secret(secret: &str) -> bool {
    engine::filters::heuristic::is_templated_secret(secret)
}

#[pyfunction]
fn is_prefixed_with_dollar_sign(secret: &str) -> bool {
    engine::filters::heuristic::is_prefixed_with_dollar_sign(secret)
}

#[pyfunction]
fn is_indirect_reference(line: &str) -> bool {
    engine::filters::heuristic::is_indirect_reference(line)
}

#[pyfunction]
fn is_lock_file(filename: &str) -> bool {
    engine::filters::heuristic::is_lock_file(filename)
}

#[pyfunction]
fn is_not_alphanumeric_string(secret: &str) -> bool {
    engine::filters::heuristic::is_not_alphanumeric_string(secret)
}

#[pyfunction]
fn is_swagger_file(filename: &str) -> bool {
    engine::filters::heuristic::is_swagger_file(filename)
}

// --- Allowlist filter ---

#[pyfunction]
#[pyo3(signature = (filename, line, previous_line=""))]
fn is_line_allowlisted(filename: &str, line: &str, previous_line: &str) -> bool {
    engine::filters::allowlist::is_line_allowlisted(filename, line, previous_line)
}

// --- Common filters ---

#[pyfunction]
fn is_invalid_file(filename: &str) -> bool {
    engine::filters::common::is_invalid_file(filename)
}

// --- Regex exclusion filters ---

#[pyfunction]
fn should_exclude_line(line: &str, patterns: Vec<String>) -> PyResult<bool> {
    let regexes = engine::filters::regex_filter::compile_regexes(&patterns)
        .map_err(|e| PyValueError::new_err(format!("Invalid regex pattern: {}", e)))?;
    Ok(engine::filters::regex_filter::should_exclude_line(
        line, &regexes,
    ))
}

#[pyfunction]
fn should_exclude_file(filename: &str, patterns: Vec<String>) -> PyResult<bool> {
    let regexes = engine::filters::regex_filter::compile_regexes(&patterns)
        .map_err(|e| PyValueError::new_err(format!("Invalid regex pattern: {}", e)))?;
    Ok(engine::filters::regex_filter::should_exclude_file(
        filename, &regexes,
    ))
}

#[pyfunction]
fn should_exclude_secret(secret: &str, patterns: Vec<String>) -> PyResult<bool> {
    let regexes = engine::filters::regex_filter::compile_regexes(&patterns)
        .map_err(|e| PyValueError::new_err(format!("Invalid regex pattern: {}", e)))?;
    Ok(engine::filters::regex_filter::should_exclude_secret(
        secret, &regexes,
    ))
}

// --- Wordlist filter ---

/// A compiled wordlist filter backed by an Aho-Corasick automaton.
#[pyclass(name = "WordlistFilter")]
struct PyWordlistFilter {
    inner: engine::filters::wordlist::WordlistFilter,
}

#[pymethods]
impl PyWordlistFilter {
    /// Create a new WordlistFilter from a file.
    ///
    /// Args:
    ///     wordlist_filename: Path to a text file with one word per line.
    ///     min_length: Words shorter than this are ignored (default: 3).
    #[new]
    #[pyo3(signature = (wordlist_filename, min_length=3))]
    fn new(wordlist_filename: &str, min_length: usize) -> PyResult<Self> {
        let inner =
            engine::filters::wordlist::WordlistFilter::from_file(wordlist_filename, min_length)
                .map_err(|e| PyValueError::new_err(format!("Failed to load wordlist: {}", e)))?;
        Ok(PyWordlistFilter { inner })
    }

    /// Check if a secret contains any word from the wordlist.
    fn should_exclude_secret(&self, secret: &str) -> bool {
        self.inner.should_exclude_secret(secret)
    }

    /// The file name the wordlist was loaded from.
    #[getter]
    fn file_name(&self) -> &str {
        &self.inner.file_name
    }

    /// SHA1 hash of the wordlist file contents.
    #[getter]
    fn file_hash(&self) -> &str {
        &self.inner.file_hash
    }

    /// Minimum word length threshold used when loading.
    #[getter]
    fn min_length(&self) -> usize {
        self.inner.min_length
    }
}

// --- Wordlist utility ---

#[pyfunction]
fn compute_file_hash(filename: &str) -> PyResult<String> {
    engine::filters::wordlist::compute_file_hash(filename)
        .map_err(|e| PyValueError::new_err(format!("Failed to compute hash: {}", e)))
}

// --- Filter registry ---

#[pyfunction]
fn get_filters_with_parameter(
    active_filter_paths: Vec<String>,
    required_params: Vec<String>,
) -> PyResult<Vec<String>> {
    let active_ids: Vec<engine::filters::registry::FilterId> = active_filter_paths
        .iter()
        .filter_map(|p| engine::filters::registry::FilterId::from_path(p))
        .collect();

    let params: Vec<engine::filters::registry::FilterParam> = required_params
        .iter()
        .filter_map(|p| match p.as_str() {
            "filename" => Some(engine::filters::registry::FilterParam::Filename),
            "line" => Some(engine::filters::registry::FilterParam::Line),
            "secret" => Some(engine::filters::registry::FilterParam::Secret),
            "context" => Some(engine::filters::registry::FilterParam::Context),
            "plugin" => Some(engine::filters::registry::FilterParam::Plugin),
            _ => None,
        })
        .collect();

    let result = engine::filters::registry::get_filters_with_parameter(&active_ids, &params);

    Ok(result.iter().map(|f| f.path().to_string()).collect())
}

/// Register all filter functions on the parent module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Heuristic filters
    m.add_function(wrap_pyfunction!(is_sequential_string, m)?)?;
    m.add_function(wrap_pyfunction!(is_potential_uuid, m)?)?;
    m.add_function(wrap_pyfunction!(is_likely_id_string, m)?)?;
    m.add_function(wrap_pyfunction!(is_non_text_file, m)?)?;
    m.add_function(wrap_pyfunction!(is_templated_secret, m)?)?;
    m.add_function(wrap_pyfunction!(is_prefixed_with_dollar_sign, m)?)?;
    m.add_function(wrap_pyfunction!(is_indirect_reference, m)?)?;
    m.add_function(wrap_pyfunction!(is_lock_file, m)?)?;
    m.add_function(wrap_pyfunction!(is_not_alphanumeric_string, m)?)?;
    m.add_function(wrap_pyfunction!(is_swagger_file, m)?)?;
    // Allowlist filter
    m.add_function(wrap_pyfunction!(is_line_allowlisted, m)?)?;
    // Common filters
    m.add_function(wrap_pyfunction!(is_invalid_file, m)?)?;
    // Regex exclusion filters
    m.add_function(wrap_pyfunction!(should_exclude_line, m)?)?;
    m.add_function(wrap_pyfunction!(should_exclude_file, m)?)?;
    m.add_function(wrap_pyfunction!(should_exclude_secret, m)?)?;
    // Wordlist filter
    m.add_class::<PyWordlistFilter>()?;
    m.add_function(wrap_pyfunction!(compute_file_hash, m)?)?;
    // Filter registry
    m.add_function(wrap_pyfunction!(get_filters_with_parameter, m)?)?;
    Ok(())
}
