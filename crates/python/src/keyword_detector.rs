//! PyO3 wrapper for the KeywordDetector plugin.

use engine::keyword_detector::KeywordDetector;
use engine::plugin::SecretDetector;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::potential_secret::PyPotentialSecret;

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

#[pyclass(name = "KeywordDetector")]
#[derive(Clone)]
pub struct PyKeywordDetector {
    inner: KeywordDetector,
}

#[pymethods]
impl PyKeywordDetector {
    #[new]
    #[pyo3(signature = (keyword_exclude=None))]
    fn new(keyword_exclude: Option<&str>) -> Self {
        Self {
            inner: KeywordDetector::new(keyword_exclude),
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
        self.inner
            .analyze_line_for_file(filename, line, line_number)
            .into_iter()
            .map(PyPotentialSecret::from_inner)
            .collect()
    }

    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_pydict(py, &SecretDetector::json(&self.inner))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyKeywordDetector>()?;
    Ok(())
}
