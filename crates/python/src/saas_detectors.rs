//! PyO3 wrappers for SaaS service secret detectors.
//!
//! Exposes the following plugins to Python:
//! - `MailchimpDetector`
//! - `NpmDetector`
//! - `OpenAIDetector`
//! - `PypiTokenDetector`
//! - `SendGridDetector`
//! - `SlackDetector`
//! - `SquareOAuthDetector`
//! - `StripeDetector`
//! - `TelegramBotTokenDetector`
//! - `TwilioKeyDetector`
//! - `IPPublicDetector`

use engine::plugin::SecretDetector;
use engine::saas_detectors;
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
// Macro to reduce boilerplate for simple detectors
// ---------------------------------------------------------------------------

macro_rules! py_detector {
    ($py_name:ident, $py_str:literal, $inner_type:ty) => {
        #[pyclass(name = $py_str)]
        #[derive(Clone)]
        pub struct $py_name {
            inner: $inner_type,
        }

        #[pymethods]
        impl $py_name {
            #[new]
            fn new() -> Self {
                Self {
                    inner: <$inner_type>::new(),
                }
            }

            #[getter]
            fn secret_type(&self) -> &str {
                self.inner.secret_type()
            }

            fn analyze_string(&self, input: &str) -> Vec<String> {
                SecretDetector::analyze_string(&self.inner, input)
            }

            fn analyze_line(
                &self,
                filename: &str,
                line: &str,
                line_number: u64,
            ) -> Vec<PyPotentialSecret> {
                SecretDetector::analyze_line(&self.inner, filename, line, line_number)
                    .into_iter()
                    .map(PyPotentialSecret::from_inner)
                    .collect()
            }

            fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
                json_value_to_pydict(py, &SecretDetector::json(&self.inner))
            }
        }
    };
}

py_detector!(
    PyMailchimpDetector,
    "MailchimpDetector",
    saas_detectors::MailchimpDetector
);
py_detector!(PyNpmDetector, "NpmDetector", saas_detectors::NpmDetector);
py_detector!(
    PyOpenAIDetector,
    "OpenAIDetector",
    saas_detectors::OpenAIDetector
);
py_detector!(
    PyPypiTokenDetector,
    "PypiTokenDetector",
    saas_detectors::PypiTokenDetector
);
py_detector!(
    PySendGridDetector,
    "SendGridDetector",
    saas_detectors::SendGridDetector
);
py_detector!(
    PySlackDetector,
    "SlackDetector",
    saas_detectors::SlackDetector
);
py_detector!(
    PySquareOAuthDetector,
    "SquareOAuthDetector",
    saas_detectors::SquareOAuthDetector
);
py_detector!(
    PyStripeDetector,
    "StripeDetector",
    saas_detectors::StripeDetector
);
py_detector!(
    PyTelegramBotTokenDetector,
    "TelegramBotTokenDetector",
    saas_detectors::TelegramBotTokenDetector
);
py_detector!(
    PyTwilioKeyDetector,
    "TwilioKeyDetector",
    saas_detectors::TwilioKeyDetector
);
py_detector!(
    PyIpPublicDetector,
    "IPPublicDetector",
    saas_detectors::IpPublicDetector
);

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Register SaaS detector classes on the Python module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMailchimpDetector>()?;
    m.add_class::<PyNpmDetector>()?;
    m.add_class::<PyOpenAIDetector>()?;
    m.add_class::<PyPypiTokenDetector>()?;
    m.add_class::<PySendGridDetector>()?;
    m.add_class::<PySlackDetector>()?;
    m.add_class::<PySquareOAuthDetector>()?;
    m.add_class::<PyStripeDetector>()?;
    m.add_class::<PyTelegramBotTokenDetector>()?;
    m.add_class::<PyTwilioKeyDetector>()?;
    m.add_class::<PyIpPublicDetector>()?;
    Ok(())
}
