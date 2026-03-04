//! PyO3 bindings for the file scanning pipeline.
//!
//! Exposes `scan_file`, `scan_line`, `scan_diff`, and `get_files_to_scan`
//! to Python.

use pyo3::prelude::*;

use crate::potential_secret::PyPotentialSecret;

/// Scan a file for secrets.
///
/// Full pipeline: read file, iterate lines, apply filename/line/secret filters,
/// run all active plugins, return list of PotentialSecret.
#[pyfunction]
fn scan_file(filename: &str) -> PyResult<Vec<PyPotentialSecret>> {
    let secrets = engine::scan::scan_file(filename);
    Ok(secrets
        .into_iter()
        .map(PyPotentialSecret::from_inner)
        .collect())
}

/// Scan a single line of text for secrets (ad-hoc).
///
/// Useful for testing individual strings without a file context.
#[pyfunction]
fn scan_line(line: &str) -> PyResult<Vec<PyPotentialSecret>> {
    let secrets = engine::scan::scan_line(line);
    Ok(secrets
        .into_iter()
        .map(PyPotentialSecret::from_inner)
        .collect())
}

/// Scan a unified diff string for secrets in added lines.
///
/// Only processes lines that were added (not removed or context lines).
#[pyfunction]
fn scan_diff(diff: &str) -> PyResult<Vec<PyPotentialSecret>> {
    let secrets = engine::scan::scan_diff(diff);
    Ok(secrets
        .into_iter()
        .map(PyPotentialSecret::from_inner)
        .collect())
}

/// Scan multiple files in parallel using rayon.
///
/// Captures settings once, then distributes file scanning across a rayon
/// thread pool. No GIL contention during Rust-side scanning.
///
/// Args:
///     filenames: List of file paths to scan.
///     num_threads: Thread pool size (default: num_cpus).
///
/// Returns:
///     Dict of {filename: [PotentialSecret, ...]}.
#[pyfunction]
#[pyo3(signature = (filenames, num_threads=None))]
fn scan_files(
    py: Python<'_>,
    filenames: Vec<String>,
    num_threads: Option<usize>,
) -> PyResult<std::collections::HashMap<String, Vec<PyPotentialSecret>>> {
    // Release GIL during Rust-side scanning
    let results = py.allow_threads(|| engine::scan::scan_files(&filenames, num_threads));

    Ok(results
        .into_iter()
        .map(|(filename, secrets)| {
            (
                filename,
                secrets
                    .into_iter()
                    .map(PyPotentialSecret::from_inner)
                    .collect(),
            )
        })
        .collect())
}

/// Discover files to scan with git-aware filtering.
///
/// Args:
///     paths: List of file/directory paths to scan.
///     should_scan_all_files: If True, include all files (not just git-tracked).
///     root: Root directory for relative path resolution.
///
/// Returns:
///     Sorted list of file paths.
#[pyfunction]
#[pyo3(signature = (paths=None, should_scan_all_files=false, root="."))]
fn get_files_to_scan(
    paths: Option<Vec<String>>,
    should_scan_all_files: bool,
    root: &str,
) -> PyResult<Vec<String>> {
    let paths = paths.unwrap_or_default();
    Ok(engine::scan::get_files_to_scan(
        &paths,
        should_scan_all_files,
        root,
    ))
}

/// Register scan functions on the module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_file, m)?)?;
    m.add_function(wrap_pyfunction!(scan_files, m)?)?;
    m.add_function(wrap_pyfunction!(scan_line, m)?)?;
    m.add_function(wrap_pyfunction!(scan_diff, m)?)?;
    m.add_function(wrap_pyfunction!(get_files_to_scan, m)?)?;
    Ok(())
}
