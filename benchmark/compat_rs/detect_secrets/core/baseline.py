"""Baseline module shim: maps detect_secrets.core.baseline to detect_secrets_rs."""
import detect_secrets_rs as _rs


def create(path_to_scan, should_scan_all_files=False, num_processors=None):
    """Create a baseline by scanning a directory.

    Maps Python's create(path, should_scan_all_files, num_processors)
    to Rust's baseline_create(paths, should_scan_all_files, root).
    """
    return _rs.baseline_create([], should_scan_all_files, root=path_to_scan)


def load(baseline_dict, filename=''):
    """Load secrets from a baseline dict."""
    return _rs.baseline_load(baseline_dict, filename)


def format_for_output(secrets_collection, is_slim_mode=False):
    """Format a SecretsCollection for JSON output."""
    return _rs.baseline_format_for_output(secrets_collection, is_slim_mode)
