"""Scan module shim: maps detect_secrets.core.scan to detect_secrets_rs."""
import detect_secrets_rs as _rs


def scan_file(filename):
    """Scan a file for secrets.

    Returns a list of PotentialSecret (compatible with Python's generator).
    """
    return _rs.scan_file(filename)
