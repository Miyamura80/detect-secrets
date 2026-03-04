"""Settings shim: provides default_settings() context manager."""
from contextlib import contextmanager

import detect_secrets_rs as _rs


@contextmanager
def default_settings():
    """Initialize all plugins and default filters, then restore on exit."""
    _rs.cache_bust()
    _rs.global_initialize_all_plugins()
    try:
        yield
    finally:
        _rs.cache_bust()
