"""Shared fixtures for detect_secrets_rs test suite."""
import pytest
import detect_secrets_rs as rs


@pytest.fixture(autouse=True)
def reset_settings():
    """Reset global settings between every test."""
    rs.cache_bust()
    rs.global_initialize_all_plugins()
    yield
    rs.cache_bust()
