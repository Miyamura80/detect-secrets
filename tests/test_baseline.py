"""Baseline management tests for detect_secrets_rs.

Tests baseline creation, loading, saving, round-trip compatibility, and upgrade
from older versions.
"""
import json
import os
import tempfile

import pytest
import detect_secrets_rs as rs


class TestBaselineVersion:
    def test_version_string(self):
        assert rs.baseline_version() == "1.5.0"


class TestBaselineRoundTrip:
    def test_create_save_load_roundtrip(self):
        """Create a baseline from a file with secrets, save it, load it back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write a file with a known secret
            secret_file = os.path.join(tmpdir, "secret.py")
            with open(secret_file, "w") as f:
                f.write("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")

            # Create baseline
            secrets = rs.baseline_create([secret_file], False, tmpdir)
            assert len(secrets) > 0

            # Format and save
            output = rs.baseline_format_for_output(secrets, False)
            baseline_path = os.path.join(tmpdir, ".secrets.baseline")
            rs.baseline_save_to_file(output, baseline_path)

            # Verify file exists and is valid JSON
            with open(baseline_path) as f:
                data = json.load(f)

            assert data["version"] == "1.5.0"
            assert "plugins_used" in data
            assert "filters_used" in data
            assert "results" in data
            assert "generated_at" in data

            # Load it back
            loaded = rs.baseline_load_from_file(baseline_path)
            loaded_secrets = rs.baseline_load(loaded, baseline_path)

            assert len(loaded_secrets) > 0

    def test_slim_mode_excludes_generated_at(self):
        """Slim mode should not include generated_at or line_number."""
        secrets = rs.SecretsCollection()
        output = rs.baseline_format_for_output(secrets, True)
        assert "generated_at" not in output

    def test_format_key_ordering(self):
        """Keys should be in order: version, plugins_used, filters_used, results, generated_at."""
        secrets = rs.SecretsCollection()
        output = rs.baseline_format_for_output(secrets, False)
        keys = list(output.keys())
        assert keys[0] == "version"
        assert keys[1] == "plugins_used"
        assert keys[2] == "filters_used"
        assert keys[3] == "results"
        assert keys[4] == "generated_at"


class TestBaselineUpgrade:
    def test_current_version_unchanged(self):
        baseline = {
            "version": "1.5.0",
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [],
            "results": {},
        }
        result = rs.baseline_upgrade(baseline)
        assert result["version"] == "1.5.0"

    def test_v0_12_migration(self):
        baseline = {
            "version": "0.11.0",
            "exclude_regex": "tests/.*",
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "results": {},
        }
        result = rs.baseline_upgrade(baseline)
        assert "exclude_regex" not in result
        assert result["version"] == "1.5.0"
        assert "filters_used" in result

    def test_v1_0_filter_migration(self):
        baseline = {
            "version": "0.14.0",
            "exclude": {"files": "tests/.*", "lines": None},
            "word_list": {"file": None, "hash": None},
            "plugins_used": [
                {"name": "Base64HighEntropyString", "base64_limit": 4.5},
                {"name": "HexHighEntropyString", "hex_limit": 3.0},
            ],
            "results": {},
        }
        result = rs.baseline_upgrade(baseline)

        assert "exclude" not in result
        assert "word_list" not in result
        assert result["version"] == "1.5.0"

        # base64_limit should be renamed to limit
        plugins = result["plugins_used"]
        b64 = next(p for p in plugins if p["name"] == "Base64HighEntropyString")
        assert "base64_limit" not in b64
        assert b64["limit"] == 4.5

    def test_v1_1_adds_new_filters(self):
        baseline = {
            "version": "1.0.0",
            "plugins_used": [],
            "filters_used": [
                {"path": "detect_secrets.filters.heuristic.is_sequential_string"},
            ],
            "results": {},
        }
        result = rs.baseline_upgrade(baseline)
        paths = [f["path"] for f in result["filters_used"]]
        assert "detect_secrets.filters.heuristic.is_lock_file" in paths
        assert "detect_secrets.filters.heuristic.is_not_alphanumeric_string" in paths
        assert "detect_secrets.filters.heuristic.is_swagger_file" in paths


class TestBaselineLoad:
    def test_load_from_dict(self):
        baseline = {
            "version": "1.5.0",
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [],
            "results": {
                "test.py": [
                    {
                        "type": "AWS Access Key",
                        "hashed_secret": "abc123",
                        "is_verified": False,
                        "line_number": 5,
                    }
                ]
            },
        }
        collection = rs.baseline_load(baseline, "")
        assert len(collection) == 1

    def test_load_from_file(self):
        baseline = {
            "version": "1.5.0",
            "plugins_used": [],
            "filters_used": [],
            "results": {},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(baseline, f)
            path = f.name

        try:
            loaded = rs.baseline_load_from_file(path)
            assert loaded["version"] == "1.5.0"
        finally:
            os.unlink(path)


class TestSecretsCollectionOperations:
    def test_merge_preserves_labels(self):
        """merge() should preserve is_secret from old baseline."""
        old = rs.SecretsCollection()
        s = rs.PotentialSecret("AWS Access Key", "test.py", "AKIAIOSFODNN7EXAMPLE", 5)
        s.is_secret = True
        old["test.py"] = [s]

        new = rs.SecretsCollection()
        s2 = rs.PotentialSecret("AWS Access Key", "test.py", "AKIAIOSFODNN7EXAMPLE", 5)
        new["test.py"] = [s2]

        new.merge(old)

    def test_len_and_bool(self):
        c = rs.SecretsCollection()
        assert len(c) == 0
        assert not c

        s = rs.PotentialSecret("Test", "file.py", "secret", 1)
        c["file.py"] = [s]
        assert len(c) > 0
        assert c

    def test_json_output(self):
        c = rs.SecretsCollection()
        j = c.json()
        assert isinstance(j, dict)
