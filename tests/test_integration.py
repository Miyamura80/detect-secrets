"""Integration tests for detect_secrets_rs.

End-to-end tests that verify the full scanning pipeline produces correct
results, matching the behavior of the Python detect-secrets original.
"""
import os
import tempfile

import pytest
import detect_secrets_rs as rs


class TestScanFile:
    def test_scan_file_with_aws_key(self):
        """scan_file should detect an AWS access key."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write("# config\n")
            f.write("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
            f.write("normal = 'hello'\n")
            path = f.name

        try:
            results = rs.scan_file(path)
            assert len(results) > 0
            types = [s.type for s in results]
            assert "AWS Access Key" in types
        finally:
            os.unlink(path)

    def test_scan_file_nonexistent(self):
        results = rs.scan_file("/nonexistent/file.txt")
        assert len(results) == 0

    def test_scan_file_non_text(self):
        results = rs.scan_file("test.png")
        assert len(results) == 0

    def test_scan_file_allowlisted(self):
        """Lines with pragma: allowlist secret should be filtered."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'  # pragma: allowlist secret\n")
            path = f.name

        try:
            results = rs.scan_file(path)
            assert len(results) == 0
        finally:
            os.unlink(path)

    def test_scan_file_private_key(self):
        """scan_file should detect private key markers."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\n")
            f.write("MIIEpAIBAAKCAQEA\n")
            f.write("-----END RSA PRIVATE KEY-----\n")
            path = f.name

        try:
            results = rs.scan_file(path)
            types = [s.type for s in results]
            assert "Private Key" in types
        finally:
            os.unlink(path)

    def test_scan_file_multiple_secrets(self):
        """A file with multiple different secret types."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
            f.write("-----BEGIN RSA PRIVATE KEY-----\n")
            f.write('basic = "https://user:pass@example.com"\n')
            path = f.name

        try:
            results = rs.scan_file(path)
            types = set(s.type for s in results)
            assert "AWS Access Key" in types
            assert "Private Key" in types
        finally:
            os.unlink(path)


class TestScanPipelineFiltering:
    """Verify that the full scan pipeline filters false positives."""

    def test_template_variable_filtered(self):
        """${variable} should be filtered by is_templated_secret."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write("password: ${link}\n")
            path = f.name

        try:
            results = rs.scan_file(path)
            keyword_secrets = [s for s in results if s.type == "Secret Keyword"]
            assert len(keyword_secrets) == 0, "Template variables should be filtered"
        finally:
            os.unlink(path)

    def test_sequential_string_filtered(self):
        """Sequential strings like 'ABCDEFGH' should be filtered."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write('token = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"\n')
            path = f.name

        try:
            results = rs.scan_file(path)
            # Sequential strings are filtered by is_sequential_string
            keyword_secrets = [s for s in results if s.type == "Secret Keyword"]
            assert len(keyword_secrets) == 0, "Sequential strings should be filtered"
        finally:
            os.unlink(path)


class TestScanLine:
    def test_aws_key(self):
        results = rs.scan_line("AKIAIOSFODNN7EXAMPLE")
        types = [s.type for s in results]
        assert "AWS Access Key" in types

    def test_no_secret(self):
        results = rs.scan_line("hello world")
        # Should not detect high-value secrets in plain text
        types = [s.type for s in results]
        assert "AWS Access Key" not in types
        assert "Private Key" not in types

    def test_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        results = rs.scan_line(jwt)
        types = [s.type for s in results]
        assert "JSON Web Token" in types

    def test_private_key(self):
        results = rs.scan_line("-----BEGIN RSA PRIVATE KEY-----")
        types = [s.type for s in results]
        assert "Private Key" in types


class TestScanDiff:
    def test_detects_added_secrets(self):
        diff = """\
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,2 +1,3 @@
 import os
+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
 print('done')"""

        results = rs.scan_diff(diff)
        types = [s.type for s in results]
        assert "AWS Access Key" in types

    def test_ignores_removed_lines(self):
        diff = """\
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,3 +1,2 @@
 import os
-AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
 print('done')"""

        results = rs.scan_diff(diff)
        types = [s.type for s in results]
        assert "AWS Access Key" not in types

    def test_empty_diff(self):
        results = rs.scan_diff("")
        assert len(results) == 0


class TestScanFiles:
    def test_parallel_scan(self):
        """Parallel scan of multiple files produces correct results."""
        paths = []
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                path = os.path.join(tmpdir, f"file_{i}.py")
                with open(path, "w") as f:
                    f.write(f'aws_key_{i} = "AKIAIOSFODNN7EXAMPL{i}"\n')
                paths.append(path)

            results = rs.scan_files(paths, 2)
            assert len(results) > 0

    def test_parallel_matches_sequential(self):
        """Parallel and sequential scanning should produce the same results."""
        paths = []
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                path = os.path.join(tmpdir, f"file_{i}.py")
                with open(path, "w") as f:
                    f.write(f'aws_key_{i} = "AKIAIOSFODNN7EXAMPL{i}"\n')
                paths.append(path)

            # Sequential
            sequential = {}
            for path in paths:
                secrets = rs.scan_file(path)
                if secrets:
                    sequential[path] = len(secrets)

            # Parallel
            parallel_results = rs.scan_files(paths, 2)
            parallel = {k: len(v) for k, v in parallel_results.items()}

            assert len(sequential) == len(parallel)


class TestPotentialSecret:
    def test_create_and_hash(self):
        s = rs.PotentialSecret("AWS Access Key", "test.py", "AKIAIOSFODNN7EXAMPLE", 5)
        assert s.type == "AWS Access Key"
        assert s.filename == "test.py"
        assert s.line_number == 5
        assert len(s.secret_hash) > 0

    def test_hash_deterministic(self):
        h1 = rs.hash_secret("my_secret")
        h2 = rs.hash_secret("my_secret")
        assert h1 == h2

    def test_hash_secret_known_value(self):
        assert rs.hash_secret("my_secret") == "7585d1f7ceb90fd0b1ab42d0a6ca39fcf55065c7"

    def test_equality(self):
        s1 = rs.PotentialSecret("Type", "file.py", "secret1", 1)
        s2 = rs.PotentialSecret("Type", "file.py", "secret1", 2)
        # Same (filename, secret_hash, secret_type) → equal
        assert s1 == s2

    def test_inequality(self):
        s1 = rs.PotentialSecret("Type", "file.py", "secret1", 1)
        s2 = rs.PotentialSecret("Type", "file.py", "secret2", 1)
        # Different secret → different hash → not equal
        assert s1 != s2

    def test_json_output(self):
        s = rs.PotentialSecret("AWS Access Key", "test.py", "AKIAIOSFODNN7EXAMPLE", 5)
        j = s.json()
        assert "type" in j
        assert "hashed_secret" in j
        assert "line_number" in j


class TestEntropy:
    def test_shannon_entropy_base64(self):
        val = rs.calculate_shannon_entropy(
            "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5",
            rs.BASE64_CHARSET,
        )
        assert val > 4.0

    def test_shannon_entropy_hex(self):
        val = rs.calculate_shannon_entropy(
            "2b00042f7481c7b056c4b410d28f33cf",
            rs.HEX_CHARSET,
        )
        assert val > 3.0

    def test_hex_numeric_reduction(self):
        """All-numeric hex strings should have reduced entropy."""
        val = rs.calculate_hex_shannon_entropy("999999")
        assert val < 0  # Should go negative after reduction


class TestSettings:
    def test_get_settings(self):
        s = rs.get_settings()
        assert s is not None

    def test_all_plugin_class_names(self):
        names = rs.all_plugin_class_names()
        assert "AWSKeyDetector" in names
        assert "BasicAuthDetector" in names
        assert "PrivateKeyDetector" in names
        assert len(names) >= 27

    def test_configure_from_baseline(self):
        baseline = {
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [],
        }
        rs.configure_settings_from_baseline(baseline, "")

    def test_version(self):
        v = rs.version()
        assert isinstance(v, str)
        assert len(v) > 0


class TestEndToEnd:
    """Full end-to-end workflow test."""

    def test_scan_create_save_load_audit(self):
        """Full workflow: create file → scan → save baseline → load → verify."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            f1 = os.path.join(tmpdir, "config.py")
            with open(f1, "w") as f:
                f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
                f.write('DB_PASS = "hunter2"\n')
                f.write("-----BEGIN RSA PRIVATE KEY-----\n")
                f.write("MIIEpAIBAAKCAQEA\n")

            f2 = os.path.join(tmpdir, "safe.py")
            with open(f2, "w") as f:
                f.write("# No secrets here\n")
                f.write("x = 42\n")

            # Create baseline
            secrets = rs.baseline_create([f1, f2], False, tmpdir)
            assert len(secrets) > 0

            # Format and save
            output = rs.baseline_format_for_output(secrets, False)
            assert output["version"] == "1.5.0"
            assert len(output["plugins_used"]) > 0

            baseline_path = os.path.join(tmpdir, ".secrets.baseline")
            rs.baseline_save_to_file(output, baseline_path)

            # Load back
            loaded_dict = rs.baseline_load_from_file(baseline_path)
            loaded_secrets = rs.baseline_load(loaded_dict, baseline_path)

            # Verify counts match
            assert len(secrets) == len(loaded_secrets)

    def test_scan_with_test_data(self):
        """Scan the Python detect-secrets test_data directory if available."""
        test_data = os.path.join(
            os.path.dirname(__file__),
            "..",
            "detect-secrets",
            "test_data",
            "files",
            "file_with_secrets.py",
        )
        if not os.path.exists(test_data):
            pytest.skip("detect-secrets submodule not available")

        results = rs.scan_file(test_data)
        # The file_with_secrets.py should have at least one secret
        assert len(results) > 0

    def test_secrets_collection_scan_files(self):
        """SecretsCollection.scan_files should populate the collection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = []
            for i in range(3):
                path = os.path.join(tmpdir, f"file_{i}.py")
                with open(path, "w") as f:
                    f.write(f'aws_key = "AKIAIOSFODNN7EXAMPL{i}"\n')
                paths.append(path)

            collection = rs.SecretsCollection()
            collection.scan_files(paths, 2)
            assert len(collection) > 0
