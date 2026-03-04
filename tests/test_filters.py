"""Filter tests for detect_secrets_rs — ported from Yelp/detect-secrets test suite.

Each test verifies that the Rust filter produces the same results as the Python
original for known inputs.
"""
import os
import tempfile

import pytest
import detect_secrets_rs as rs


# ---------------------------------------------------------------------------
# Heuristic: is_sequential_string
# ---------------------------------------------------------------------------

class TestIsSequentialString:
    @pytest.mark.parametrize("secret", [
        "ABCDEF",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "0123456789",
        "1234567890",
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "0123456789abcdef",
        "abcdef0123456789",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
    ])
    def test_sequential(self, secret):
        assert rs.is_sequential_string(secret) is True

    def test_not_sequential(self):
        assert rs.is_sequential_string("BEEF1234") is False


# ---------------------------------------------------------------------------
# Heuristic: is_potential_uuid
# ---------------------------------------------------------------------------

class TestIsPotentialUuid:
    @pytest.mark.parametrize("secret", [
        "3636dd46-ea21-11e9-81b4-2a2ae2dbcce4",
        "97fb0431-46ac-41df-9ef9-1a18545ce2a0",
    ])
    def test_uuid(self, secret):
        assert rs.is_potential_uuid(secret) is True

    def test_not_uuid(self):
        assert rs.is_potential_uuid("not-a-uuid") is False


# ---------------------------------------------------------------------------
# Heuristic: is_likely_id_string
# ---------------------------------------------------------------------------

class TestIsLikelyIdString:
    @pytest.mark.parametrize("secret,line", [
        ("RANDOM_STRING", "id: RANDOM_STRING"),
        ("RANDOM_STRING", "id=RANDOM_STRING"),
        ("RANDOM_STRING", "id = RANDOM_STRING"),
        ("RANDOM_STRING", "myid: RANDOM_STRING"),
        ("RANDOM_STRING", "myid=RANDOM_STRING"),
        ("RANDOM_STRING", "myid = RANDOM_STRING"),
        ("RANDOM_STRING", "userid: RANDOM_STRING"),
        ("RANDOM_STRING", "userid=RANDOM_STRING"),
        ("RANDOM_STRING", "userid = RANDOM_STRING"),
        ("RANDOM_STRING", "data test_id: RANDOM_STRING"),
        ("RANDOM_STRING", "data test_id=RANDOM_STRING"),
        ("RANDOM_STRING", "data test_id = RANDOM_STRING"),
        ("RANDOM_STRING", "ids = RANDOM_STRING, RANDOM_STRING"),
        ("RANDOM_STRING", "my_ids: RANDOM_STRING, RANDOM_STRING"),
    ])
    def test_id_string(self, secret, line):
        assert rs.is_likely_id_string(secret, line, False) is True

    @pytest.mark.parametrize("secret,line", [
        ("RANDOM_STRING", "hidden_secret: RANDOM_STRING"),
        ("RANDOM_STRING", "hidden_secret=RANDOM_STRING"),
        ("RANDOM_STRING", "hidden_secret = RANDOM_STRING"),
        ("SOME_RANDOM_STRING", "id: SOME_OTHER_RANDOM_STRING"),
        ("RANDOM_STRING", "postgres://david:RANDOM_STRING"),
    ])
    def test_not_id_string(self, secret, line):
        assert rs.is_likely_id_string(secret, line, False) is False


# ---------------------------------------------------------------------------
# Heuristic: is_templated_secret
# ---------------------------------------------------------------------------

class TestIsTemplatedSecret:
    @pytest.mark.parametrize("secret,expected", [
        ("{hunter2}", True),
        ("<hunter2>", True),
        ("${hunter2}", True),
        ("hunter2", False),
    ])
    def test_templated(self, secret, expected):
        # is_templated_secret takes the secret VALUE, not the full line
        assert rs.is_templated_secret(secret) is expected


# ---------------------------------------------------------------------------
# Heuristic: is_prefixed_with_dollar_sign
# ---------------------------------------------------------------------------

class TestIsPrefixedWithDollarSign:
    @pytest.mark.parametrize("secret,expected", [
        ("$secret", True),
        ("secret", False),
        ("", False),
    ])
    def test_dollar_prefix(self, secret, expected):
        assert rs.is_prefixed_with_dollar_sign(secret) is expected


# ---------------------------------------------------------------------------
# Heuristic: is_indirect_reference
# ---------------------------------------------------------------------------

class TestIsIndirectReference:
    @pytest.mark.parametrize("line,expected", [
        ("secret = get_secret_key()", True),
        ('secret = request.headers["apikey"]', True),
        ("secret = hunter2", False),
    ])
    def test_indirect(self, line, expected):
        assert rs.is_indirect_reference(line) is expected


# ---------------------------------------------------------------------------
# Heuristic: is_lock_file
# ---------------------------------------------------------------------------

class TestIsLockFile:
    @pytest.mark.parametrize("filename,expected", [
        ("composer.lock", True),
        ("packages.lock.json", True),
        ("path/yarn.lock", True),
        ("Gemfilealock", False),
    ])
    def test_lock_file(self, filename, expected):
        assert rs.is_lock_file(filename) is expected


# ---------------------------------------------------------------------------
# Heuristic: is_not_alphanumeric_string
# ---------------------------------------------------------------------------

class TestIsNotAlphanumericString:
    @pytest.mark.parametrize("secret,expected", [
        ("*****", True),
        ("a&b23?!", False),
    ])
    def test_alphanumeric(self, secret, expected):
        assert rs.is_not_alphanumeric_string(secret) is expected


# ---------------------------------------------------------------------------
# Heuristic: is_swagger_file
# ---------------------------------------------------------------------------

class TestIsSwaggerFile:
    @pytest.mark.parametrize("filename,expected", [
        ("/path/swagger-ui.html", True),
        ("/path/swagger/config.yml", True),
        ("/path/non/swager/files", False),
    ])
    def test_swagger(self, filename, expected):
        assert rs.is_swagger_file(filename) is expected


# ---------------------------------------------------------------------------
# Heuristic: is_non_text_file
# ---------------------------------------------------------------------------

class TestIsNonTextFile:
    @pytest.mark.parametrize("filename,expected", [
        ("image.png", True),
        ("document.pdf", True),
        ("archive.zip", True),
        ("script.py", False),
        ("config.yaml", False),
    ])
    def test_non_text(self, filename, expected):
        assert rs.is_non_text_file(filename) is expected


# ---------------------------------------------------------------------------
# Allowlist: is_line_allowlisted
# ---------------------------------------------------------------------------

class TestIsLineAllowlisted:
    COMMENT_PARTS = [
        ("#", ""),
        ("# ", " more text"),
        ("//", ""),
        ("// ", " more text"),
        ("/*", "*/"),
        ("/* ", " */"),
        ("--", ""),
        ("-- ", " more text"),
        ("<!--", "-->"),
    ]

    @pytest.mark.parametrize("prefix,suffix", COMMENT_PARTS)
    def test_same_line_allowlist(self, prefix, suffix):
        # API: is_line_allowlisted(filename, line, previous_line)
        line = "AKIAEXAMPLE  {}pragma: allowlist secret{}".format(prefix, suffix)
        assert rs.is_line_allowlisted("test.py", line, "") is True

    @pytest.mark.parametrize("prefix,suffix", COMMENT_PARTS)
    def test_nextline_allowlist(self, prefix, suffix):
        # previous_line has the pragma comment, current line has the secret
        comment = "{}pragma: allowlist nextline secret{}".format(prefix, suffix)
        assert rs.is_line_allowlisted("test.py", "AKIAEXAMPLE", comment) is True

    def test_backwards_compat_whitelist(self):
        line = "AKIAEXAMPLE  # pragma: whitelist secret"
        assert rs.is_line_allowlisted("test.py", line, "") is True

    def test_no_allowlist(self):
        assert rs.is_line_allowlisted("test.py", "secret = hunter2", "") is False


# ---------------------------------------------------------------------------
# Regex filters
# ---------------------------------------------------------------------------

class TestShouldExcludeLine:
    @pytest.mark.parametrize("line,expected", [
        ('password = "canarytoken"', True),
        ('password = "hunter2"', False),
        ("not-real-secret = value", True),
        ("maybe-not-real-secret = value", False),
    ])
    def test_exclude_line(self, line, expected):
        patterns = ["canarytoken", "^not-real-secret = .*$"]
        assert rs.should_exclude_line(line, patterns) is expected


class TestShouldExcludeFile:
    @pytest.mark.parametrize("filename,expected", [
        ("tests/blah.py", True),
        ("detect_secrets/tests/blah.py", False),
        ("app/messages/i18/en.properties", True),
        ("app/i18secrets/secrets.yaml", False),
    ])
    def test_exclude_file(self, filename, expected):
        patterns = ["^tests/.*", ".*/i18/.*"]
        assert rs.should_exclude_file(filename, patterns) is expected


class TestShouldExcludeSecret:
    @pytest.mark.parametrize("secret,expected", [
        ("Password123", True),
        ("MyRealPassword", False),
        ("1-my-first-password-for-database", True),
        ("my-password", False),
    ])
    def test_exclude_secret(self, secret, expected):
        patterns = [r"^[Pp]assword[0-9]{0,3}$", "my-first-password"]
        assert rs.should_exclude_secret(secret, patterns) is expected


# ---------------------------------------------------------------------------
# Wordlist filter
# ---------------------------------------------------------------------------

class TestWordlistFilter:
    def test_from_file(self):
        # WordlistFilter constructor: (wordlist_filename, min_length=3)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("password\nsecretkey\ntestvalue\n")
            f.flush()
            path = f.name

        try:
            wl = rs.WordlistFilter(path, 6)
            assert wl.should_exclude_secret("mypasswordhere") is True
            assert wl.should_exclude_secret("XY") is False
        finally:
            os.unlink(path)

    def test_case_insensitive(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("testpass\npassword123\nsecretkey\n")
            f.flush()
            path = f.name

        try:
            wl = rs.WordlistFilter(path, 4)
            assert wl.should_exclude_secret("TestPass") is True  # case-insensitive
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Common filters
# ---------------------------------------------------------------------------

class TestIsInvalidFile:
    def test_nonexistent(self):
        assert rs.is_invalid_file("/nonexistent/path/file.py") is True

    def test_existing(self):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            path = f.name
        try:
            assert rs.is_invalid_file(path) is False
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# get_filters_with_parameter
# ---------------------------------------------------------------------------

class TestGetFiltersWithParameter:
    def test_returns_list(self):
        # API: get_filters_with_parameter(active_filter_paths, required_params)
        all_filters = [
            "detect_secrets.filters.heuristic.is_sequential_string",
            "detect_secrets.filters.heuristic.is_potential_uuid",
            "detect_secrets.filters.heuristic.is_likely_id_string",
            "detect_secrets.filters.heuristic.is_templated_secret",
            "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign",
            "detect_secrets.filters.heuristic.is_not_alphanumeric_string",
        ]
        result = rs.get_filters_with_parameter(all_filters, ["secret"])
        assert isinstance(result, list)
        assert len(result) > 0

    def test_filename_parameter(self):
        all_filters = [
            "detect_secrets.filters.heuristic.is_lock_file",
            "detect_secrets.filters.heuristic.is_swagger_file",
            "detect_secrets.filters.heuristic.is_non_text_file",
        ]
        result = rs.get_filters_with_parameter(all_filters, ["filename"])
        assert isinstance(result, list)
        assert len(result) > 0
