"""Plugin tests for detect_secrets_rs — ported from Yelp/detect-secrets test suite.

Each test verifies that the Rust plugin produces the same matches as the Python
original for known inputs.
"""
import pytest
import detect_secrets_rs as rs


def _t(*parts):
    """Assemble test token from parts to avoid GitHub push-protection false positives."""
    return "".join(parts)


# ---------------------------------------------------------------------------
# AWS Key Detector
# ---------------------------------------------------------------------------

class TestAWSKeyDetector:
    EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    @pytest.fixture
    def plugin(self):
        return rs.AWSKeyDetector()

    @pytest.mark.parametrize("line,should_flag", [
        ("AKIAZZZZZZZZZZZZZZZZ", True),
        ("akiazzzzzzzzzzzzzzzz", False),
        ("AKIZZ", False),
        ("A3T0ZZZZZZZZZZZZZZZZ", True),
        ("ABIAZZZZZZZZZZZZZZZZ", True),
        ("ACCAZZZZZZZZZZZZZZZZ", True),
        ("ASIAZZZZZZZZZZZZZZZZ", True),
    ])
    def test_access_key_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag

    @pytest.mark.parametrize("line,should_flag", [
        ('aws_access_key = "{}"'.format(EXAMPLE_SECRET), True),
        ('aws_access_key = "{}"'.format(EXAMPLE_SECRET + "a"), False),
        ('aws_access_key = "{}"'.format(EXAMPLE_SECRET[0:39]), False),
    ])
    def test_secret_access_key_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Azure Storage Key Detector
# ---------------------------------------------------------------------------

class TestAzureStorageKeyDetector:
    @pytest.fixture
    def plugin(self):
        return rs.AzureStorageKeyDetector()

    def test_valid_key(self, plugin):
        line = 'AccountKey=' + _t('lJzRc1YdHaAA2KCNJJ1tkYwF/', '+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==')
        results = plugin.analyze_string(line)
        assert len(results) > 0


# ---------------------------------------------------------------------------
# Artifactory Detector
# ---------------------------------------------------------------------------

class TestArtifactoryDetector:
    @pytest.fixture
    def plugin(self):
        return rs.ArtifactoryDetector()

    @pytest.mark.parametrize("line,should_flag", [
        ("AP6xxxxxxxxxx", True),
        ("AP2xxxxxxxxxx", True),
        ("AP3xxxxxxxxxx", True),
        ("AP5xxxxxxxxxx", True),
        ("APAxxxxxxxxxx", True),
        ("APBxxxxxxxxxx", True),
        ("AKCxxxxxxxxxx", True),
        ('artif-key:AP6xxxxxxxxxx', True),
        ('X-JFrog-Art-Api: AKCxxxxxxxxxx', True),
        ('"AP6xxxxxxxxxx"', True),
        ("testAKCwithinsomeirrelevantstring", False),
        ("X-JFrog-Art-Api: $API_KEY", False),
        ("artifactory:_password=AP6xxxxxx", False),
        ("artifactory:_password=AKCxxxxxxxx", False),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Basic Auth Detector
# ---------------------------------------------------------------------------

class TestBasicAuthDetector:
    @pytest.fixture
    def plugin(self):
        return rs.BasicAuthDetector()

    @pytest.mark.parametrize("payload,should_flag", [
        ("https://username:password@yelp.com", True),
        ('http://localhost:5000/<%= @variable %>', False),
        ('"https://url:8000";@something else', False),
        ("'https://url:8000';@something else", False),
        ("https://url:8000 @something else", False),
        ("https://url:8000/ @something else", False),
    ])
    def test_detection(self, plugin, payload, should_flag):
        results = plugin.analyze_string(payload)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Cloudant Detector
# ---------------------------------------------------------------------------

class TestCloudantDetector:
    PASSWORD = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

    @pytest.fixture
    def plugin(self):
        return rs.CloudantDetector()

    @pytest.mark.parametrize("line,should_flag", [
        ('cloudant_password="{}"'.format(PASSWORD), True),
        ("cloudant_pw='{}'".format(PASSWORD), True),
        ('cloudant_password = "a-fake-tooshort-key"', False),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Discord Bot Token Detector
# ---------------------------------------------------------------------------

class TestDiscordBotTokenDetector:
    @pytest.fixture
    def plugin(self):
        return rs.DiscordBotTokenDetector()

    @pytest.mark.parametrize("token,should_flag", [
        (_t("MTk4NjIyNDgzNDcx", "OTI1MjQ4.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs"), True),
        (_t("Nzk5MjgxNDk0NDc2", "NDU1OTg3.YABS5g.2lmzECVlZv3vv6miVnUaKPQi2wI"), True),
        (_t("MZ1yGvKTjE0rY0cV8i47", "CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC"), True),
        (_t("OTUyNED5MDk2MTMx", "Nzc2MkEz.YjESug.UNf-1GhsIG8zWT409q2C7Bh_zWQ"), True),
        (_t("OTUyNED5MDk2MTMx", "Nzc2MkEz.GSroKE.g2MTwve8OnUAAByz8KV_ZTV1Ipzg4o_NmQWUMs"), True),
        (_t("MTAyOTQ4MTN5OTU5", "MTDwMEcxNg.GSwJyi.sbaw8msOR3Wi6vPUzeIWy_P0vJbB0UuRVjH8l8"), True),
        # Invalid tokens
        ("MZ1yGvKTj0rY0cV8i47CjAa.uHQPq.Xb1Mk2nEhe-4icrGOuegj57zMC", False),  # segments too short
        ("PZ1yGvKTjE0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC", False),  # invalid first char
    ])
    def test_detection(self, plugin, token, should_flag):
        results = plugin.analyze_string(token)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# GitHub Token Detector
# ---------------------------------------------------------------------------

class TestGitHubTokenDetector:
    @pytest.fixture
    def plugin(self):
        return rs.GitHubTokenDetector()

    @pytest.mark.parametrize("payload,should_flag", [
        (_t("ghp_", "wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx"), True),
        ("foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx", False),
        ("foo", False),
    ])
    def test_detection(self, plugin, payload, should_flag):
        results = plugin.analyze_string(payload)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# GitLab Token Detector
# ---------------------------------------------------------------------------

class TestGitLabTokenDetector:
    @pytest.fixture
    def plugin(self):
        return rs.GitLabTokenDetector()

    @pytest.mark.parametrize("token,should_flag", [
        # PAT
        (_t("glpat-", "hellOworld380_testin"), True),
        ("gldt-seems_too000Sshorty", False),
        ("glpat_hellOworld380_testin", False),
        # Runner registration
        (_t("GR1348941", "PREfix_helloworld380"), True),
        ("GR1348941helloWord0", False),
        # CI/CD (requires hex partition prefix, e.g. "64_")
        (_t("glcbt-", "64_helloworld380_testin"), True),
        # Incoming mail
        (_t("glimt-", "my-tokens_are-correctAB38"), True),
        ("glimt-my-tokens_are-correctAB", False),
        # Trigger
        (_t("glptt-", "Need5_T00-be-exactly-40-chars--ELse_fail"), True),
        # Agent
        (_t("glagent-", "Need5_T00-bee-longer-than-50_chars-or-else-failING"), True),
        ("glagent-hellOworld380_testin", False),
        # OAuth
        (_t("gloas-", "checking_Length-Is-_exactly_64--checking_Length-Is-_exactly_64--"), True),
    ])
    def test_detection(self, plugin, token, should_flag):
        results = plugin.analyze_string(token)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# High Entropy Strings
# ---------------------------------------------------------------------------

class TestHexHighEntropyString:
    @pytest.fixture
    def plugin(self):
        return rs.HexHighEntropyString()

    def test_non_secret(self, plugin):
        results = plugin.analyze_string('"aaaaaa"')
        assert len(results) == 0

    def test_secret(self, plugin):
        results = plugin.analyze_string('"2b00042f7481c7b056c4b410d28f33cf"')
        assert len(results) > 0


class TestBase64HighEntropyString:
    @pytest.fixture
    def plugin(self):
        return rs.Base64HighEntropyString()

    def test_non_secret(self, plugin):
        results = plugin.analyze_string('"c3VwZXIgc2VjcmV0IHZhbHVl"')
        assert len(results) == 0

    def test_secret(self, plugin):
        results = plugin.analyze_string('"c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5"')
        assert len(results) > 0

    def test_url_safe_base64_secret(self, plugin):
        results = plugin.analyze_string(
            '"I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_f-pTAuoX2U="'
        )
        assert len(results) > 0

    def test_no_quotes_no_match(self, plugin):
        results = plugin.analyze_string(
            "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5"
        )
        assert len(results) == 0

    def test_multiple_strings(self, plugin):
        non_secret = "c3VwZXIgc2VjcmV0IHZhbHVl"
        secret = "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5"
        line = 'String #1: "{}"; String #2: "{}"'.format(non_secret, secret)
        results = plugin.analyze_string(line)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# IBM Cloud IAM Detector
# ---------------------------------------------------------------------------

class TestIbmCloudIamDetector:
    KEY = "abcd1234abcd1234abcd1234ABCD1234ABCD1234--__"

    @pytest.fixture
    def plugin(self):
        return rs.IbmCloudIamDetector()

    @pytest.mark.parametrize("line,should_flag", [
        ('ibm-cloud_api_key: {}'.format(KEY), True),
        ('IBM-API-KEY : "{}"'.format(KEY), True),
        ('iam_api_key="{}"'.format(KEY), True),
        ('ibm_api_key := {}'.format(KEY), True),
        ('ibm_iam_key:= "insert_key_here"', False),  # too short
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# IBM COS HMAC Detector
# ---------------------------------------------------------------------------

class TestIbmCosHmacDetector:
    SECRET = "1234567890abcdef1234567890abcdef1234567890abcdef"

    @pytest.fixture
    def plugin(self):
        return rs.IbmCosHmacDetector()

    @pytest.mark.parametrize("line,should_flag", [
        ('"secret_access_key": "{}"'.format(SECRET), True),
        ('secret_access_key="{}"'.format(SECRET), True),
        ("secret_access_key='{}'".format(SECRET), True),
        ('not_secret = notapassword', False),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# JWT Token Detector
# ---------------------------------------------------------------------------

class TestJwtTokenDetector:
    @pytest.fixture
    def plugin(self):
        return rs.JwtTokenDetector()

    @pytest.mark.parametrize("payload,should_flag", [
        # Valid JWTs
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", True),
        # Header with CR/LF
        ("eyJ0eXAiOiJKV1QiLA0KImFsZyI6IkhTMjU2In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", True),
        # Claims with newlines
        ("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9lIiwKInN0YXR1cyI6ImVtcGxveWVlIgp9", True),
        # Claims with unicode
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IsWww6HFkcOtIMOWxZHDqcOoIiwiaWF0IjoxNTE2MjM5MDIyfQ.k5HibI_uLn_RTuPcaCNkaVaQH2y5q6GvJg8GPpGMRwQ", True),
        # No signature
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", True),
        # Invalid JWTs
        ('{"alg":"HS256","typ":"JWT"}.{"name":"Jon Doe"}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', False),
        ("bm90X3ZhbGlkX2pzb25fYXRfYWxs.bm90X3ZhbGlkX2pzb25fYXRfYWxs.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", False),
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", False),
        ("jwt", False),
    ])
    def test_detection(self, plugin, payload, should_flag):
        results = plugin.analyze_string(payload)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Keyword Detector
# ---------------------------------------------------------------------------

class TestKeywordDetector:
    COMMON_SECRET = "m{{h}o)p${e]nob(ody[finds>-_$#thisone}}"
    WHITES_SECRET = "value with quotes and spaces"

    @pytest.fixture
    def plugin(self):
        return rs.KeywordDetector()

    @pytest.mark.parametrize("line,should_flag", [
        # Config / INI style (no specific file type)
        ('password = "{}"'.format(WHITES_SECRET), True),
        ('apikey = {}'.format(COMMON_SECRET), True),
        ("api_key: '{}'".format(WHITES_SECRET), True),
        ('aws_secret_access_key: {}'.format(WHITES_SECRET), True),
        # These are filtered at the scan pipeline level (not by analyze_line):
        # 'password = "somefakekey"' → filtered by keyword_exclude heuristic
        # 'password: ${link}' → filtered by is_templated_secret
        # The plugin itself DOES match, but the pipeline filters them out.
        ('some_key = "real_secret"', False),
        ('api_key = ""', False),
        ("secret: ''", False),
    ])
    def test_config_detection(self, plugin, line, should_flag):
        # analyze_line(filename, line, line_number)
        results = plugin.analyze_line("config.ini", line, 1)
        assert bool(results) == should_flag

    def test_go_detection(self, plugin):
        results = plugin.analyze_line(
            "main.go",
            'apikey := "{}"'.format(self.COMMON_SECRET),
            1,
        )
        assert len(results) > 0

    def test_symbol_only_no_match(self, plugin):
        results = plugin.analyze_line(
            "config.ini",
            'password = ,.:-\u00a8@*\u00bf?!',
            1,
        )
        assert len(results) == 0


# ---------------------------------------------------------------------------
# Private Key Detector
# ---------------------------------------------------------------------------

class TestPrivateKeyDetector:
    @pytest.fixture
    def plugin(self):
        return rs.PrivateKeyDetector()

    def test_rsa_private_key(self, plugin):
        results = plugin.analyze_string("-----BEGIN RSA PRIVATE KEY-----")
        assert len(results) > 0

    def test_generic_private_key(self, plugin):
        results = plugin.analyze_string("-----BEGIN PRIVATE KEY-----")
        assert len(results) > 0

    def test_no_match(self, plugin):
        results = plugin.analyze_string("-----BEGIN PUBLIC KEY-----")
        assert len(results) == 0


# ---------------------------------------------------------------------------
# Mailchimp Detector
# ---------------------------------------------------------------------------

class TestMailchimpDetector:
    @pytest.fixture
    def plugin(self):
        return rs.MailchimpDetector()

    @pytest.mark.parametrize("line,should_flag", [
        (_t("343ea45721923ed9", "56e2b38c31db76aa-us30"), True),
        (_t("a2937653ed38c31a", "43ea46e2b19257db-us2"), True),
        (_t("3ea4572956e2b381", "923ed34c31db76aa-2"), False),
        (_t("9276a43e2951aa46", "e2b1c33ED38357DB-us2"), False),  # uppercase
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# NPM Detector
# ---------------------------------------------------------------------------

class TestNpmDetector:
    @pytest.fixture
    def plugin(self):
        return rs.NpmDetector()

    @pytest.mark.parametrize("line,should_flag", [
        (_t("//registry.npmjs.org/:_authToken=", "743b294a-cd03-11ec-9d64-0242ac120002"), True),
        (_t("//registry.npmjs.org/:_authToken=", "npm_xxxxxxxxxxx"), True),
        ("registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002", False),
        ("//registry.npmjs.org/:_authToken=${NPM_TOKEN}", False),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# OpenAI Detector
# ---------------------------------------------------------------------------

class TestOpenAIDetector:
    @pytest.fixture
    def plugin(self):
        return rs.OpenAIDetector()

    @pytest.mark.parametrize("line,should_flag", [
        (_t("sk-Xi8tcNiHV9awbCcvilTe", "T3BlbkFJ3UDnpdEwNNm6wVBpYM0o"), True),
        (_t("sk-proj-Xi8tdMjHV6pmbBbwilTe", "T3BlbkFJ3UDnpdEwNNm6wVBpYM0o"), True),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# PyPI Token Detector
# ---------------------------------------------------------------------------

class TestPypiTokenDetector:
    @pytest.fixture
    def plugin(self):
        return rs.PypiTokenDetector()

    def test_valid_token(self, plugin):
        token = _t("pypi-AgEIcHlwaS5vcmcCJDU3OTM1MjliLWIyYTYtNDEwOC05NzRk", "LTM0MjNiNmEwNWIzYgACF1sxLFsitesttestbWluaW1hbC1wcm9qZWN0Il1dAAIsWzIsWyJjYWY4OTAwZi0xNDMwLTRiYQstYmFmMi1mMDE3OGIyNWZhNTkiXV0AAAYgh2UINPjWBDwT0r3tQ1o5oZyswcjN0-IluP6z34SX3KM")
        results = plugin.analyze_string(token)
        assert len(results) > 0


# ---------------------------------------------------------------------------
# SendGrid Detector
# ---------------------------------------------------------------------------

class TestSendGridDetector:
    @pytest.fixture
    def plugin(self):
        return rs.SendGridDetector()

    @pytest.mark.parametrize("line,should_flag", [
        (_t("SG.ngeVfQFYQlKU0ufo8x5d1A", ".TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr"), True),
        ("SG.ngeVfQFYQlKU0ufo8x5d1A..TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr", False),
        ("AG.ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr", False),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Slack Detector
# ---------------------------------------------------------------------------

class TestSlackDetector:
    @pytest.fixture
    def plugin(self):
        return rs.SlackDetector()

    @pytest.mark.parametrize("line", [
        _t("xoxp-", "523423-234243-234233-e039d02840a0b9379c"),
        _t("xoxo-", "523423-234243-234233-e039d02840a0b9379c"),
        _t("xoxs-", "523423-234243-234233-e039d02840a0b9379c"),
        _t("xoxa-", "511111111-31111111111-3111111111111-e039d02840a0b9379c"),
        _t("xoxa-2-", "511111111-31111111111-3111111111111-e039d02840a0b9379c"),
        _t("xoxr-", "523423-234243-234233-e039d02840a0b9379c"),
        _t("xoxb-", "34532454-e039d02840a0b9379c"),
        _t("https://hooks.slack.com/", "services/Txxxxxxxx/Bxxxxxxxx/xxxxxxxxxxxxxxxxxxxxxxxx"),
    ])
    def test_valid_tokens(self, plugin, line):
        results = plugin.analyze_string(line)
        assert len(results) > 0, f"Should detect Slack token in: {line}"


# ---------------------------------------------------------------------------
# Softlayer Detector
# ---------------------------------------------------------------------------

class TestSoftlayerDetector:
    TOKEN = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

    @pytest.fixture
    def plugin(self):
        return rs.SoftlayerDetector()

    @pytest.mark.parametrize("line,should_flag", [
        ('softlayer_api_key: {}'.format(TOKEN), True),
        ('softlayer-key : {}'.format(TOKEN), True),
        ("sl_api_key='{}'".format(TOKEN), True),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Square OAuth Detector
# ---------------------------------------------------------------------------

class TestSquareOAuthDetector:
    @pytest.fixture
    def plugin(self):
        return rs.SquareOAuthDetector()

    def test_valid_token(self, plugin):
        results = plugin.analyze_string(
            r"sq0csp-ABCDEFGHIJK_LMNOPQRSTUVWXYZ-0123456789\abcd"
        )
        assert len(results) > 0


# ---------------------------------------------------------------------------
# Stripe Detector
# ---------------------------------------------------------------------------

class TestStripeDetector:
    @pytest.fixture
    def plugin(self):
        return rs.StripeDetector()

    @pytest.mark.parametrize("line,should_flag", [
        (_t("sk_live_", "ReTllpYQYfIZu2Jnf2lAPFjD"), True),
        (_t("rk_live_", "5TcWfjKmJgpql9hjpRnwRXbT"), True),
        ("pk_live_j5krY8XTgIcDaHDb3YrsAfCl", False),
        ("sk_live_", False),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Telegram Bot Token Detector
# ---------------------------------------------------------------------------

class TestTelegramBotTokenDetector:
    @pytest.fixture
    def plugin(self):
        return rs.TelegramBotTokenDetector()

    @pytest.mark.parametrize("line,should_flag", [
        (_t("110201543:", "AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw"), True),
        (_t("7213808860:", "AAH1bjqpKKW3maRSPAxzIU-0v6xNuq2-NjM"), True),
        ("bot110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw", False),
        ("foo:AAH1bjqpKKW3maRSPAxzIU-0v6xNuq2-NjM", False),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Twilio Key Detector
# ---------------------------------------------------------------------------

class TestTwilioKeyDetector:
    @pytest.fixture
    def plugin(self):
        return rs.TwilioKeyDetector()

    @pytest.mark.parametrize("line,should_flag", [
        ("SK" + "x" * 32, True),
        ("AC" + "x" * 32, True),
    ])
    def test_detection(self, plugin, line, should_flag):
        results = plugin.analyze_string(line)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# IP Public Detector
# ---------------------------------------------------------------------------

class TestIPPublicDetector:
    @pytest.fixture
    def plugin(self):
        return rs.IPPublicDetector()

    @pytest.mark.parametrize("payload,should_flag", [
        # Valid public IPs
        ("133.133.133.133", True),
        ("This line has an IP address 133.133.133.133@something else", True),
        ("133.133.133.133:8080", True),
        ("1.1.1.1", True),
        # Private / reserved IPs
        ("127.0.0.1", False),
        ("10.0.0.1", False),
        ("172.16.0.1", False),
        ("192.168.0.1", False),
        ("169.254.169.254", False),
        # Invalid
        ("256.256.256.256", False),
        ("1.2.3", False),
        ("1.2.3.04", False),
        ("noreply@github.com", False),
    ])
    def test_detection(self, plugin, payload, should_flag):
        results = plugin.analyze_string(payload)
        assert bool(results) == should_flag


# ---------------------------------------------------------------------------
# Plugin JSON output
# ---------------------------------------------------------------------------

class TestPluginJSON:
    """Verify each plugin produces valid JSON configuration."""

    @pytest.mark.parametrize("plugin_class", [
        rs.AWSKeyDetector,
        rs.AzureStorageKeyDetector,
        rs.ArtifactoryDetector,
        rs.BasicAuthDetector,
        rs.CloudantDetector,
        rs.DiscordBotTokenDetector,
        rs.GitHubTokenDetector,
        rs.GitLabTokenDetector,
        rs.HexHighEntropyString,
        rs.Base64HighEntropyString,
        rs.IbmCloudIamDetector,
        rs.IbmCosHmacDetector,
        rs.JwtTokenDetector,
        rs.KeywordDetector,
        rs.MailchimpDetector,
        rs.NpmDetector,
        rs.OpenAIDetector,
        rs.PrivateKeyDetector,
        rs.PypiTokenDetector,
        rs.SendGridDetector,
        rs.SlackDetector,
        rs.SoftlayerDetector,
        rs.SquareOAuthDetector,
        rs.StripeDetector,
        rs.TelegramBotTokenDetector,
        rs.TwilioKeyDetector,
        rs.IPPublicDetector,
    ])
    def test_json_output(self, plugin_class):
        plugin = plugin_class()
        j = plugin.json()
        assert "name" in j
        assert isinstance(j["name"], str)


# ---------------------------------------------------------------------------
# Plugin secret_type
# ---------------------------------------------------------------------------

class TestPluginSecretType:
    """Verify each plugin has a non-empty secret_type."""

    @pytest.mark.parametrize("plugin_class", [
        rs.AWSKeyDetector,
        rs.BasicAuthDetector,
        rs.PrivateKeyDetector,
        rs.JwtTokenDetector,
        rs.KeywordDetector,
        rs.HexHighEntropyString,
        rs.Base64HighEntropyString,
        rs.SlackDetector,
        rs.StripeDetector,
        rs.GitHubTokenDetector,
    ])
    def test_secret_type(self, plugin_class):
        plugin = plugin_class()
        assert isinstance(plugin.secret_type, str)
        assert len(plugin.secret_type) > 0
