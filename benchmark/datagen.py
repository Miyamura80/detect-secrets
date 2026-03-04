"""Synthetic test data generation with seeded RNG for reproducibility."""
import base64
import json
import os
import random
import shutil
import string
import tempfile
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple


class DataGen:
    """Deterministic test data generator."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)
        self._tmpdir: Optional[str] = None

    @property
    def tmpdir(self) -> str:
        if self._tmpdir is None:
            self._tmpdir = tempfile.mkdtemp(prefix='bench_ds_')
        return self._tmpdir

    def cleanup(self) -> None:
        if self._tmpdir and os.path.exists(self._tmpdir):
            shutil.rmtree(self._tmpdir)
            self._tmpdir = None

    # ── String generators ──

    def random_base64_string(self, length: int = 40) -> str:
        chars = string.ascii_letters + string.digits + '+/='
        return ''.join(self.rng.choice(chars) for _ in range(length))

    def random_hex_string(self, length: int = 40) -> str:
        return ''.join(self.rng.choice('0123456789abcdef') for _ in range(length))

    def random_numeric_string(self, length: int = 20) -> str:
        return ''.join(self.rng.choice(string.digits) for _ in range(length))

    def random_alnum_string(self, length: int = 20) -> str:
        return ''.join(self.rng.choice(string.ascii_letters + string.digits) for _ in range(length))

    def fake_aws_key(self) -> str:
        prefix = self.rng.choice(['AKIA', 'ASIA'])
        return prefix + ''.join(self.rng.choice(string.ascii_uppercase + string.digits) for _ in range(16))

    def fake_aws_secret(self) -> str:
        chars = string.ascii_letters + string.digits + '+/'
        return ''.join(self.rng.choice(chars) for _ in range(40))

    def fake_github_token(self) -> str:
        prefix = self.rng.choice(['ghp', 'gho', 'ghu', 'ghs', 'ghr'])
        return prefix + '_' + ''.join(self.rng.choice(string.ascii_letters + string.digits + '_') for _ in range(36))

    def fake_private_key_header(self) -> str:
        key_types = [
            'BEGIN RSA PRIVATE KEY',
            'BEGIN EC PRIVATE KEY',
            'BEGIN DSA PRIVATE KEY',
            'BEGIN OPENSSH PRIVATE KEY',
            'BEGIN PGP PRIVATE KEY BLOCK',
            'BEGIN PRIVATE KEY',
        ]
        return '-----' + self.rng.choice(key_types) + '-----'

    def fake_basic_auth_url(self) -> str:
        user = self.random_alnum_string(8)
        password = self.random_alnum_string(16)
        host = self.random_alnum_string(10).lower()
        return f'https://{user}:{password}@{host}.example.com/api'

    def fake_slack_token(self) -> str:
        prefix = self.rng.choice(['xoxb', 'xoxp', 'xoxa', 'xoxo', 'xoxs', 'xoxr'])
        parts = '-'.join(str(self.rng.randint(100000000, 999999999)) for _ in range(3))
        suffix = ''.join(self.rng.choice(string.ascii_lowercase + string.digits) for _ in range(12))
        return f'{prefix}-{parts}-{suffix}'

    def fake_stripe_key(self) -> str:
        prefix = self.rng.choice(['sk_live', 'rk_live'])
        return prefix + '_' + ''.join(self.rng.choice(string.ascii_letters + string.digits) for _ in range(24))

    def fake_jwt_token(self) -> str:
        header = base64.urlsafe_b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({'sub': '1234567890', 'name': 'Test'}).encode()).rstrip(b'=').decode()
        sig = ''.join(self.rng.choice(string.ascii_letters + string.digits + '-_') for _ in range(43))
        return f'{header}.{payload}.{sig}'

    def fake_password_assignment(self, lang: str = 'py') -> str:
        var_name = self.rng.choice(['password', 'secret', 'api_key', 'auth_key', 'private_key', 'db_pass'])
        value = self.random_alnum_string(20)
        if lang in ('py', 'env'):
            return f'{var_name} = "{value}"'
        elif lang == 'js':
            return f'const {var_name} = "{value}";'
        elif lang == 'yaml':
            return f'{var_name}: "{value}"'
        return f'{var_name} = "{value}"'

    # ── Line generators ──

    _PYTHON_TEMPLATES = [
        'import {mod}',
        'from {mod} import {name}',
        'def {name}({args}):',
        '    return {name}({args})',
        '    {var} = {val}',
        '    if {var} > {val}:',
        '    for {var} in range({val}):',
        '    print({var})',
        'class {Name}:',
        '    def __init__(self):',
        '    self.{var} = {val}',
        '# {comment}',
        '    raise ValueError("{comment}")',
        '    try:',
        '    except Exception as e:',
        '    with open("{name}") as f:',
        '    {var} = [{val}, {val2}]',
        '    {var} = {{{key}: {val}}}',
        '    logger.info("{comment}")',
        '    assert {var} == {val}',
    ]

    _YAML_TEMPLATES = [
        '{key}: {val}',
        '  {key}: {val}',
        '    - {val}',
        '# {comment}',
        '{key}:',
        '  - name: {name}',
        '    value: {val}',
        '  {key}: "{val}"',
        '---',
        'apiVersion: v1',
        'kind: {Name}',
        'metadata:',
        '  name: {name}',
        '  namespace: {name}',
        'spec:',
        '  replicas: {val}',
        '  selector:',
        '    matchLabels:',
        '      app: {name}',
        '  template:',
    ]

    _JS_TEMPLATES = [
        'import {{ {name} }} from "{mod}";',
        'const {var} = require("{mod}");',
        'function {name}({args}) {{',
        '  return {name}({args});',
        '  const {var} = {val};',
        '  let {var} = {val};',
        '  if ({var} > {val}) {{',
        '  for (let i = 0; i < {val}; i++) {{',
        '  console.log({var});',
        'class {Name} {{',
        '  constructor() {{',
        '  this.{var} = {val};',
        '// {comment}',
        '  throw new Error("{comment}");',
        '  try {{',
        '  }} catch (e) {{',
        '  const {var} = [{val}, {val2}];',
        '  const {var} = {{ {key}: {val} }};',
        'export default {Name};',
        'module.exports = {{ {name} }};',
    ]

    _ENV_TEMPLATES = [
        '{KEY}={val}',
        '# {comment}',
        '{KEY}="{val}"',
        '{KEY}={val}',
        'export {KEY}={val}',
        '{KEY}=http://localhost:{port}',
        '{KEY}=true',
        '{KEY}=false',
        '{KEY}={val}',
        '{KEY}={val}',
    ]

    _MODULES = ['os', 'sys', 'json', 'math', 'time', 'logging', 'pathlib', 'hashlib', 'datetime', 'collections']
    _NAMES = ['process', 'handle', 'compute', 'validate', 'transform', 'parse', 'render', 'fetch', 'save', 'load']
    _VARS = ['result', 'data', 'value', 'item', 'count', 'index', 'output', 'status', 'config', 'response']
    _COMMENTS = [
        'TODO: refactor this', 'This is a placeholder', 'Handle edge case',
        'Performance optimization needed', 'Temporary workaround', 'See issue #1234',
        'Initialize the handler', 'Process the request', 'Validate input', 'Clean up resources',
    ]

    def _fill_template(self, template: str) -> str:
        """Fill a template with random plausible values."""
        return template.format(
            mod=self.rng.choice(self._MODULES),
            name=self.rng.choice(self._NAMES),
            Name=self.rng.choice(self._NAMES).capitalize(),
            args=', '.join(self.rng.sample(self._VARS, self.rng.randint(0, 3))),
            var=self.rng.choice(self._VARS),
            val=self.rng.randint(0, 1000),
            val2=self.rng.randint(0, 1000),
            key=self.rng.choice(self._VARS),
            KEY=self.rng.choice(self._VARS).upper(),
            comment=self.rng.choice(self._COMMENTS),
            port=self.rng.randint(3000, 9999),
        )

    def normal_code_line(self, lang: str = 'py') -> str:
        templates = {
            'py': self._PYTHON_TEMPLATES,
            'yaml': self._YAML_TEMPLATES,
            'js': self._JS_TEMPLATES,
            'env': self._ENV_TEMPLATES,
        }
        return self._fill_template(self.rng.choice(templates.get(lang, self._PYTHON_TEMPLATES)))

    def secret_line(self, lang: str = 'py') -> str:
        """Generate a line containing a secret appropriate for the language."""
        generators = [
            lambda: self.fake_password_assignment(lang),
            lambda: f'# AWS Key: {self.fake_aws_key()}',
            lambda: f'token = "{self.fake_github_token()}"' if lang == 'py' else f'token: "{self.fake_github_token()}"',
            lambda: self.fake_private_key_header(),
            lambda: f'url = "{self.fake_basic_auth_url()}"' if lang in ('py', 'js') else f'url: "{self.fake_basic_auth_url()}"',
            lambda: f'slack_token = "{self.fake_slack_token()}"' if lang == 'py' else f'slack_token: "{self.fake_slack_token()}"',
            lambda: f'stripe_key = "{self.fake_stripe_key()}"' if lang == 'py' else f'stripe_key: "{self.fake_stripe_key()}"',
            lambda: f'ENTROPY_STRING = "{self.random_base64_string(40)}"',
        ]
        return self.rng.choice(generators)()

    # ── File generators ──

    def generate_file(self, lang: str, num_lines: int, secret_density: float = 0.02) -> str:
        """Generate a file with given line count and secret density. Returns the file path."""
        ext_map = {'py': '.py', 'yaml': '.yaml', 'js': '.js', 'env': '.env'}
        ext = ext_map.get(lang, '.txt')
        filepath = os.path.join(self.tmpdir, f'bench_{self.rng.randint(0, 999999):06d}{ext}')

        lines = []
        for _ in range(num_lines):
            if self.rng.random() < secret_density:
                lines.append(self.secret_line(lang))
            else:
                lines.append(self.normal_code_line(lang))

        with open(filepath, 'w') as f:
            f.write('\n'.join(lines) + '\n')

        return filepath

    def generate_repo(self, num_files: int) -> str:
        """Generate a synthetic repo directory with mixed file types. Returns the directory path."""
        repo_dir = os.path.join(self.tmpdir, f'repo_{self.rng.randint(0, 999999):06d}')
        os.makedirs(repo_dir, exist_ok=True)

        # Create a plausible directory structure
        subdirs = ['src', 'lib', 'config', 'tests', 'src/utils', 'src/core', 'lib/helpers']
        for subdir in subdirs:
            os.makedirs(os.path.join(repo_dir, subdir), exist_ok=True)

        lang_weights = [('py', 0.35), ('js', 0.30), ('yaml', 0.20), ('env', 0.15)]
        langs = [l for l, _ in lang_weights]
        weights = [w for _, w in lang_weights]

        ext_map = {'py': '.py', 'yaml': '.yaml', 'js': '.js', 'env': '.env'}
        dir_by_lang = {
            'py': ['src', 'src/utils', 'src/core', 'tests'],
            'js': ['src', 'src/utils', 'lib', 'lib/helpers'],
            'yaml': ['config', '.'],
            'env': ['.'],
        }

        for i in range(num_files):
            lang = self.rng.choices(langs, weights=weights, k=1)[0]
            subdir = self.rng.choice(dir_by_lang[lang])
            ext = ext_map[lang]
            filename = f'file_{i:04d}{ext}'
            filepath = os.path.join(repo_dir, subdir, filename)

            # Varying file sizes: mostly small, some large
            num_lines = self.rng.choice([50, 100, 200, 500, 100, 100])

            lines = []
            for _ in range(num_lines):
                if self.rng.random() < 0.02:
                    lines.append(self.secret_line(lang))
                else:
                    lines.append(self.normal_code_line(lang))

            with open(filepath, 'w') as f:
                f.write('\n'.join(lines) + '\n')

        return repo_dir

    # ── Batch generators for microbenchmarks ──

    def generate_base64_strings(self, count: int, length: int) -> List[str]:
        return [self.random_base64_string(length) for _ in range(count)]

    def generate_hex_strings(self, count: int, length: int) -> List[str]:
        return [self.random_hex_string(length) for _ in range(count)]

    def generate_numeric_strings(self, count: int, length: int) -> List[str]:
        return [self.random_numeric_string(length) for _ in range(count)]

    def generate_matching_lines(self, plugin_name: str, count: int) -> List[str]:
        """Generate lines that should match a given plugin."""
        generators: Dict[str, callable] = {
            'AWSKeyDetector': lambda: f'aws_key = "{self.fake_aws_key()}"',
            'KeywordDetector': lambda: self.fake_password_assignment('py'),
            'GitHubTokenDetector': lambda: f'token = "{self.fake_github_token()}"',
            'PrivateKeyDetector': lambda: self.fake_private_key_header(),
            'BasicAuthDetector': lambda: self.fake_basic_auth_url(),
            'SlackDetector': lambda: self.fake_slack_token(),
            'StripeDetector': lambda: self.fake_stripe_key(),
            'JwtTokenDetector': lambda: self.fake_jwt_token(),
            'Base64HighEntropyString': lambda: f'secret = "{self.random_base64_string(40)}"',
            'HexHighEntropyString': lambda: f'token = "{self.random_hex_string(40)}"',
        }
        gen = generators.get(plugin_name, lambda: f'secret = "{self.random_alnum_string(20)}"')
        return [gen() for _ in range(count)]

    def generate_nonmatching_lines(self, count: int) -> List[str]:
        """Generate lines that should not match any plugin (clean code)."""
        return [self.normal_code_line('py') for _ in range(count)]

    # ── Baseline data generators ──

    def generate_secrets_baseline(self, num_secrets: int, num_files: int) -> Dict:
        """Generate a synthetic baseline dict for serde benchmarks."""
        import hashlib
        results: Dict[str, List] = {}
        secret_types = [
            'AWS Access Key', 'Secret Keyword', 'GitHub Token',
            'Private Key', 'Base64 High Entropy String', 'Hex High Entropy String',
        ]

        files = [f'src/file_{i:04d}.py' for i in range(num_files)]
        secrets_per_file = max(1, num_secrets // num_files)

        for filename in files:
            file_secrets = []
            for j in range(secrets_per_file):
                secret_val = self.random_alnum_string(30)
                file_secrets.append({
                    'type': self.rng.choice(secret_types),
                    'filename': filename,
                    'hashed_secret': hashlib.sha1(secret_val.encode()).hexdigest(),
                    'is_verified': False,
                    'line_number': self.rng.randint(1, 500),
                })
            results[filename] = file_secrets

        from detect_secrets.__version__ import VERSION
        return {
            'version': VERSION,
            'plugins_used': [
                {'name': 'AWSKeyDetector'},
                {'name': 'Base64HighEntropyString', 'limit': 4.5},
                {'name': 'HexHighEntropyString', 'limit': 3.0},
                {'name': 'KeywordDetector'},
                {'name': 'PrivateKeyDetector'},
                {'name': 'GitHubTokenDetector'},
            ],
            'filters_used': [
                {'path': 'detect_secrets.filters.allowlist.is_line_allowlisted'},
                {'path': 'detect_secrets.filters.heuristic.is_sequential_string'},
                {'path': 'detect_secrets.filters.heuristic.is_potential_uuid'},
                {'path': 'detect_secrets.filters.heuristic.is_likely_id_string'},
                {'path': 'detect_secrets.filters.heuristic.is_templated_secret'},
                {'path': 'detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign'},
                {'path': 'detect_secrets.filters.heuristic.is_indirect_reference'},
                {'path': 'detect_secrets.filters.heuristic.is_lock_file'},
                {'path': 'detect_secrets.filters.heuristic.is_not_alphanumeric_string'},
                {'path': 'detect_secrets.filters.heuristic.is_swagger_file'},
            ],
            'results': results,
            'generated_at': '2026-01-01T00:00:00Z',
        }
