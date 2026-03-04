"""Microbenchmark: per-plugin regex matching via analyze_string()."""
from typing import List

from benchmark.datagen import DataGen
from benchmark.timing import BenchmarkResult
from benchmark.timing import time_func

PLUGINS_TO_BENCH = [
    'AWSKeyDetector',
    'KeywordDetector',
    'GitHubTokenDetector',
    'PrivateKeyDetector',
    'BasicAuthDetector',
    'SlackDetector',
    'StripeDetector',
    'JwtTokenDetector',
    'Base64HighEntropyString',
    'HexHighEntropyString',
]

LINES_PER_CATEGORY = 1000


def _get_plugin_instance(name: str):
    """Instantiate a plugin by class name."""
    from detect_secrets.plugins.aws import AWSKeyDetector
    from detect_secrets.plugins.basic_auth import BasicAuthDetector
    from detect_secrets.plugins.github_token import GitHubTokenDetector
    from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
    from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
    from detect_secrets.plugins.jwt import JwtTokenDetector
    from detect_secrets.plugins.keyword import KeywordDetector
    from detect_secrets.plugins.private_key import PrivateKeyDetector
    from detect_secrets.plugins.slack import SlackDetector
    from detect_secrets.plugins.stripe import StripeDetector

    mapping = {
        'AWSKeyDetector': AWSKeyDetector,
        'KeywordDetector': KeywordDetector,
        'GitHubTokenDetector': GitHubTokenDetector,
        'PrivateKeyDetector': PrivateKeyDetector,
        'BasicAuthDetector': BasicAuthDetector,
        'SlackDetector': SlackDetector,
        'StripeDetector': StripeDetector,
        'JwtTokenDetector': JwtTokenDetector,
        'Base64HighEntropyString': Base64HighEntropyString,
        'HexHighEntropyString': HexHighEntropyString,
    }
    return mapping[name]()


def run(iterations: int = 5, sizes: List[str] = None) -> List[BenchmarkResult]:
    gen = DataGen(seed=42)
    results = []

    # Pre-generate non-matching lines (shared across all plugins)
    miss_lines = gen.generate_nonmatching_lines(LINES_PER_CATEGORY)

    for plugin_name in PLUGINS_TO_BENCH:
        plugin = _get_plugin_instance(plugin_name)
        match_lines = gen.generate_matching_lines(plugin_name, LINES_PER_CATEGORY)

        # Match path benchmark
        def run_match(lines=match_lines, p=plugin):
            for line in lines:
                list(p.analyze_string(line))

        timings = time_func(run_match, iterations)
        results.append(BenchmarkResult(
            name=f'regex_{plugin_name}_match',
            count=LINES_PER_CATEGORY,
            iterations=iterations,
            timings=timings,
            extra={'plugin': plugin_name, 'path': 'match'},
        ))

        # Miss path benchmark (hot path in real usage)
        def run_miss(lines=miss_lines, p=plugin):
            for line in lines:
                list(p.analyze_string(line))

        timings = time_func(run_miss, iterations)
        results.append(BenchmarkResult(
            name=f'regex_{plugin_name}_miss',
            count=LINES_PER_CATEGORY,
            iterations=iterations,
            timings=timings,
            extra={'plugin': plugin_name, 'path': 'miss'},
        ))

    return results
