"""Microbenchmark: Shannon entropy calculation."""
from typing import List

from benchmark.datagen import DataGen
from benchmark.timing import BenchmarkResult
from benchmark.timing import time_func

# Size tiers: (string_length, count)
SIZE_TIERS = {
    'small': [(32, 10000)],
    'medium': [(128, 5000)],
    'large': [(512, 1000)],
}


def run(iterations: int = 5, sizes: List[str] = None) -> List[BenchmarkResult]:
    from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
    from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString

    if sizes is None:
        sizes = ['small', 'medium', 'large']

    gen = DataGen(seed=42)
    results = []

    base64_plugin = Base64HighEntropyString()
    hex_plugin = HexHighEntropyString()

    for size_name in sizes:
        for str_length, count in SIZE_TIERS.get(size_name, []):
            # Base64 entropy
            b64_strings = gen.generate_base64_strings(count, str_length)

            def run_base64(strings=b64_strings, plugin=base64_plugin):
                for s in strings:
                    plugin.calculate_shannon_entropy(s)

            timings = time_func(run_base64, iterations)
            results.append(BenchmarkResult(
                name=f'entropy_base64_{size_name}',
                count=count,
                iterations=iterations,
                timings=timings,
                extra={'string_length': str_length},
            ))

            # Hex entropy
            hex_strings = gen.generate_hex_strings(count, str_length)

            def run_hex(strings=hex_strings, plugin=hex_plugin):
                for s in strings:
                    plugin.calculate_shannon_entropy(s)

            timings = time_func(run_hex, iterations)
            results.append(BenchmarkResult(
                name=f'entropy_hex_{size_name}',
                count=count,
                iterations=iterations,
                timings=timings,
                extra={'string_length': str_length},
            ))

            # Hex numeric-only path (triggers the int(data) branch)
            numeric_strings = gen.generate_numeric_strings(count, str_length)

            def run_hex_numeric(strings=numeric_strings, plugin=hex_plugin):
                for s in strings:
                    plugin.calculate_shannon_entropy(s)

            timings = time_func(run_hex_numeric, iterations)
            results.append(BenchmarkResult(
                name=f'entropy_hex_numeric_{size_name}',
                count=count,
                iterations=iterations,
                timings=timings,
                extra={'string_length': str_length},
            ))

    return results
