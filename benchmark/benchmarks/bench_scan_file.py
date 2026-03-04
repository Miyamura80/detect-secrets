"""Mid-level benchmark: single file scanning (all plugins + filters)."""
from typing import List

from benchmark.datagen import DataGen
from benchmark.timing import BenchmarkResult
from benchmark.timing import time_func

# (lang, num_lines) for each size tier
FILE_CONFIGS = {
    'small': [('py', 100), ('yaml', 100), ('js', 100), ('env', 100)],
    'medium': [('py', 1000), ('yaml', 1000), ('js', 1000), ('env', 1000)],
    'large': [('py', 10000), ('yaml', 10000), ('js', 10000), ('env', 10000)],
}


def run(iterations: int = 5, sizes: List[str] = None) -> List[BenchmarkResult]:
    from detect_secrets.core.scan import scan_file
    from detect_secrets.settings import default_settings

    if sizes is None:
        sizes = ['small', 'medium', 'large']

    gen = DataGen(seed=42)
    results = []

    try:
        for size_name in sizes:
            for lang, num_lines in FILE_CONFIGS.get(size_name, []):
                filepath = gen.generate_file(lang, num_lines, secret_density=0.02)

                def run_scan(path=filepath):
                    with default_settings():
                        secrets = list(scan_file(path))

                timings = time_func(run_scan, iterations)

                # Count secrets found in one pass for reporting
                with default_settings():
                    secret_count = len(list(scan_file(filepath)))

                results.append(BenchmarkResult(
                    name=f'scan_file_{lang}_{size_name}',
                    count=num_lines,
                    iterations=iterations,
                    timings=timings,
                    extra={
                        'lang': lang,
                        'num_lines': num_lines,
                        'secrets_found': secret_count,
                    },
                ))
    finally:
        gen.cleanup()

    return results
