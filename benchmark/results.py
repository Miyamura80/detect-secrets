"""JSON aggregation and comparison printer."""
import json
import os
import platform
import sys
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from .timing import BenchmarkResult


def build_output(results: List[BenchmarkResult], backend: str = 'python') -> Dict[str, Any]:
    """Build the final JSON output document."""
    try:
        from detect_secrets.__version__ import VERSION as ds_version
    except ImportError:
        ds_version = 'unknown'

    return {
        'metadata': {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'python_version': platform.python_version(),
            'detect_secrets_version': ds_version,
            'backend': backend,
            'platform': platform.platform(),
            'cpu_count': os.cpu_count(),
        },
        'benchmarks': {
            r.name: r.to_dict()
            for r in results
        },
    }


def save_results(results: List[BenchmarkResult], path: str, backend: str = 'python') -> None:
    output = build_output(results, backend=backend)
    with open(path, 'w') as f:
        json.dump(output, f, indent=2)
        f.write('\n')


def print_results(results: List[BenchmarkResult]) -> None:
    """Print a formatted table of benchmark results."""
    if not results:
        print('No benchmark results.')
        return

    name_width = max(len(r.name) for r in results)
    header = f'{"Benchmark":<{name_width}}  {"Mean":>10}  {"Median":>10}  {"StdDev":>10}  {"Min":>10}  {"Max":>10}  {"Count":>8}'
    print(header)
    print('-' * len(header))

    for r in results:
        s = r.stats
        print(
            f'{r.name:<{name_width}}  '
            f'{s["mean"]:>10.6f}  '
            f'{s["median"]:>10.6f}  '
            f'{s["stddev"]:>10.6f}  '
            f'{s["min"]:>10.6f}  '
            f'{s["max"]:>10.6f}  '
            f'{r.count:>8}'
        )


def compare_results(current: List[BenchmarkResult], old_path: str) -> None:
    """Load a previous results file and print a comparison table."""
    with open(old_path) as f:
        old_data = json.load(f)

    old_benchmarks = old_data.get('benchmarks', {})
    current_map = {r.name: r for r in current}

    all_names = sorted(set(list(old_benchmarks.keys()) + list(current_map.keys())))

    if not all_names:
        print('No benchmarks to compare.')
        return

    name_width = max(len(n) for n in all_names)
    header = f'{"Benchmark":<{name_width}}  {"Old Mean":>10}  {"New Mean":>10}  {"Change":>10}'
    print('\n--- Comparison ---')
    print(header)
    print('-' * len(header))

    for name in all_names:
        old_mean = old_benchmarks.get(name, {}).get('stats', {}).get('mean')
        new_result = current_map.get(name)
        new_mean = new_result.stats['mean'] if new_result else None

        old_str = f'{old_mean:>10.6f}' if old_mean is not None else f'{"N/A":>10}'
        new_str = f'{new_mean:>10.6f}' if new_mean is not None else f'{"N/A":>10}'

        if old_mean and new_mean:
            pct = ((new_mean - old_mean) / old_mean) * 100
            change_str = f'{pct:>+9.1f}%'
        else:
            change_str = f'{"N/A":>10}'

        print(f'{name:<{name_width}}  {old_str}  {new_str}  {change_str}')
