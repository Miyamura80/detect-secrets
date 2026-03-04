"""Macro benchmark: full repo scan with multiprocessing."""
import os
from typing import List

from benchmark.datagen import DataGen
from benchmark.timing import BenchmarkResult
from benchmark.timing import time_func

REPO_SIZES = {
    'small': 50,
    'medium': 200,
    'large': 500,
}


def _count_files(directory: str) -> int:
    count = 0
    for root, _, files in os.walk(directory):
        count += len(files)
    return count


def run(iterations: int = 5, sizes: List[str] = None) -> List[BenchmarkResult]:
    from detect_secrets.core.baseline import create
    from detect_secrets.settings import default_settings

    if sizes is None:
        sizes = ['small', 'medium', 'large']

    gen = DataGen(seed=42)
    results = []

    try:
        for size_name in sizes:
            num_files = REPO_SIZES.get(size_name)
            if num_files is None:
                continue

            repo_dir = gen.generate_repo(num_files)
            actual_files = _count_files(repo_dir)

            # Single-core benchmark
            def run_single(path=repo_dir):
                with default_settings():
                    secrets = create(path, should_scan_all_files=True, num_processors=1)

            timings_single = time_func(run_single, iterations)

            # Compute throughput for extra info
            mean_single = sum(timings_single) / len(timings_single) if timings_single else 1
            results.append(BenchmarkResult(
                name=f'scan_repo_{size_name}_single',
                count=actual_files,
                iterations=iterations,
                timings=timings_single,
                extra={
                    'num_files': actual_files,
                    'num_processors': 1,
                    'files_per_second': actual_files / mean_single if mean_single > 0 else 0,
                },
            ))

            # Multi-core benchmark (default processor count)
            def run_multi(path=repo_dir):
                with default_settings():
                    secrets = create(path, should_scan_all_files=True)

            timings_multi = time_func(run_multi, iterations)

            mean_multi = sum(timings_multi) / len(timings_multi) if timings_multi else 1
            cpu_count = os.cpu_count() or 1
            results.append(BenchmarkResult(
                name=f'scan_repo_{size_name}_multi',
                count=actual_files,
                iterations=iterations,
                timings=timings_multi,
                extra={
                    'num_files': actual_files,
                    'num_processors': cpu_count,
                    'files_per_second': actual_files / mean_multi if mean_multi > 0 else 0,
                },
            ))
    finally:
        gen.cleanup()

    return results
