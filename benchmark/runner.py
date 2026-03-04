"""Benchmark orchestrator."""
import sys
from typing import List
from typing import Optional

from .timing import BenchmarkResult

# Suite definitions
SUITES = {
    'micro': ['entropy', 'regex'],
    'mid': ['scan_file', 'baseline_io'],
    'macro': ['scan_repo'],
    'all': ['entropy', 'regex', 'scan_file', 'scan_repo', 'baseline_io'],
}

BENCHMARK_MODULES = {
    'entropy': 'benchmark.benchmarks.bench_entropy',
    'regex': 'benchmark.benchmarks.bench_regex',
    'scan_file': 'benchmark.benchmarks.bench_scan_file',
    'scan_repo': 'benchmark.benchmarks.bench_scan_repo',
    'baseline_io': 'benchmark.benchmarks.bench_baseline_io',
}


def run_suite(
    suite: str = 'all',
    iterations: int = 5,
    size: Optional[str] = None,
) -> List[BenchmarkResult]:
    """Run a benchmark suite and return results."""
    import importlib

    bench_names = SUITES.get(suite, SUITES['all'])
    sizes = [size] if size else None

    all_results: List[BenchmarkResult] = []

    for name in bench_names:
        module_path = BENCHMARK_MODULES[name]
        print(f'Running {name} benchmarks...', file=sys.stderr)

        module = importlib.import_module(module_path)

        kwargs = {'iterations': iterations}
        if sizes is not None:
            kwargs['sizes'] = sizes

        results = module.run(**kwargs)
        all_results.extend(results)

        for r in results:
            s = r.stats
            print(
                f'  {r.name}: mean={s["mean"]:.6f}s median={s["median"]:.6f}s '
                f'(n={r.count}, iters={r.iterations})',
                file=sys.stderr,
            )

    return all_results
