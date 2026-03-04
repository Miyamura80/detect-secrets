"""Mid-level benchmark: baseline JSON serde + merge/trim."""
import json
import os
import tempfile
from typing import List

from benchmark.datagen import DataGen
from benchmark.timing import BenchmarkResult
from benchmark.timing import time_func

# (num_secrets, num_files) for each size tier
BASELINE_SIZES = {
    'small': (50, 10),
    'medium': (500, 100),
    'large': (5000, 500),
}


def run(iterations: int = 5, sizes: List[str] = None) -> List[BenchmarkResult]:
    from detect_secrets.core.baseline import format_for_output
    from detect_secrets.core.baseline import load
    from detect_secrets.core.secrets_collection import SecretsCollection
    from detect_secrets.settings import default_settings

    if sizes is None:
        sizes = ['small', 'medium', 'large']

    gen = DataGen(seed=42)
    results = []

    for size_name in sizes:
        config = BASELINE_SIZES.get(size_name)
        if config is None:
            continue

        num_secrets, num_files = config

        # Generate a baseline dict
        baseline_dict = gen.generate_secrets_baseline(num_secrets, num_files)
        baseline_json = json.dumps(baseline_dict, indent=2)

        # Write to temp file for load benchmark
        tmpfile = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        tmpfile.write(baseline_json)
        tmpfile.close()

        try:
            # ── Deserialize benchmark ──
            def run_deserialize(data=baseline_dict):
                with default_settings():
                    collection = load({**data})

            timings = time_func(run_deserialize, iterations)
            results.append(BenchmarkResult(
                name=f'baseline_deserialize_{size_name}',
                count=num_secrets,
                iterations=iterations,
                timings=timings,
                extra={'num_secrets': num_secrets, 'num_files': num_files},
            ))

            # ── Serialize benchmark ──
            with default_settings():
                collection = load({**baseline_dict})

            def run_serialize(col=collection):
                with default_settings():
                    output = format_for_output(col)
                    _ = json.dumps(output)

            timings = time_func(run_serialize, iterations)
            results.append(BenchmarkResult(
                name=f'baseline_serialize_{size_name}',
                count=num_secrets,
                iterations=iterations,
                timings=timings,
                extra={'num_secrets': num_secrets, 'num_files': num_files},
            ))

            # ── Merge benchmark ──
            with default_settings():
                collection_a = load({**baseline_dict})
                collection_b = load({**baseline_dict})

            def run_merge(a=collection_a, b=collection_b):
                # merge modifies in place, so we need to work with copies
                from copy import deepcopy
                target = deepcopy(a)
                target.merge(b)

            timings = time_func(run_merge, iterations)
            results.append(BenchmarkResult(
                name=f'baseline_merge_{size_name}',
                count=num_secrets,
                iterations=iterations,
                timings=timings,
                extra={'num_secrets': num_secrets, 'num_files': num_files},
            ))

            # ── Trim benchmark ──
            with default_settings():
                collection_full = load({**baseline_dict})
                # Create a partial collection (simulating some secrets removed)
                partial_dict = {**baseline_dict}
                partial_results = {}
                for i, (fname, secrets) in enumerate(baseline_dict['results'].items()):
                    if i % 2 == 0:
                        partial_results[fname] = secrets
                partial_dict['results'] = partial_results
                collection_partial = load(partial_dict)

            filelist = list(baseline_dict['results'].keys())

            def run_trim(full=collection_full, partial=collection_partial, fl=filelist):
                from copy import deepcopy
                target = deepcopy(full)
                target.trim(scanned_results=partial, filelist=fl)

            timings = time_func(run_trim, iterations)
            results.append(BenchmarkResult(
                name=f'baseline_trim_{size_name}',
                count=num_secrets,
                iterations=iterations,
                timings=timings,
                extra={'num_secrets': num_secrets, 'num_files': num_files},
            ))

        finally:
            os.unlink(tmpfile.name)

    return results
