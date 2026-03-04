"""Entry point: python -m benchmark"""
import argparse
import os
import sys


def _setup_backend(backend: str) -> None:
    """Configure sys.path for the chosen backend."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if backend == 'rust':
        # Use compat shim that maps detect_secrets.* -> detect_secrets_rs.*
        compat_path = os.path.join(project_root, 'benchmark', 'compat_rs')
        if compat_path not in sys.path:
            sys.path.insert(0, compat_path)
    else:
        # Use original Python detect-secrets submodule
        ds_path = os.path.join(project_root, 'detect-secrets')
        if os.path.isdir(ds_path) and ds_path not in sys.path:
            sys.path.insert(0, ds_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='benchmark',
        description='Performance benchmark suite for detect-secrets',
    )
    parser.add_argument(
        '--backend',
        choices=['python', 'rust'],
        default='python',
        help='Backend implementation to benchmark (default: python)',
    )
    parser.add_argument(
        '--suite',
        choices=['all', 'micro', 'mid', 'macro'],
        default='all',
        help='Which benchmark suite to run (default: all)',
    )
    parser.add_argument(
        '--iterations',
        type=int,
        default=5,
        help='Number of iterations per benchmark (default: 5)',
    )
    parser.add_argument(
        '--size',
        choices=['small', 'medium', 'large'],
        default=None,
        help='Only run a specific size tier',
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Save results to a JSON file',
    )
    parser.add_argument(
        '--compare',
        type=str,
        default=None,
        help='Compare against a previous results JSON file',
    )

    args = parser.parse_args()

    _setup_backend(args.backend)

    from benchmark.runner import run_suite
    from benchmark.results import compare_results
    from benchmark.results import print_results
    from benchmark.results import save_results

    results = run_suite(
        suite=args.suite,
        iterations=args.iterations,
        size=args.size,
    )

    print()
    print_results(results)

    if args.output:
        save_results(results, args.output, backend=args.backend)
        print(f'\nResults saved to {args.output}', file=sys.stderr)

    if args.compare:
        compare_results(results, args.compare)


if __name__ == '__main__':
    main()
