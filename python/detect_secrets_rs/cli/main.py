"""CLI entry point for ``detect-secrets scan`` and ``audit``."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

import detect_secrets_rs as rs

from .audit import handle_audit


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detect-secrets",
        description="Rust-backed drop-in replacement for Yelp/detect-secrets.",
    )
    parser.add_argument("--version", action="version", version=rs.version())
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument(
        "-C",
        metavar="<path>",
        dest="custom_root",
        default="",
        help="Run as if started in <path> rather than the current directory.",
    )
    parser.add_argument(
        "-c", "--cores",
        dest="num_cores",
        type=int,
        default=None,
        help="Number of cores for parallel processing (default: all).",
    )

    sub = parser.add_subparsers(dest="action")

    # ---- scan ----
    scan_parser = sub.add_parser(
        "scan",
        help="Create a baseline by scanning a repository for secrets.",
    )
    scan_parser.add_argument(
        "--string",
        nargs="?",
        const=True,
        help="Scan an individual string and display each plugin's verdict.",
    )
    scan_parser.add_argument(
        "--only-allowlisted",
        action="store_true",
        help="Only scan lines flagged with ``allowlist secret``.",
    )
    scan_parser.add_argument(
        "path",
        nargs="*",
        default=["."],
        help="Paths to scan (default: current directory).",
    )
    scan_parser.add_argument(
        "--all-files",
        action="store_true",
        help="Scan all files (not just git-tracked).",
    )
    scan_parser.add_argument(
        "--baseline",
        metavar="FILENAME",
        default=None,
        help="Update an existing baseline file.",
    )
    scan_parser.add_argument(
        "--force-use-all-plugins",
        action="store_true",
        help="Override baseline plugin list with all available plugins.",
    )
    scan_parser.add_argument(
        "--slim",
        action="store_true",
        help="Create a slim baseline (not compatible with audit).",
    )
    _add_plugin_options(scan_parser)
    _add_filter_options(scan_parser)

    # ---- audit ----
    audit_parser = sub.add_parser(
        "audit",
        help="Review a baseline and interactively label secrets.",
    )
    audit_parser.add_argument(
        "filename",
        nargs="+",
        help="Baseline file(s) to audit (two files when using --diff).",
    )
    audit_parser.add_argument(
        "--diff",
        action="store_true",
        help="Compare two baseline files for added/removed secrets.",
    )
    audit_parser.add_argument(
        "--stats",
        action="store_true",
        help="Display per-plugin audit statistics.",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Output statistics as JSON (requires --stats).",
    )

    report_group = audit_parser.add_argument_group(title="report options")
    report_group.add_argument(
        "--report",
        action="store_true",
        help="Generate a JSON report of all findings.",
    )
    report_excl = report_group.add_mutually_exclusive_group()
    report_excl.add_argument(
        "--only-real",
        action="store_true",
        help="Report only true positives and unverified secrets.",
    )
    report_excl.add_argument(
        "--only-false",
        action="store_true",
        help="Report only false positives.",
    )

    return parser


def _add_plugin_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group(title="plugin options")
    group.add_argument(
        "--list-all-plugins",
        action="store_true",
        help="List all plugins that will be used for the scan.",
    )
    group.add_argument(
        "-p", "--plugin",
        nargs=1,
        action="append",
        help="Path to custom secret detector plugin.",
    )
    group.add_argument(
        "--base64-limit",
        type=float,
        default=None,
        help="Entropy limit for Base64 strings (0.0–8.0, default 4.5).",
    )
    group.add_argument(
        "--hex-limit",
        type=float,
        default=None,
        help="Entropy limit for Hex strings (0.0–8.0, default 3.0).",
    )
    group.add_argument(
        "--disable-plugin",
        nargs=1,
        action="append",
        help="Plugin class name to disable (repeatable).",
    )


def _add_filter_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group(title="filter options")
    verify = group.add_mutually_exclusive_group()
    verify.add_argument(
        "-n", "--no-verify",
        action="store_true",
        help="Disable additional verification via network calls.",
    )
    verify.add_argument(
        "--only-verified",
        action="store_true",
        help="Only flag secrets that can be verified.",
    )
    group.add_argument(
        "--exclude-lines",
        type=str,
        action="append",
        help="Regex — matching lines will be ignored (repeatable).",
    )
    group.add_argument(
        "--exclude-files",
        type=str,
        action="append",
        help="Regex — matching filenames will be ignored (repeatable).",
    )
    group.add_argument(
        "--exclude-secrets",
        type=str,
        action="append",
        help="Regex — matching secrets will be ignored (repeatable).",
    )
    group.add_argument(
        "--word-list",
        dest="word_list_file",
        default=None,
        help="Text file with words to ignore when found in secrets.",
    )
    group.add_argument(
        "-f", "--filter",
        nargs=1,
        action="append",
        help="Custom filter (Python import path or file://path::func).",
    )
    group.add_argument(
        "--disable-filter",
        nargs=1,
        action="append",
        help="Filter path to disable (repeatable).",
    )


# ---------------------------------------------------------------------------
# Settings initialisation
# ---------------------------------------------------------------------------

def _initialize_settings(args: argparse.Namespace) -> None:
    """Populate global settings from baseline / CLI flags."""
    baseline_data = None

    if args.baseline and os.path.isfile(args.baseline):
        baseline_data = rs.baseline_load_from_file(args.baseline)
        rs.configure_settings_from_baseline(baseline_data, args.baseline)

        if args.force_use_all_plugins:
            rs.global_clear_plugins()
            rs.global_initialize_all_plugins()
    else:
        rs.global_initialize_all_plugins()

    # -- plugin overrides --
    if args.disable_plugin:
        names = [n for item in args.disable_plugin for n in item]
        rs.global_disable_plugins(names)

    if args.base64_limit is not None:
        rs.global_set_plugin_limit("Base64HighEntropyString", "limit", args.base64_limit)

    if args.hex_limit is not None:
        rs.global_set_plugin_limit("HexHighEntropyString", "limit", args.hex_limit)

    # -- filter overrides --
    if args.exclude_lines:
        rs.global_set_filter(
            "detect_secrets.filters.regex.should_exclude_line",
            {"pattern": args.exclude_lines},
        )

    if args.exclude_files:
        rs.global_set_filter(
            "detect_secrets.filters.regex.should_exclude_file",
            {"pattern": args.exclude_files},
        )

    if args.exclude_secrets:
        rs.global_set_filter(
            "detect_secrets.filters.regex.should_exclude_secret",
            {"pattern": args.exclude_secrets},
        )

    if args.word_list_file:
        rs.global_set_filter(
            "detect_secrets.filters.wordlist.should_exclude_secret",
            {"file_name": args.word_list_file, "min_length": 3},
        )

    if args.no_verify:
        rs.global_disable_filters([
            "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
        ])

    if args.disable_filter:
        paths = [p for item in args.disable_filter for p in item]
        rs.global_disable_filters(paths)

    if args.filter:
        paths = [p for item in args.filter for p in item]
        for path in paths:
            rs.global_set_filter(path, {})

    # Custom root handling
    if args.custom_root:
        rs.global_disable_filters(["detect_secrets.filters.common.is_invalid_file"])
        if args.path == ["."]:
            args.path = [args.custom_root]

    return baseline_data


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def _handle_scan(args: argparse.Namespace) -> int:
    baseline_data = _initialize_settings(args)

    if args.list_all_plugins:
        names = rs.global_get_plugin_names()
        for name in sorted(names):
            print(name)
        return 0

    if args.string:
        line = args.string
        if isinstance(args.string, bool):
            line = sys.stdin.read().splitlines()[0]
        results = rs.scan_line(line)
        # Build secret_type → class_name mapping
        type_to_class = rs.get_mapping_from_secret_type_to_class()
        # Build class_name → secret_type reverse mapping
        class_to_type = {v: k for k, v in type_to_class.items()}
        plugin_names = sorted(rs.all_plugin_class_names())
        matched_types = {s.type for s in results}
        width = max((len(n) for n in plugin_names), default=0)
        for name in plugin_names:
            secret_type = class_to_type.get(name, "")
            verdict = "True" if secret_type in matched_types else "False"
            print(f"{name:<{width}}: {verdict}")
        return 0

    root = args.custom_root or "."
    secrets = rs.baseline_create(args.path, args.all_files, root)

    if args.baseline:
        if baseline_data is not None:
            old_secrets = rs.baseline_load(baseline_data, args.baseline)
            secrets.merge(old_secrets)
        output = rs.baseline_format_for_output(secrets, args.slim)
        rs.baseline_save_to_file(output, args.baseline)
    else:
        output = rs.baseline_format_for_output(secrets, args.slim)
        print(json.dumps(output, indent=2))

    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    if argv is None and len(sys.argv) == 1:
        argv = ["--help"]

    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.action:
        parser.print_help()
        return 1

    rs.cache_bust()

    if args.action == "scan":
        return _handle_scan(args)

    if args.action == "audit":
        return handle_audit(args)

    print(f"Unknown action: {args.action}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
