"""Interactive audit of a detect-secrets baseline file.

Supports:
- Interactive labelling (true positive / false positive)
- ``--report``  JSON report of findings
- ``--stats``   per-plugin precision / recall statistics
- ``--diff``    compare two baseline files
"""
from __future__ import annotations

import json
import os
import platform
import sys
from typing import Any, Dict, List, Optional, Tuple

import detect_secrets_rs as rs


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CONTEXT_LINES = 2  # lines shown above/below the target line

# ANSI escape helpers
_BOLD = "\033[1m"
_RED = "\033[91m"
_YELLOW_BG = "\033[43m"
_RESET = "\033[0m"
_HEADER_LINE = "-" * 40


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clear_screen() -> None:
    """Clear the terminal."""
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")


def _read_lines(filename: str) -> List[str]:
    """Read file lines, returning an empty list on error."""
    try:
        with open(filename, encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except OSError:
        return []


def _render_context(
    filename: str,
    line_number: int,
    secret_value: Optional[str] = None,
) -> str:
    """Build a code-snippet string with context around *line_number*."""
    lines = _read_lines(filename)
    if not lines:
        return f"  (unable to read {filename})"

    # 1-indexed → 0-indexed
    idx = line_number - 1
    start = max(0, idx - _CONTEXT_LINES)
    end = min(len(lines), idx + _CONTEXT_LINES + 1)

    buf: list[str] = []
    for i in range(start, end):
        lineno = i + 1
        raw = lines[i].rstrip("\n\r")
        if i == idx:
            display = raw
            if secret_value and secret_value in raw:
                display = raw.replace(
                    secret_value,
                    f"{_YELLOW_BG}{secret_value}{_RESET}{_BOLD}",
                )
            buf.append(f"  {_BOLD}{lineno:>5}:{display}{_RESET}")
        else:
            buf.append(f"  {lineno:>5}:{raw}")
    return "\n".join(buf)


def _recover_secret(
    filename: str,
    line_number: int,
    secret_type: str,
    secret_hash: str,
) -> Optional[str]:
    """Try to recover the plaintext secret from the file.

    Re-scans the specific line with all active plugins, and returns the
    secret whose hash matches *secret_hash*.
    """
    lines = _read_lines(filename)
    if not lines:
        return None
    idx = line_number - 1
    if idx < 0 or idx >= len(lines):
        return None

    line = lines[idx].rstrip("\n\r")
    matches = rs.scan_line(line)
    for m in matches:
        if m.secret_hash == secret_hash:
            return m.secret_value
    return None


# ---------------------------------------------------------------------------
# Interactive audit
# ---------------------------------------------------------------------------

def _collect_unlabelled(baseline_data: dict) -> List[Tuple[str, dict]]:
    """Return a list of ``(filename, secret_dict)`` for unlabelled secrets."""
    results = baseline_data.get("results", {})
    unlabelled: List[Tuple[str, dict]] = []
    for filename in sorted(results.keys()):
        for entry in results[filename]:
            if entry.get("is_secret") is None:
                unlabelled.append((filename, entry))
    return unlabelled


def _interactive_audit(baseline_path: str) -> int:
    """Run the interactive audit loop.  Returns exit code."""
    try:
        baseline_data = rs.baseline_load_from_file(baseline_path)
    except Exception as exc:
        print(f"Not a valid baseline file!\n{exc}", file=sys.stderr)
        return 0

    unlabelled = _collect_unlabelled(baseline_data)
    if not unlabelled:
        print("Nothing to audit!")
        return 0

    total = len(unlabelled)
    idx = 0
    modified = False

    while 0 <= idx < total:
        filename, entry = unlabelled[idx]
        line_number = entry.get("line_number", 0)
        secret_type = entry.get("type", "Unknown")
        secret_hash = entry.get("hashed_secret", "")

        _clear_screen()

        print(f"Secret:      {idx + 1} of {total}")
        print(f"Filename:    {filename}")
        print(f"Secret Type: {secret_type}")
        print(_HEADER_LINE)

        if line_number:
            secret_value = _recover_secret(
                filename, line_number, secret_type, secret_hash,
            )
            snippet = _render_context(filename, line_number, secret_value)
            print(snippet)
        else:
            print(f"  {_RED}ERROR: No line numbers found in baseline!{_RESET}")
            print("  Line numbers are needed for auditing.")
            print("  Try recreating your baseline to fix this issue.")
            break

        print(_HEADER_LINE)

        # Determine available prompt
        can_label = True
        lines = _read_lines(filename)
        line_idx = line_number - 1
        if not lines or line_idx < 0 or line_idx >= len(lines):
            print(
                f"  {_RED}ERROR: Secret not found on line {line_number}!{_RESET}"
            )
            print("  Try recreating your baseline to fix this issue.")
            can_label = False

        if can_label:
            prompt = (
                "Should this string be committed to the repository? "
                "(y)es, (n)o, (s)kip, (b)ack, (q)uit: "
            )
        else:
            prompt = "What would you like to do? (s)kip, (b)ack, (q)uit: "

        choice = input(prompt).strip().lower()

        if choice == "y" and can_label:
            # "yes, commit it" → false positive
            entry["is_secret"] = False
            modified = True
            idx += 1
        elif choice == "n" and can_label:
            # "no, don't commit it" → true positive
            entry["is_secret"] = True
            modified = True
            idx += 1
        elif choice == "s":
            # skip (or undo previous label by resetting to None)
            entry["is_secret"] = None
            idx += 1
        elif choice == "b":
            if idx > 0:
                idx -= 1
            else:
                print("Already at the first secret.")
        elif choice == "q":
            break
        else:
            # invalid input — re-display
            continue

    # ---- persist ----
    if modified:
        print("Saving progress...")
        _save_baseline(baseline_data, baseline_path)

    return 0


def _save_baseline(baseline_data: dict, path: str) -> None:
    """Write updated baseline back to disk."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(baseline_data, fh, indent=2)
        fh.write("\n")


# ---------------------------------------------------------------------------
# Report mode
# ---------------------------------------------------------------------------

def _handle_report(
    baseline_path: str,
    only_real: bool = False,
    only_false: bool = False,
) -> int:
    """Print a JSON report of all audited secrets."""
    try:
        baseline_data = rs.baseline_load_from_file(baseline_path)
    except Exception as exc:
        print(f"Not a valid baseline file!\n{exc}", file=sys.stderr)
        return 0

    results = baseline_data.get("results", {})
    report_entries: List[Dict[str, Any]] = []

    for filename in sorted(results.keys()):
        for entry in results[filename]:
            is_secret = entry.get("is_secret")
            is_verified = entry.get("is_verified", False)

            if is_secret is True:
                category = "VERIFIED_TRUE"
            elif is_secret is False:
                category = "VERIFIED_FALSE"
            else:
                category = "UNVERIFIED"

            if only_real and category == "VERIFIED_FALSE":
                continue
            if only_false and category != "VERIFIED_FALSE":
                continue

            line_number = entry.get("line_number", 0)
            secret_type = entry.get("type", "Unknown")
            secret_hash = entry.get("hashed_secret", "")

            # Try to recover secret and lines
            lines_map: Dict[str, str] = {}
            secret_value = None
            if line_number:
                secret_value = _recover_secret(
                    filename, line_number, secret_type, secret_hash,
                )
                file_lines = _read_lines(filename)
                if file_lines:
                    line_idx = line_number - 1
                    if 0 <= line_idx < len(file_lines):
                        lines_map[str(line_number)] = file_lines[line_idx].rstrip("\n\r")

            report_entries.append({
                "category": category,
                "filename": filename,
                "lines": lines_map,
                "secrets": secret_value or "",
                "types": [secret_type],
            })

    print(json.dumps({"results": report_entries}, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Stats mode
# ---------------------------------------------------------------------------

def _handle_stats(baseline_path: str, as_json: bool = False) -> int:
    """Print per-plugin statistics."""
    try:
        baseline_data = rs.baseline_load_from_file(baseline_path)
    except Exception as exc:
        print(f"Not a valid baseline file!\n{exc}", file=sys.stderr)
        return 0

    results = baseline_data.get("results", {})

    # Aggregate per-plugin
    stats: Dict[str, Dict[str, int]] = {}  # plugin → {tp, fp, unknown}
    for filename in results:
        for entry in results[filename]:
            plugin = entry.get("type", "Unknown")
            if plugin not in stats:
                stats[plugin] = {"true-positives": 0, "false-positives": 0, "unknown": 0}
            is_secret = entry.get("is_secret")
            if is_secret is True:
                stats[plugin]["true-positives"] += 1
            elif is_secret is False:
                stats[plugin]["false-positives"] += 1
            else:
                stats[plugin]["unknown"] += 1

    if as_json:
        json_stats: Dict[str, Any] = {}
        for plugin in sorted(stats):
            raw = stats[plugin]
            tp = raw["true-positives"]
            fp = raw["false-positives"]
            unk = raw["unknown"]
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + unk) if (tp + unk) > 0 else 0.0
            json_stats[plugin] = {
                "stats": {
                    "raw": raw,
                    "score": {
                        "precision": round(precision, 4),
                        "recall": round(recall, 4),
                    },
                },
            }
        print(json.dumps(json_stats, indent=2))
    else:
        for plugin in sorted(stats):
            raw = stats[plugin]
            tp = raw["true-positives"]
            fp = raw["false-positives"]
            unk = raw["unknown"]
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + unk) if (tp + unk) > 0 else 0.0
            print(
                f"Plugin: {plugin}\n"
                f"  True Positives: {tp}, False Positives: {fp}, Unknown: {unk}, "
                f"Precision: {precision:.4f}, Recall: {recall:.4f}\n"
            )

    return 0


# ---------------------------------------------------------------------------
# Diff mode
# ---------------------------------------------------------------------------

def _handle_diff(filenames: List[str]) -> int:
    """Show added/removed secrets between two baselines."""
    if len(filenames) != 2:
        print("Error: --diff requires exactly two baseline filenames.", file=sys.stderr)
        return 1

    try:
        old_data = rs.baseline_load_from_file(filenames[0])
        new_data = rs.baseline_load_from_file(filenames[1])
    except Exception as exc:
        print(f"Not a valid baseline file!\n{exc}", file=sys.stderr)
        return 0

    old_results = old_data.get("results", {})
    new_results = new_data.get("results", {})

    # Build sets of (filename, hashed_secret, secret_type) for comparison
    def _make_set(results: dict) -> Dict[Tuple[str, str, str], dict]:
        s: Dict[Tuple[str, str, str], dict] = {}
        for filename in results:
            for entry in results[filename]:
                key = (
                    filename,
                    entry.get("hashed_secret", ""),
                    entry.get("type", ""),
                )
                s[key] = {**entry, "filename": filename}
        return s

    old_set = _make_set(old_results)
    new_set = _make_set(new_results)

    added = [new_set[k] for k in new_set if k not in old_set]
    removed = [old_set[k] for k in old_set if k not in new_set]

    # Combine into a display list
    diff_items: List[Tuple[str, dict]] = []
    for item in removed:
        diff_items.append(("REMOVED", item))
    for item in added:
        diff_items.append(("ADDED", item))

    # Sort by filename, then line_number
    diff_items.sort(key=lambda x: (x[1].get("filename", ""), x[1].get("line_number", 0)))

    if not diff_items:
        print("No differences found between the two baselines.")
        return 0

    total = len(diff_items)
    idx = 0

    while 0 <= idx < total:
        status, entry = diff_items[idx]
        filename = entry.get("filename", "")
        line_number = entry.get("line_number", 0)
        secret_type = entry.get("type", "Unknown")

        _clear_screen()

        print(f"Secret:      {idx + 1} of {total}")
        print(f"Filename:    {filename}")
        print(f"Secret Type: {secret_type}")
        print(_HEADER_LINE)

        if status == "ADDED":
            print(f"  Status:    >> {_BOLD}ADDED{_RESET} <<")
        else:
            print(f"  Status:    >> {_RED}REMOVED{_RESET} <<")

        if line_number:
            snippet = _render_context(filename, line_number)
            print(snippet)

        print(_HEADER_LINE)

        prompt = "What would you like to do? (s)kip, (b)ack, (q)uit: "
        choice = input(prompt).strip().lower()

        if choice == "s":
            idx += 1
        elif choice == "b":
            if idx > 0:
                idx -= 1
        elif choice == "q":
            break
        else:
            continue

    return 0


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def handle_audit(args) -> int:
    """Dispatch to the appropriate audit sub-mode."""
    filenames = args.filename

    if args.diff:
        return _handle_diff(filenames)

    if len(filenames) != 1:
        print("Error: audit requires exactly one baseline filename.", file=sys.stderr)
        return 1

    baseline_path = filenames[0]

    if args.stats:
        return _handle_stats(baseline_path, as_json=getattr(args, "json", False))

    if args.report:
        return _handle_report(
            baseline_path,
            only_real=getattr(args, "only_real", False),
            only_false=getattr(args, "only_false", False),
        )

    return _interactive_audit(baseline_path)
