"""
cli.py -- run a scan from the terminal, without the web app.

This is the Week 1 checkpoint: if this script works, the whole scanning
engine works. Everything else (queue, React, PDF) is a wrapper around it.

USAGE
-----
    python -m scanner.cli https://example.com
    python -m scanner.cli example.com --json
    python -m scanner.cli example.com --timeout 15 --show-fixes
"""

import argparse        # standard library for command line arguments
import json            # to print machine-readable output with --json
import sys             # exit codes

from .engine import run_scan          # the scanner
from .models import ScanError         # friendly error type

# Small text symbols instead of emoji: they render in every Windows terminal.
SYMBOL = {"pass": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]", "info": "[INFO]"}


def print_report(result, show_fixes: bool) -> None:
    """Human readable report printed to stdout."""

    print("")                                                    # breathing room
    print("=" * 64)                                              # a line of 64 '=' characters
    print(f" VulnScan Lite report for {result.final_url}")       # the URL we actually scanned
    print("=" * 64)
    print(f" Score : {result.score}/100   Grade: {result.grade}")   # the headline numbers
    print(f" HTTP  : {result.status_code}   Server: {result.server or '(hidden)'}")
    print(f" Time  : {result.duration_ms} ms")
    print("")                                                    # blank line

    for module in result.modules:                                # one block per module
        print(f"-- {module.title} ({module.score}/100) " + "-" * 20)   # module header
        for check in module.checks:                              # every check in the module
            symbol = SYMBOL.get(check.status, "[????]")          # coloured-ish marker
            print(f"  {symbol} {check.title}")
            print(f"         {check.detail}")                    # one-line explanation
            if check.evidence:                                   # show what we saw
                print(f"         evidence: {check.evidence}")
            if show_fixes and check.status == "fail":            # optional remediation
                fix = check.remediation.get("fix")
                snippet = check.remediation.get("snippet")
                if fix:
                    print(f"         FIX: {fix}")
                if snippet:
                    for line in snippet.splitlines():            # keep the snippet indented
                        print(f"              {line}")
        print("")                                                # blank line between modules

    print("Only scan websites you own. This tool performs passive analysis only.")
    print("")                                                    # final newline


def main() -> int:
    """Parse arguments, run the scan, print the result. Returns an exit code."""

    parser = argparse.ArgumentParser(
        prog="python -m scanner.cli",
        description="Passive security scan of a single public URL.",
    )
    parser.add_argument("url", help="the site to scan, e.g. https://example.com")   # positional
    parser.add_argument("--json", action="store_true", help="print raw JSON instead of a report")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    parser.add_argument("--show-fixes", action="store_true", help="print remediation snippets")
    args = parser.parse_args()                                    # argparse validates and converts types

    try:
        result = run_scan(args.url, timeout=args.timeout)         # do the work
    except ScanError as exc:                                      # expected, friendly failure
        print(f"Scan failed: {exc}", file=sys.stderr)             # stderr, not stdout
        return 2                                                  # conventional "bad input" exit code
    except KeyboardInterrupt:                                     # Ctrl+C
        print("Cancelled.", file=sys.stderr)
        return 130                                                # 128 + SIGINT

    if args.json:                                                 # machine-readable mode
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:                                                         # human mode
        print_report(result, args.show_fixes)

    return 0                                                      # success


if __name__ == "__main__":        # only run when executed directly, not when imported
    raise SystemExit(main())      # SystemExit carries our integer exit code to the shell
