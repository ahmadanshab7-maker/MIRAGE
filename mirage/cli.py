#!/usr/bin/env python3
"""MIRAGE CLI - Command-line interface for environment profiling.

MIRAGE v0.1 is a passive measurement instrument. It does NOT:
- Detect honeypots or sandboxes
- Calculate authenticity/deception scores
- Classify environments
- Use heuristic thresholds or machine learning

Usage:
    python -m mirage.cli --output snapshot.json
    python -m mirage.cli --output snapshot.json --collectors system,network
    python -m mirage.cli --help
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

# Import collectors
from mirage.collectors import system, users, filesystem, software, runtime, network
from mirage.models.snapshot import Snapshot
from mirage import __version__


ALL_COLLECTORS = {
    "system": system.collect,
    "users": users.collect,
    "filesystem": filesystem.collect,
    "software": software.collect,
    "runtime": runtime.collect,
    "network": network.collect,
}


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="mirage",
        description=(
            "MIRAGE v0.1 - Passive Linux Environment Profiler\n\n"
            "Collects read-only environmental measurements for cybersecurity research.\n"
            "This tool does NOT detect honeypots, calculate deception scores, or classify environments."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path for JSON snapshot (default: stdout)",
    )
    
    parser.add_argument(
        "-c", "--collectors",
        type=str,
        default=None,
        help="Comma-separated list of collectors to run (default: all). "
             f"Available: {', '.join(ALL_COLLECTORS.keys())}",
    )
    
    parser.add_argument(
        "--no-users",
        action="store_true",
        help="Skip the users collector (for privacy-sensitive environments)",
    )
    
    parser.add_argument(
        "--no-filesystem",
        action="store_true", 
        help="Skip the filesystem collector (can be slow on large systems)",
    )
    
    parser.add_argument(
        "--notes",
        type=str,
        default=None,
        help="Optional notes to include in the snapshot metadata",
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output to stderr",
    )
    
    return parser.parse_args(argv)


def run_collectors(
    collector_names: list[str],
    quiet: bool = False,
) -> dict[str, dict]:
    """Run specified collectors and return their results.
    
    Args:
        collector_names: List of collector names to run
        quiet: If True, suppress progress messages
    
    Returns:
        Dictionary mapping collector names to their results
    """
    results = {}
    
    for name in collector_names:
        if not quiet:
            print(f"[*] Running collector: {name}", file=sys.stderr)
        
        collect_fn = ALL_COLLECTORS.get(name)
        if collect_fn is None:
            if not quiet:
                print(f"[!] Unknown collector: {name}", file=sys.stderr)
            continue
        
        try:
            result = collect_fn()
            results[name] = result
        except Exception as e:
            results[name] = {
                "error": str(e),
                "errors": [str(e)],
            }
            if not quiet:
                print(f"[!] Collector {name} failed: {e}", file=sys.stderr)
    
    return results


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point for the CLI.
    
    Args:
        argv: Command-line arguments (defaults to sys.argv[1:])
    
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    args = parse_args(argv)
    
    # Determine which collectors to run
    if args.collectors:
        collector_names = [c.strip() for c in args.collectors.split(",")]
        # Validate collector names
        invalid = set(collector_names) - set(ALL_COLLECTORS.keys())
        if invalid:
            print(f"[!] Unknown collectors: {', '.join(invalid)}", file=sys.stderr)
            print(f"    Available: {', '.join(ALL_COLLECTORS.keys())}", file=sys.stderr)
            return 1
    else:
        collector_names = list(ALL_COLLECTORS.keys())
        
        # Apply exclusions
        if args.no_users:
            collector_names = [c for c in collector_names if c != "users"]
        if args.no_filesystem:
            collector_names = [c for c in collector_names if c != "filesystem"]
    
    if not collector_names:
        print("[!] No collectors to run", file=sys.stderr)
        return 1
    
    # Create snapshot
    snapshot = Snapshot()
    snapshot.set_metadata(
        collector_name="mirage",
        collector_version=__version__,
        notes=args.notes,
    )
    
    # Run collectors
    results = run_collectors(collector_names, quiet=args.quiet)
    
    # Add results to snapshot
    for name, result in results.items():
        snapshot.add_collector_result(name, result)
    
    # Output
    json_output = snapshot.to_json(indent=2)
    
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_output)
        if not args.quiet:
            print(f"[+] Snapshot saved to: {args.output}", file=sys.stderr)
    else:
        print(json_output)
    
    # Report any errors
    errors = snapshot.get_data().get("errors", [])
    if errors and not args.quiet:
        print(f"\n[!] Collection completed with {len(errors)} error(s):", file=sys.stderr)
        for error in errors[:10]:  # Show first 10 errors
            print(f"    - {error}", file=sys.stderr)
        if len(errors) > 10:
            print(f"    ... and {len(errors) - 10} more", file=sys.stderr)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
