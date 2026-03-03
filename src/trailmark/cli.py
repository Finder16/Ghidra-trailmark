"""Trailmark CLI entry point."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from trailmark.query.api import QueryEngine


def main() -> None:
    """Run the Trailmark CLI."""
    parser = argparse.ArgumentParser(
        prog="trailmark",
        description="Parse source code into queryable graphs",
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a directory and output the code graph",
    )
    analyze.add_argument("path", help="Directory to analyze")
    analyze.add_argument(
        "--language",
        "-l",
        default="python",
        help="Source language (default: python)",
    )
    analyze.add_argument(
        "--summary",
        "-s",
        action="store_true",
        help="Print summary instead of full graph",
    )
    analyze.add_argument(
        "--complexity",
        "-c",
        type=int,
        default=0,
        help="Show functions with complexity >= threshold",
    )

    augment = subparsers.add_parser(
        "augment",
        help="Augment a code graph with SARIF or weAudit findings",
    )
    augment.add_argument("path", help="Directory to analyze")
    augment.add_argument(
        "--language",
        "-l",
        default="python",
        help="Source language (default: python)",
    )
    augment.add_argument(
        "--sarif",
        action="append",
        default=[],
        help="SARIF file(s) to augment with (repeatable)",
    )
    augment.add_argument(
        "--weaudit",
        action="append",
        default=[],
        help="weAudit file(s) to augment with (repeatable)",
    )
    augment.add_argument(
        "--json",
        action="store_true",
        help="Output full augmented graph as JSON",
    )

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "analyze":
        _run_analyze(args)
    elif args.command == "augment":
        _run_augment(args)


def _run_analyze(args: argparse.Namespace) -> None:
    """Execute the analyze subcommand."""
    engine = QueryEngine.from_directory(
        args.path,
        language=args.language,
    )

    if args.summary:
        _print_summary(engine)
    elif args.complexity > 0:
        _print_complexity(engine, args.complexity)
    else:
        print(engine.to_json())


def _print_summary(engine: QueryEngine) -> None:
    """Print a graph summary."""
    summary = engine.summary()
    print(f"Nodes: {summary['total_nodes']}")
    print(f"  Functions: {summary['functions']}")
    print(f"  Classes: {summary['classes']}")
    print(f"Call edges: {summary['call_edges']}")
    print(f"Dependencies: {', '.join(summary['dependencies'])}")
    print(f"Entrypoints: {summary['entrypoints']}")


def _print_complexity(engine: QueryEngine, threshold: int) -> None:
    """Print complexity hotspots."""
    hotspots = engine.complexity_hotspots(threshold)
    if not hotspots:
        print(f"No functions with complexity >= {threshold}")
        return
    for h in hotspots:
        loc = h["location"]
        print(
            f"  {h['id']}  "
            f"complexity={h['cyclomatic_complexity']}  "
            f"{loc['file_path']}:{loc['start_line']}",
        )


def _run_augment(args: argparse.Namespace) -> None:
    """Execute the augment subcommand."""
    engine = QueryEngine.from_directory(
        args.path,
        language=args.language,
    )

    for sarif_path in args.sarif:
        result = engine.augment_sarif(sarif_path)
        _print_augment_result("SARIF", sarif_path, result)

    for weaudit_path in args.weaudit:
        result = engine.augment_weaudit(weaudit_path)
        _print_augment_result("weAudit", weaudit_path, result)

    if args.json:
        print(engine.to_json())


def _print_augment_result(
    label: str,
    path: str,
    result: dict[str, Any],
) -> None:
    """Print a summary of an augmentation result."""
    print(f"{label}: {path}")
    print(f"  Matched: {result['matched_findings']}")
    print(f"  Unmatched: {result['unmatched_findings']}")
    subgraphs = result.get("subgraphs_created", [])
    if subgraphs:
        print(f"  Subgraphs: {', '.join(str(s) for s in subgraphs)}")
