"""Command line entry point for redpen."""

from __future__ import annotations

import argparse
import sys


def _not_implemented(command: str):
    def handler(args: argparse.Namespace) -> int:
        print(f"redpen: {command} is not implemented yet", file=sys.stderr)
        return 2

    return handler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redpen", description="Benchmark AI code reviewers on real CVEs."
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    for name, help_text in (
        ("build-dataset", "build a dataset version from the cve-variant-sweep corpus"),
        ("run", "run reviewers and the judge over a dataset"),
        ("report", "render the leaderboard from completed runs"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(handler=_not_implemented(name))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    try:
        return args.handler(args)
    except Exception as exc:
        print(f"redpen: {args.command} failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
