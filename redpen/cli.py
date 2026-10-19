"""Command line entry point for redpen."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _not_implemented(command: str):
    def handler(args: argparse.Namespace) -> int:
        print(f"redpen: {command} is not implemented yet", file=sys.stderr)
        return 2

    return handler


def _build_dataset(args: argparse.Namespace) -> int:
    from redpen.dataset import build_dataset

    if not args.sweep_dir:
        raise ValueError("--sweep-dir is required (or set REDPEN_SWEEP_DIR)")
    out = Path(args.out)
    report = build_dataset(args.sweep_dir, out, args.cache_dir, force=args.force)
    if report.failures:
        print(f"build failed: {len(report.failures)} of {report.total} cases failed; {out} not written")
        return 1
    print(f"built {len(report.built)} cases into {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redpen", description="Benchmark AI code reviewers on real CVEs."
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    bd = sub.add_parser(
        "build-dataset", help="build a dataset version from the cve-variant-sweep corpus"
    )
    bd.add_argument("--sweep-dir", default=os.environ.get("REDPEN_SWEEP_DIR"))
    bd.add_argument("--out", default="dataset/v1")
    bd.add_argument(
        "--cache-dir",
        default=os.environ.get("REDPEN_CACHE_DIR")
        or str(Path.home() / ".cache" / "redpen" / "repos"),
    )
    bd.add_argument("--force", action="store_true")
    bd.set_defaults(handler=_build_dataset)
    for name, help_text in (
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
