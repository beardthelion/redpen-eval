"""Command line entry point for redpen."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


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


def _run(args: argparse.Namespace) -> int:
    from redpen.runner import run

    return run(args.reviewer, args.judge, args.cases, args.dataset, args.config,
               args.results_dir, concurrency=args.concurrency, resume=args.resume)


def _report(args: argparse.Namespace) -> int:
    from redpen.report import report

    return report(args.results_dir, args.dataset, args.runs, args.markdown)


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
    rn = sub.add_parser("run", help="run reviewers and the judge over a dataset")
    rn.add_argument("--reviewer", required=True)
    rn.add_argument("--judge")
    rn.add_argument("--cases", help="all, a guard class, or comma-separated case ids (default all)")
    rn.add_argument("--dataset", default="dataset/v1")
    rn.add_argument("--config", default="reviewers.yaml")
    rn.add_argument("--results-dir", default="results")
    rn.add_argument("--concurrency", type=int, default=4)
    rn.add_argument("--resume", metavar="RUN_ID")
    rn.set_defaults(handler=_run)
    rp = sub.add_parser("report", help="render the leaderboard from completed runs")
    rp.add_argument("--results-dir", default="results")
    rp.add_argument("--dataset", default="dataset/v1")
    rp.add_argument("--runs", metavar="ID[,ID...]")
    rp.add_argument("--markdown", metavar="PATH")
    rp.set_defaults(handler=_report)
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
