"""P3 command line: seed a demo database, inspect it, or serve the API.

    python -m p3_api.cli seed data/mock_findings.raw.json
    python -m p3_api.cli stats
    python -m p3_api.cli serve
    python -m p3_api.cli reset --yes

`seed` takes *raw* findings (P1's shape) and runs the full enrich-and-store
path, so seeding a demo exercises exactly the code a real scan does.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from p2_scoring.rules import UnknownRuleError

from . import repository
from .db import DEFAULT_DB_PATH, session
from .scan_service import ScanIngestError, seed_from_file


def _cmd_seed(args: argparse.Namespace) -> int:
    try:
        with session(args.db) as connection:
            report = seed_from_file(connection, args.path)
    except FileNotFoundError:
        print(f"error: no such file: {args.path}", file=sys.stderr)
        return 1
    except ScanIngestError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.detail:
            print(f"  {exc.detail}", file=sys.stderr)
        return 1
    except UnknownRuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"scan {report.scan_id}: {report.finding_count} finding(s) ingested")
    print(f"  new={report.outcome.get('new', 0)} updated={report.outcome.get('updated', 0)} "
          f"reopened={report.outcome.get('reopened', 0)} unchanged={report.outcome.get('unchanged', 0)}")
    print(f"  average score: {report.average_score}")
    for band, count in sorted(report.band_counts.items()):
        print(f"  {band:<9} {count}")
    for warning in report.warnings:
        print(f"  warning: {warning}", file=sys.stderr)
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    with session(args.db) as connection:
        stats = repository.summary_stats(connection)
        bands = repository.by_band(connection)
        services = repository.by_service(connection)
        frameworks = repository.compliance_summary(connection)

    print(f"findings      {stats['total']} ({stats['open']} open, {stats['critical']} critical)")
    print(f"avg score     {stats['average_score']} overall, {stats['average_open_score']} open")
    print(f"scans         {stats['scan_count']} (last {stats['last_scan_at'] or 'never'})")

    print("\nby severity band")
    for row in bands:
        print(f"  {row['label']:<9} {row['count']:>3}  avg {row['avg_score']}")

    print("\nby service")
    for row in services:
        print(f"  {row['label']:<16} {row['count']:>3}  avg {row['avg_score']}")

    print("\nby framework")
    for row in frameworks:
        print(f"  {row['framework']:<9} {row['finding_count']:>3} findings, "
              f"{row['open_count']} open, {row['critical_count']} critical")
    return 0


def _cmd_reset(args: argparse.Namespace) -> int:
    if not args.yes:
        print(
            f"refusing to wipe {args.db} without --yes.\n"
            f"this deletes every stored finding and scan record.",
            file=sys.stderr,
        )
        return 1
    with session(args.db) as connection:
        repository.clear(connection)
    print(f"cleared {args.db}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import os

    import uvicorn

    os.environ["CSPM_DB_PATH"] = str(args.db)
    print(f"serving on http://{args.host}:{args.port}  (db: {args.db})")
    uvicorn.run("p3_api.app:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m p3_api.cli", description=__doc__)
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    seed = sub.add_parser("seed", help="ingest a raw findings JSON file")
    seed.add_argument("path", help="path to a raw findings JSON file")
    seed.set_defaults(func=_cmd_seed)

    stats = sub.add_parser("stats", help="print database summary")
    stats.set_defaults(func=_cmd_stats)

    reset = sub.add_parser("reset", help="delete all findings and scan records")
    reset.add_argument("--yes", action="store_true", help="confirm the wipe")
    reset.set_defaults(func=_cmd_reset)

    serve = sub.add_parser("serve", help="run the API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
