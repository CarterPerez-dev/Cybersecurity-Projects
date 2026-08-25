"""glasswatch command-line interface.

Four subcommands:

  glasswatch logs                    list currently usable CT logs
  glasswatch scan-file               score a plain list of domains (offline, no network)
  glasswatch stream                  poll a live CT log and score new certs as they land
  glasswatch serve                   read-only local dashboard over stored findings
"""

from __future__ import annotations

import argparse
import sys
import time

import requests

from glasswatch import ctlog
from glasswatch.detect import score_against_watchlist
from glasswatch.server import serve_dashboard
from glasswatch.store import FindingsStore
from glasswatch.watchlist import load_watchlist


def _print_finding(finding, prefix: str = "") -> None:
    print(f"{prefix}[{finding.severity.upper():>8}] score={finding.score:<3} "
          f"{finding.domain}  (brand: {finding.brand})", file=sys.stderr)
    for reason in finding.reasons:
        print(f"{prefix}    - {reason}", file=sys.stderr)


def cmd_logs(args: argparse.Namespace) -> int:
    logs = ctlog.fetch_usable_logs()
    for log in sorted(logs, key=lambda l: (l.operator, l.description)):
        print(f"{log.operator:12} {log.description:40} {log.url}")
    print(f"\n{len(logs)} usable logs", file=sys.stderr)
    return 0


def cmd_scan_file(args: argparse.Namespace) -> int:
    brands = load_watchlist(args.watchlist)
    store = FindingsStore(args.db) if args.db else None
    total = 0
    flagged = 0

    with open(args.input, encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if not domain or domain.startswith("#"):
                continue
            total += 1
            for finding in score_against_watchlist(domain, brands):
                flagged += 1
                is_new = store.record(finding) if store else True
                if is_new or args.all:
                    _print_finding(finding)

    print(f"\nscanned {total} domains, {flagged} findings", file=sys.stderr)
    if store:
        store.close()
    return 0


def cmd_stream(args: argparse.Namespace) -> int:
    brands = load_watchlist(args.watchlist)
    store = FindingsStore(args.db)
    session = requests.Session()

    if args.log_url:
        log = ctlog.CTLog(operator="manual", description="manual", url=args.log_url.rstrip("/") + "/")
    else:
        logs = ctlog.fetch_usable_logs(session)
        if not logs:
            print("no usable CT logs found", file=sys.stderr)
            return 1
        log = logs[0]

    print(f"watching {log.operator} / {log.description}\n  {log.url}", file=sys.stderr)

    tree_size = ctlog.get_sth(log, session)
    cursor = max(0, tree_size - args.backfill) if args.backfill else tree_size
    print(f"tree size {tree_size}, starting at index {cursor}", file=sys.stderr)

    deadline = time.monotonic() + args.seconds if args.seconds else None
    certs_scanned = 0

    while True:
        if deadline and time.monotonic() >= deadline:
            break

        tree_size = ctlog.get_sth(log, session)
        if cursor >= tree_size:
            if args.seconds is None:
                break  # one-shot mode: nothing new, stop
            time.sleep(args.poll_interval)
            continue

        end = min(cursor + args.batch_size - 1, tree_size - 1)
        entries = ctlog.get_entries(log, cursor, end, session)
        if not entries:
            time.sleep(args.poll_interval)
            continue

        for entry in entries:
            domains = ctlog.leaf_to_domains(entry)
            certs_scanned += 1
            for domain in domains:
                for finding in score_against_watchlist(domain, brands):
                    is_new = store.record(finding, log_url=log.url)
                    if is_new:
                        _print_finding(finding)

        cursor += len(entries)
        print(f"\rindexed {cursor}/{tree_size}  ({certs_scanned} certs scanned, "
              f"{store.count()} findings so far)", end="", file=sys.stderr)

        if args.seconds is None and cursor >= tree_size:
            break

    print(f"\nstopped at index {cursor}, {store.count()} total findings in {args.db}", file=sys.stderr)
    store.close()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    serve_dashboard(args.db, args.port, args.host)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glasswatch", description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_logs = sub.add_parser("logs", help="list currently usable CT logs")
    p_logs.set_defaults(func=cmd_logs)

    p_scan = sub.add_parser("scan-file", help="score a newline-delimited domain list (offline)")
    p_scan.add_argument("input", help="path to a file with one domain per line")
    p_scan.add_argument("--watchlist", required=True, help="path to watchlist.yml")
    p_scan.add_argument("--db", help="optional SQLite path to persist findings")
    p_scan.add_argument("--all", action="store_true", help="print every finding, not just new ones")
    p_scan.set_defaults(func=cmd_scan_file)

    p_stream = sub.add_parser("stream", help="poll a live CT log and score new certs")
    p_stream.add_argument("--watchlist", required=True, help="path to watchlist.yml")
    p_stream.add_argument("--db", required=True, help="SQLite path to persist findings")
    p_stream.add_argument("--log-url", help="specific CT log base URL; default: first usable log")
    p_stream.add_argument("--backfill", type=int, default=0,
                           help="also scan this many existing entries before the current tip")
    p_stream.add_argument("--batch-size", type=int, default=256, help="entries per get-entries request")
    p_stream.add_argument("--poll-interval", type=float, default=5.0, help="seconds between get-sth polls")
    p_stream.add_argument("--seconds", type=float, default=None,
                           help="keep polling for this many seconds; default: stop once caught up")
    p_stream.set_defaults(func=cmd_stream)

    p_serve = sub.add_parser("serve", help="serve a read-only dashboard over stored findings")
    p_serve.add_argument("--db", required=True, help="SQLite path written by 'stream' or 'scan-file'")
    p_serve.add_argument("--port", type=int, default=8787)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except requests.RequestException as exc:
        print(f"network error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
