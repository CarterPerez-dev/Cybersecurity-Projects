"""
©AngelaMos | 2026
cli.py
"""

import argparse
import sys
from collections.abc import Sequence

from not_sandboxed import __version__, config
from not_sandboxed.context import Context, Origin, Trust
from not_sandboxed.firewall import Firewall
from not_sandboxed.policy import Policy
from not_sandboxed.tools import AgentReply
from not_sandboxed.verdict import Decision, Verdict


def _read(text: str | None) -> str:
    if text is not None:
        return text
    if sys.stdin.isatty():
        return ""
    return sys.stdin.read()


def _context(text: str, trust: str) -> Context:
    ctx = Context()
    if trust == Trust.SYSTEM:
        return ctx.system(text)
    if trust == Trust.USER:
        return ctx.user(text)
    return ctx.data(
        text,
        origin = Origin(
            channel = config.CLI_DEFAULT_CHANNEL,
            ref = config.CLI_DEFAULT_REF,
        ),
    )


def _report(verdict: Verdict) -> None:
    print(
        config.CLI_VERDICT_LINE.format(
            decision = str(verdict.decision).upper(),
            elapsed = verdict.elapsed_ms,
            policy = verdict.policy_id,
        )
    )

    fired = [
        finding for finding in verdict.findings
        if finding.rule != config.RULE_LAYER_DISABLED
    ]
    if not fired:
        print(config.CLI_NO_FINDINGS)
        return

    for finding in fired:
        print(
            config.CLI_FINDING_LINE.format(
                mark = (
                    config.CLI_INVARIANT_MARK
                    if finding.invariant else config.CLI_SCORED_MARK
                ),
                layer = finding.layer,
                rule = finding.rule,
                severity = finding.severity.name,
            )
        )


def _status(verdict: Verdict) -> int:
    return 1 if verdict.decision is Decision.BLOCK else 0


def _inspect(args: argparse.Namespace) -> int:
    text = _read(args.text)
    if not text:
        print(config.CLI_EMPTY_INPUT, file = sys.stderr)
        return 2

    firewall = Firewall(Policy(strict_data = not args.lenient))
    verdict = firewall.inspect(_context(text, args.trust))

    _report(verdict)
    if args.trust == Trust.DATA:
        print(config.CLI_INGRESS_CAVEAT, file = sys.stderr)
    return _status(verdict)


def _egress(args: argparse.Namespace) -> int:
    text = _read(args.text)
    if not text:
        print(config.CLI_EMPTY_INPUT, file = sys.stderr)
        return 2

    policy = Policy(
        canaries = tuple(args.canary),
        allowed_hosts = tuple(args.allow_host),
    )
    firewall = Firewall(policy)
    verdict = firewall.inspect_egress(
        AgentReply(text = text),
        Context().user(""),
    )

    _report(verdict)
    return _status(verdict)


def _bench(args: argparse.Namespace) -> int:
    try:
        from bench.runner import format_report, run, run_ablation
    except ImportError:
        print(config.CLI_BENCH_UNAVAILABLE, file = sys.stderr)
        return 2

    print(format_report(run(), run_ablation()))
    return 0


def _serve(factory: str, host: str, port: int) -> int:
    import uvicorn

    uvicorn.run(factory, factory = True, host = host, port = port)
    return 0


def _proxy(args: argparse.Namespace) -> int:
    return _serve(
        "not_sandboxed.proxy.app:build_app",
        args.host,
        args.port,
    )


def _arena(args: argparse.Namespace) -> int:
    return _serve(
        "not_sandboxed.arena.app:build_arena",
        args.host,
        args.port,
    )


def _text_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "text",
        nargs = "?",
        default = None,
        help = "text to inspect; reads stdin when omitted",
    )


def build_parser() -> argparse.ArgumentParser:
    """
    Build the argument parser, which is also the only place the
    command surface is described
    """
    parser = argparse.ArgumentParser(
        prog = config.CLI_PROGRAM,
        description = config.CLI_DESCRIPTION,
        epilog = config.CLI_EPILOG,
    )
    parser.add_argument(
        "--version",
        action = "version",
        version = f"{config.CLI_PROGRAM} {__version__}",
    )
    sub = parser.add_subparsers(dest = "command", required = True)

    inspect = sub.add_parser(
        "inspect",
        help = "inspect text on the way in to a model",
    )
    _text_argument(inspect)
    inspect.add_argument(
        "--trust",
        choices = config.CLI_TRUST_CHOICES,
        default = config.CLI_DEFAULT_TRUST,
        help = "provenance of the text; this decides the verdict",
    )
    inspect.add_argument(
        "--lenient",
        action = "store_true",
        help = "score instruction-shaped text instead of blocking it",
    )
    inspect.set_defaults(run = _inspect)

    egress = sub.add_parser(
        "egress",
        help = "inspect model output on the way out",
    )
    _text_argument(egress)
    egress.add_argument(
        "--canary",
        action = "append",
        default = [],
        help = "a secret that must not leave, in any encoding",
    )
    egress.add_argument(
        "--allow-host",
        action = "append",
        default = [],
        help = "permitted host; a leading dot covers subdomains",
    )
    egress.set_defaults(run = _egress)

    bench = sub.add_parser(
        "bench",
        help = "run the benchmark and the per-layer ablation",
    )
    bench.set_defaults(run = _bench)

    proxy = sub.add_parser(
        "proxy",
        help = "serve the OpenAI-compatible proxy",
    )
    proxy.add_argument("--host", default = config.CLI_DEFAULT_HOST)
    proxy.add_argument(
        "--port",
        type = int,
        default = config.CLI_PROXY_PORT,
    )
    proxy.set_defaults(run = _proxy)

    arena = sub.add_parser("arena", help = "serve the arena")
    arena.add_argument("--host", default = config.CLI_DEFAULT_HOST)
    arena.add_argument(
        "--port",
        type = int,
        default = config.CLI_ARENA_PORT,
    )
    arena.set_defaults(run = _arena)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """
    Entry point, returning the exit status rather than raising
    """
    args = build_parser().parse_args(argv)
    status: int = args.run(args)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
