"""
©AngelaMos | 2026
harvest.py
"""

import os
import sys
from collections.abc import Sequence
from io import StringIO
from pathlib import Path

import orjson
from ruamel.yaml import YAML

from not_sandboxed import config


class HarvestRefusedError(Exception):
    """
    Raised when a harvest would write untrusted input somewhere the
    firewall treats as ground truth
    """


class BypassLog:
    """
    Append-only record of the payloads that beat the bounty level

    The session store lives in one process and dies with it, so a
    bypass that is only remembered in memory cannot be reviewed and
    the harvest recipe has nothing to read
    """
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        if path is not None:
            path.parent.mkdir(parents = True, exist_ok = True)

    @property
    def enabled(self) -> bool:
        """
        Whether this log has somewhere to write
        """
        return self.path is not None

    def write(self, level: int, ticket: str) -> None:
        """
        Append one bypass, doing nothing when the log is disabled
        """
        if self.path is None:
            return

        record = {"level": str(level), "ticket": ticket}
        with self.path.open("ab") as sink:
            sink.write(orjson.dumps(record) + b"\n")


def bypass_log_from_env(variable: str) -> BypassLog:
    """
    Build the bypass sink named by an environment variable, disabled
    when the variable is unset or empty
    """
    raw = os.environ.get(variable, "").strip()
    return BypassLog(Path(raw) if raw else None)


def read_bypasses(source: Path) -> list[str]:
    """
    Every recorded bypass ticket, in the order they were won
    """
    if not source.exists():
        return []

    tickets: list[str] = []
    for line in source.read_bytes().splitlines():
        if not line.strip():
            continue
        record = orjson.loads(line)
        ticket = record.get("ticket")
        if ticket:
            tickets.append(ticket)
    return tickets


def _guard(target: Path) -> None:
    parts = set(target.parts)
    for protected in config.HARVEST_PROTECTED_DIRS:
        if protected in parts:
            raise HarvestRefusedError(
                config.HARVEST_REFUSAL.format(target = target)
            )


def _document(payloads: Sequence[str]) -> str:
    yaml = YAML()
    yaml.default_flow_style = False
    stream = StringIO()
    yaml.dump(
        {
            "class": config.HARVEST_CLASS,
            "stage": config.HARVEST_STAGE,
            "span": config.HARVEST_SPAN,
            "texts": list(payloads),
            "transforms": [config.HARVEST_TRANSFORM],
        },
        stream,
    )
    return stream.getvalue()


def harvest(
    payloads: Sequence[str],
    corpus_root: Path,
) -> Path:
    """
    Write bypass candidates somewhere a human reviews them, never into
    the corpus the benchmark scores against

    Serialisation goes through the YAML emitter rather than repr, which
    turns a newline into a literal backslash-n and emits quoting no
    loader accepts, corrupting the payload this exists to preserve
    """
    target = corpus_root / config.HARVEST_CANDIDATE_DIR
    _guard(target)

    target.mkdir(parents = True, exist_ok = True)
    destination = target / config.HARVEST_FILENAME
    destination.write_text(config.HARVEST_HEADER + _document(payloads))
    return destination


def main() -> int:
    """
    Export recorded bypass candidates for review
    """
    if len(sys.argv) < 3:
        print(config.HARVEST_USAGE.format(program = sys.argv[0]))
        return 2

    payloads = read_bypasses(Path(sys.argv[1]))
    if not payloads:
        print(config.HARVEST_EMPTY)
        return 0

    destination = harvest(payloads, Path(sys.argv[2]))
    print(
        config.HARVEST_WROTE.format(
            count = len(payloads),
            target = destination,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
