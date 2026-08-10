"""
©AngelaMos | 2026
harvest.py
"""

from collections.abc import Sequence
from pathlib import Path

from not_sandboxed import config


class HarvestRefusedError(Exception):
    """
    Raised when a harvest would write untrusted input somewhere the
    firewall treats as ground truth
    """


def _guard(target: Path) -> None:
    parts = {part for part in target.parts}
    for protected in config.HARVEST_PROTECTED_DIRS:
        if protected in parts:
            raise HarvestRefusedError(
                config.HARVEST_REFUSAL.format(target = target)
            )


def harvest(
    payloads: Sequence[str],
    corpus_root: Path,
) -> Path:
    """
    Write bypass candidates somewhere a human reviews them, never into
    the corpus the benchmark scores against
    """
    target = corpus_root / config.HARVEST_CANDIDATE_DIR
    _guard(target)

    target.mkdir(parents = True, exist_ok = True)
    destination = target / "harvested.yaml"

    lines = [
        "# ©AngelaMos | 2026",
        "# harvested.yaml",
        "",
        "# Candidates only. Review each one by hand and move it into",
        "# an attack class deliberately. Nothing here is scored.",
        "",
        "class: candidate",
        "stage: request",
        "span: data",
        "texts:",
    ]
    lines += [f"  - {payload!r}" for payload in payloads]
    lines += ["transforms:", "  - none", ""]

    destination.write_text("\n".join(lines))
    return destination
