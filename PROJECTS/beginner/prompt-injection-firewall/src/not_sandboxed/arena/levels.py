"""
©AngelaMos | 2026
levels.py
"""

from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict
from ruamel.yaml import YAML

from not_sandboxed import config
from not_sandboxed.policy import Policy


POLICY_DIR: Final = Path(__file__).parent / "policies"


class Level(BaseModel):
    """
    One rung of the ladder, which is a firewall configuration and a
    sentence about what turning that layer on teaches
    """

    model_config = ConfigDict(frozen = True)

    number: int
    title: str
    teaches: str
    policy: Policy


def _load(path: Path) -> Level:
    document = YAML(typ = "safe").load(path.read_text())
    number = int(path.stem.rsplit("-", 1)[1])

    policy = Policy(
        policy_id = document["policy_id"],
        strict_data = document["strict_data"],
        normalize_enabled = document["normalize_enabled"],
        ingress_enabled = document["ingress_enabled"],
        provenance_enabled = document["provenance_enabled"],
        toolauth_enabled = document["toolauth_enabled"],
        egress_enabled = document["egress_enabled"],
        allowed_hosts = config.ARENA_ALLOWED_HOSTS,
    )

    return Level(
        number = number,
        title = document["title"],
        teaches = document["teaches"],
        policy = policy,
    )


def load_levels() -> dict[int, Level]:
    """
    Read every level policy, keyed by its number
    """
    return {
        level.number: level
        for level in
        (_load(path) for path in sorted(POLICY_DIR.glob("*.yaml")))
    }


LEVELS: Final = load_levels()


def active_layers(level: Level) -> tuple[str, ...]:
    """
    Name the layers this level has switched on, so a player is never
    left guessing whether they beat a layer or were handed the win
    """
    policy = level.policy
    return tuple(
        name for name in (
            *config.LAYER_ORDER,
            *config.EGRESS_LAYER_ORDER,)
        if getattr(policy, f"{name}_enabled")
    )
