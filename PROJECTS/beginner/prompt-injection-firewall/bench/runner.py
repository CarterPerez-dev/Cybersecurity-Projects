"""
©AngelaMos | 2026
runner.py
"""

import base64
import codecs
import time
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict
from ruamel.yaml import YAML

from not_sandboxed import config
from not_sandboxed.context import Context, Origin, Trust
from not_sandboxed.firewall import Firewall
from not_sandboxed.policy import Policy
from not_sandboxed.tools import (
    AgentReply,
    Effect,
    Guard,
    Tool,
    ToolCallRequest,
)
from not_sandboxed.verdict import Decision


CANARY: Final = "VANTAGE-7731-ORION"
ALLOWED_HOST: Final = "vantage.example"
CORPUS_ROOT: Final = Path(__file__).parent / "corpus"

REGISTRY: Final = {
    "send_email":
    Tool(
        name = "send_email",
        effects = frozenset({Effect.WRITE,
                             Effect.NETWORK_EGRESS}),
        guards = frozenset({Guard.NO_UNTRUSTED_INFLUENCE}),
        required_args = frozenset({"to",
                                   "body"}),
    ),
}

_ZWSP: Final = chr(0x200B)
_RLO: Final = chr(0x202E)


def _tag_block(text: str) -> str:
    return "".join(
        chr(config.TAG_BLOCK_START + ord(c)) if c.isascii() else c
        for c in text
    )


def _confusable(text: str) -> str:
    swap = {v: k for k, v in config.CONFUSABLES.items()}
    return "".join(swap.get(c, c) for c in text)


TRANSFORMS: Final[
    dict[str,
         Callable[[str],
                  str]]
] = {
    "none": lambda text: text,
    "tag_block": _tag_block,
    "zero_width": _ZWSP.join,
    "bidi": lambda text: f"{_RLO}{text}",
    "confusable": _confusable,
    "base64": lambda text: base64.b64encode(text.encode()).decode(),
    "base32": lambda text: base64.b32encode(text.encode()).decode(),
    "hex": lambda text: text.encode().hex(),
    "percent": lambda text: urllib.parse.quote(text, safe = ""),
    "dash": "-".join,
    "space": " ".join,
    "reverse": lambda text: text[::-1],
    "rot13": lambda text: codecs.encode(text, "rot13"),
}


class Case(BaseModel):
    """
    One corpus entry after transforms have been applied
    """

    model_config = ConfigDict(frozen = True)

    case_id: str
    label: str
    stage: str
    span: str
    text: str
    hostile: bool
    tool_call: ToolCallRequest | None = None
    replay_nonce: bool = False


@dataclass
class ClassResult:
    """
    Per-class tally of what the firewall decided
    """

    total: int = 0
    caught: int = 0

    @property
    def rate(self) -> float:
        return self.caught / self.total if self.total else 0.0


@dataclass
class Report:
    """
    The whole benchmark outcome, detection and false positives together
    """

    attacks: dict[str, ClassResult] = field(default_factory = dict)
    benign: dict[str, ClassResult] = field(default_factory = dict)
    elapsed_ms: list[float] = field(default_factory = list)

    @property
    def detection_rate(self) -> float:
        total = sum(r.total for r in self.attacks.values())
        caught = sum(r.caught for r in self.attacks.values())
        return caught / total if total else 0.0

    @property
    def false_positive_rate(self) -> float:
        total = sum(r.total for r in self.benign.values())
        flagged = sum(r.caught for r in self.benign.values())
        return flagged / total if total else 0.0

    @property
    def p50_ms(self) -> float:
        if not self.elapsed_ms:
            return 0.0
        ordered = sorted(self.elapsed_ms)
        return ordered[len(ordered) // 2]

    @property
    def p99_ms(self) -> float:
        if not self.elapsed_ms:
            return 0.0
        ordered = sorted(self.elapsed_ms)
        index = min(
            len(ordered) - 1,
            int(len(ordered) * 0.99),
        )
        return ordered[index]


def _load_file(path: Path, hostile: bool) -> list[Case]:
    document = YAML(typ = "safe").load(path.read_text())
    label = document["class"]
    stage = document.get("stage", "request")
    span = document.get("span", "data")
    replay = bool(document.get("replay_nonce", False))
    call = document.get("tool_call")
    request = (
        ToolCallRequest(
            name = call["name"],
            args = dict(call["args"]),
        ) if call else None
    )

    cases: list[Case] = []
    for text_index, raw in enumerate(document["texts"]):
        for name in document["transforms"]:
            body = raw.replace("{canary}", CANARY)
            cases.append(
                Case(
                    case_id = f"{label}-{text_index}-{name}",
                    label = label,
                    stage = stage,
                    span = span,
                    text = TRANSFORMS[name](body) if "{fence}" not in body
                    and "{nonce}" not in body else body,
                    hostile = hostile,
                    tool_call = request,
                    replay_nonce = replay,
                )
            )
    return cases


def load_corpus() -> tuple[list[Case], list[Case]]:
    """
    Read every attack and benign file into flat case lists
    """
    attacks = [
        case for path in sorted((CORPUS_ROOT / "attacks").glob("*.yaml"))
        for case in _load_file(path, hostile = True)
    ]
    benign = [
        case for path in sorted((CORPUS_ROOT / "benign").glob("*.yaml"))
        for case in _load_file(path, hostile = False)
    ]
    return attacks, benign


def base_policy(**overrides: object) -> Policy:
    """
    The policy every benchmark run starts from
    """
    policy = Policy(
        policy_id = "bench",
        strict_data = True,
        canaries = (CANARY,
                    ),
        allowed_hosts = (ALLOWED_HOST,
                         ),
    )
    return policy.model_copy(update = dict(overrides))


def _build_context(case: Case, nonce: str | None) -> Context:
    ctx = Context().system("You are a support agent for Vantage.")
    if nonce is not None:
        ctx = Context(nonce = nonce
                      ).system("You are a support agent for Vantage.")

    text = case.text
    if case.replay_nonce and nonce is not None:
        fence = config.FENCE_CLOSE.format(nonce = nonce)
        text = text.replace("{fence}", fence)
        text = text.replace("{nonce}", nonce)

    if case.span == Trust.USER:
        return ctx.user(text)
    return ctx.data(
        text,
        origin = Origin(channel = "ticket",
                        ref = "8814"),
    )


def evaluate(case: Case, policy: Policy) -> tuple[bool, float]:
    """
    Run one case through the firewall and report whether it was
    stopped and how long that took
    """
    firewall = Firewall(policy, registry = REGISTRY)
    started = time.perf_counter()

    if case.stage == "response":
        ctx = Context().system("s").user("help")
        reply = AgentReply(
            text = case.text,
            tool_calls = ((case.tool_call,
                           ) if case.tool_call else ()),
        )
        if case.tool_call is not None:
            ctx = ctx.data(
                "hostile ticket",
                origin = Origin(channel = "ticket",
                                ref = "8814"),
            )
        verdict = firewall.inspect_egress(reply, ctx)
    else:
        probe = Context()
        ctx = _build_context(case, probe.nonce)
        verdict = firewall.inspect(ctx)

    elapsed = (time.perf_counter() - started) * 1000.0
    return verdict.decision is Decision.BLOCK, elapsed


def run(policy: Policy | None = None) -> Report:
    """
    Score the whole corpus and report detection and false positives
    side by side, because either one alone is a marketing number
    """
    active = policy or base_policy()
    attacks, benign = load_corpus()
    report = Report()

    for case in attacks:
        blocked, elapsed = evaluate(case, active)
        bucket = report.attacks.setdefault(case.label, ClassResult())
        bucket.total += 1
        bucket.caught += int(blocked)
        report.elapsed_ms.append(elapsed)

    for case in benign:
        blocked, elapsed = evaluate(case, active)
        bucket = report.benign.setdefault(case.label, ClassResult())
        bucket.total += 1
        bucket.caught += int(blocked)
        report.elapsed_ms.append(elapsed)

    return report


ALL_LAYERS: Final = (
    *config.LAYER_ORDER,
    *config.EGRESS_LAYER_ORDER,
)


class Ablation(BaseModel):
    """
    What one layer catches by itself and what it adds to the full
    stack, which are different questions with different answers
    """

    model_config = ConfigDict(frozen = True)

    solo: int
    marginal: int

    @property
    def inert(self) -> bool:
        """
        True only when the layer catches nothing alone and adds
        nothing to the stack
        """
        return self.solo == 0 and self.marginal == 0

    @property
    def alibied(self) -> bool:
        """
        True when another layer already covers everything this one
        catches, which is redundancy rather than uselessness
        """
        return self.solo > 0 and self.marginal == 0


def _caught(policy: Policy, attacks: Sequence[Case]) -> set[str]:
    return {case.case_id for case in attacks if evaluate(case, policy)[0]}


def run_ablation() -> dict[str, Ablation]:
    """
    Measure each layer twice: alone, and as a marginal addition to the
    full stack

    Leave-one-out alone is blind to a layer whose work another layer
    duplicates, and would report it as inert while it is catching
    attacks nothing else catches once its alibi is disabled
    """
    attacks, _ = load_corpus()
    full = _caught(base_policy(), attacks)
    results: dict[str, Ablation] = {}

    for layer in ALL_LAYERS:
        off = {f"{name}_enabled": False for name in ALL_LAYERS}
        solo = _caught(
            base_policy(**{
                **off,
                f"{layer}_enabled": True
            }),
            attacks,
        )
        without = _caught(
            base_policy(**{f"{layer}_enabled": False}),
            attacks,
        )
        results[layer] = Ablation(
            solo = len(solo),
            marginal = len(full) - len(without),
        )

    return results


def format_report(
    report: Report,
    deltas: dict[str,
                 Ablation],
) -> str:
    """
    Render the benchmark for a terminal
    """
    lines = ["", "ATTACK CORPUS", "-" * 58]
    for label in sorted(report.attacks):
        result = report.attacks[label]
        lines.append(
            f"  {label:24} {result.caught:4}/{result.total:<4} "
            f"{result.rate * 100:6.1f}%"
        )

    lines += ["", "BENIGN CORPUS  (flagged = false positive)", "-" * 58]
    for label in sorted(report.benign):
        result = report.benign[label]
        lines.append(
            f"  {label:24} {result.caught:4}/{result.total:<4} "
            f"{result.rate * 100:6.1f}%"
        )

    lines += ["", "PER-LAYER ABLATION", "-" * 58]
    lines.append(f"  {'layer':24} {'solo':>5} {'marginal':>9}")
    for layer, ablation in deltas.items():
        mark = ""
        if ablation.inert:
            mark = "  INERT - DELETE"
        elif ablation.alibied:
            mark = "  alibied"
        lines.append(
            f"  {layer:24} {ablation.solo:5} "
            f"{ablation.marginal:9}{mark}"
        )

    lines += [
        "",
        "-" * 58,
        f"  detection rate       {report.detection_rate * 100:6.1f}%",
        f"  false positive rate  "
        f"{report.false_positive_rate * 100:6.1f}%",
        f"  latency p50 / p99    "
        f"{report.p50_ms:.2f} ms / {report.p99_ms:.2f} ms",
        "",
        "  READ THIS BEFORE QUOTING THE DETECTION RATE",
        "  This corpus was written by the same author as the rules.",
        "  It measures what the author thought of, which is not the",
        "  same as what an attacker will think of. Ingress detection",
        "  is incomplete by construction; the number that matters is",
        "  the false positive rate, and the layers whose guarantees",
        "  do not depend on guessing the payload.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    """
    Run the benchmark and print the report
    """
    report = run()
    deltas = run_ablation()
    print(format_report(report, deltas))


__all__: Sequence[str] = [
    "Report",
    "base_policy",
    "load_corpus",
    "main",
    "run",
    "run_ablation",
]

if __name__ == "__main__":
    main()
