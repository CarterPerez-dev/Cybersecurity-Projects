"""
©AngelaMos | 2026
firewall.py
"""

import time

from not_sandboxed import config
from not_sandboxed.context import Context, Span, Trust
from not_sandboxed.layers import Layer
from not_sandboxed.layers.ingress import IngressLayer
from not_sandboxed.layers.normalize import NormalizeLayer
from not_sandboxed.layers.provenance import ProvenanceLayer
from not_sandboxed.policy import Policy, decide, escalate
from not_sandboxed.verdict import Finding, Severity, Verdict


def _fence(span: Span, nonce: str) -> str:
    origin = span.origin
    channel = origin.channel if origin is not None else "unknown"
    ref = origin.ref if origin is not None else "unknown"

    opened = config.FENCE_OPEN.format(
        nonce = nonce,
        channel = channel,
        ref = ref,
    )
    closed = config.FENCE_CLOSE.format(nonce = nonce)
    return f"{opened}\n{span.text}\n{closed}"


def render(ctx: Context) -> str:
    """
    Build the prompt, fencing every untrusted span with a delimiter its
    own content cannot forge
    """
    parts: list[str] = []

    for span in ctx.spans:
        if span.trust is Trust.DATA:
            parts.append(_fence(span, ctx.nonce))
        else:
            parts.append(span.text)

    return "\n".join(parts)


class Firewall:
    """
    Runs every enabled layer, fails closed on any of them, and resolves
    what they found into a decision
    """
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.layers: dict[str,
                          Layer] = {
                              config.LAYER_NORMALIZE: NormalizeLayer(),
                              config.LAYER_INGRESS: IngressLayer(),
                              config.LAYER_PROVENANCE: ProvenanceLayer(),
                          }

    def _enabled(self, name: str) -> bool:
        return bool(getattr(self.policy, f"{name}_enabled", True))

    def _run(self, name: str, ctx: Context) -> list[Finding]:
        if not self._enabled(name):
            return [
                Finding(
                    layer = name,
                    rule = config.RULE_LAYER_DISABLED,
                    severity = Severity.INFO,
                    invariant = False,
                    evidence = "layer disabled by policy",
                )
            ]

        try:
            return self.layers[name].inspect(ctx, self.policy)
        except Exception as error:
            return [
                Finding(
                    layer = name,
                    rule = config.RULE_LAYER_ERROR,
                    severity = Severity.CRITICAL,
                    invariant = True,
                    evidence = type(error).__name__,
                )
            ]

    def inspect(self, ctx: Context) -> Verdict:
        """
        Inspect a context with every enabled layer and resolve the
        findings into a decision
        """
        started = time.perf_counter()
        findings: list[Finding] = []

        for name in config.LAYER_ORDER:
            findings.extend(self._run(name, ctx))

        findings = escalate(findings, self.policy)
        elapsed = (time.perf_counter() - started) * 1000.0

        return Verdict(
            decision = decide(findings,
                              self.policy),
            findings = tuple(findings),
            policy_id = self.policy.policy_id,
            elapsed_ms = elapsed,
        )

    def render(self, ctx: Context) -> str:
        """
        Build the fenced prompt for this context
        """
        return render(ctx)
