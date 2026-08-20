"""
©AngelaMos | 2026
firewall.py
"""

import time
from collections.abc import Mapping

from not_sandboxed import config
from not_sandboxed.context import Context, Span, Trust
from not_sandboxed.layers import Layer
from not_sandboxed.layers.egress import EgressLayer
from not_sandboxed.layers.ingress import IngressLayer
from not_sandboxed.layers.normalize import NormalizeLayer
from not_sandboxed.layers.provenance import ProvenanceLayer
from not_sandboxed.layers.toolauth import ToolAuthLayer
from not_sandboxed.policy import Policy, PolicyError, decide, escalate
from not_sandboxed.tools import AgentReply, Tool, render_arg
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
    def __init__(
        self,
        policy: Policy,
        registry: Mapping[str,
                          Tool] | None = None,
    ) -> None:
        self.policy = policy
        self.layers: dict[str,
                          Layer] = {
                              config.LAYER_NORMALIZE: NormalizeLayer(),
                              config.LAYER_INGRESS: IngressLayer(),
                              config.LAYER_PROVENANCE: ProvenanceLayer(),
                          }
        self.toolauth = ToolAuthLayer(registry = registry or {})
        self.egress = EgressLayer(
            canaries = policy.canaries,
            allowed_hosts = policy.allowed_hosts,
        )

        if self.egress.rejected:
            raise PolicyError(
                config.CANARY_REJECTED.format(
                    count = len(self.egress.rejected),
                    minimum = config.MIN_CANARY_LENGTH,
                )
            )

    def _enabled(self, name: str) -> bool:
        return bool(getattr(self.policy, f"{name}_enabled", True))

    def _disabled(self, name: str) -> Finding:
        return Finding(
            layer = name,
            rule = config.RULE_LAYER_DISABLED,
            severity = Severity.INFO,
            invariant = False,
            evidence = "layer disabled by policy",
        )

    def _layer_error(self, name: str, error: Exception) -> Finding:
        return Finding(
            layer = name,
            rule = config.RULE_LAYER_ERROR,
            severity = Severity.CRITICAL,
            invariant = True,
            evidence = type(error).__name__,
        )

    def _run(self, name: str, ctx: Context) -> list[Finding]:
        if not self._enabled(name):
            return [self._disabled(name)]

        try:
            return self.layers[name].inspect(ctx, self.policy)
        except Exception as error:
            return [self._layer_error(name, error)]

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

    def inspect_egress(
        self,
        reply: AgentReply,
        ctx: Context,
    ) -> Verdict:
        """
        Authorize what the model wants to do and refuse anything that
        would carry a registered secret out
        """
        started = time.perf_counter()
        findings: list[Finding] = []

        findings.extend(self._run_toolauth(reply, ctx))
        findings.extend(self._run_egress(reply))

        elapsed = (time.perf_counter() - started) * 1000.0

        return Verdict(
            decision = decide(findings,
                              self.policy),
            findings = tuple(findings),
            policy_id = self.policy.policy_id,
            elapsed_ms = elapsed,
        )

    def _run_toolauth(
        self,
        reply: AgentReply,
        ctx: Context,
    ) -> list[Finding]:
        if not self.policy.toolauth_enabled:
            return [self._disabled(config.LAYER_TOOLAUTH)]

        try:
            findings: list[Finding] = []
            for call in reply.tool_calls:
                findings.extend(
                    self.toolauth.inspect_call(
                        call,
                        ctx,
                        self.policy,
                    )
                )
        except Exception as error:
            return [self._layer_error(config.LAYER_TOOLAUTH, error)]
        else:
            return findings

    def _run_egress(self, reply: AgentReply) -> list[Finding]:
        if not self.policy.egress_enabled:
            return [self._disabled(config.LAYER_EGRESS)]

        try:
            surfaces = egress_surfaces(reply)
            budget = sum(len(surface) for surface in surfaces)
            if budget > config.MAX_EGRESS_BYTES:
                return [
                    Finding(
                        layer = config.LAYER_EGRESS,
                        rule = config.RULE_OUTPUT_TOO_LARGE,
                        severity = Severity.CRITICAL,
                        invariant = True,
                        evidence = f"{budget} chars across the reply",
                    )
                ]

            findings: list[Finding] = []
            for surface in surfaces:
                findings.extend(self.egress.inspect_text(surface))
        except Exception as error:
            return [self._layer_error(config.LAYER_EGRESS, error)]
        else:
            return findings

    def render(self, ctx: Context) -> str:
        """
        Build the fenced prompt for this context
        """
        return render(ctx)


def egress_surfaces(reply: AgentReply) -> tuple[str, ...]:
    """
    Every piece of a reply that leaves the boundary, which is the prose
    and every tool argument value flattened to text
    """
    return (
        reply.text,
        *(
            render_arg(value)
            for call in reply.tool_calls
            for value in call.args.values()
        ),
    )
