"""
©AngelaMos | 2026
toolauth.py
"""

from collections.abc import Iterable, Mapping

from not_sandboxed import config
from not_sandboxed.context import Context
from not_sandboxed.policy import Policy
from not_sandboxed.tools import Guard, Tool, ToolCallRequest
from not_sandboxed.verdict import Finding, Severity


class ToolAuthLayer:
    """
    The model requests an action and this decides whether it happens,
    without ever consulting the model's stated reason
    """

    name = config.LAYER_TOOLAUTH

    def __init__(self, registry: Mapping[str, Tool]) -> None:
        self.registry = dict(registry)

    def _finding(self, rule: str, evidence: str) -> Finding:
        return Finding(
            layer = config.LAYER_TOOLAUTH,
            rule = rule,
            severity = Severity.CRITICAL,
            invariant = True,
            evidence = evidence,
        )

    def inspect_call(
        self,
        request: ToolCallRequest,
        ctx: Context,
        policy: Policy,
    ) -> list[Finding]:
        """
        Authorize one requested tool call against the registry and the
        taint the context has already picked up
        """
        tool = self.registry.get(request.name)
        if tool is None:
            return [
                self._finding(
                    config.RULE_TOOL_UNKNOWN,
                    request.name,
                )
            ]

        return [
            *self._argument_findings(tool,
                                     request),
            *self._guard_findings(tool,
                                  request,
                                  ctx),
        ]

    def _argument_findings(
        self,
        tool: Tool,
        request: ToolCallRequest,
    ) -> Iterable[Finding]:
        missing = tool.required_args - request.args.keys()
        if missing:
            yield self._finding(
                config.RULE_TOOL_ARGS_INVALID,
                f"{tool.name} missing {sorted(missing)}",
            )

    def _guard_findings(
        self,
        tool: Tool,
        request: ToolCallRequest,
        ctx: Context,
    ) -> Iterable[Finding]:
        if (Guard.NO_UNTRUSTED_INFLUENCE in tool.guards
                and ctx.tainted_by):
            origins = ",".join(
                f"{origin.channel}:{origin.ref}"
                for origin in ctx.tainted_by
            )
            yield self._finding(
                config.RULE_TAINTED_ACTION,
                f"{tool.name} downstream of {origins}",
            )

        if Guard.ARGS_ALLOWLISTED in tool.guards:
            for key, allowed in tool.allowlists.items():
                value = request.args.get(key)
                if value is not None and value not in allowed:
                    yield self._finding(
                        config.RULE_TOOL_NOT_ALLOWLISTED,
                        f"{tool.name}.{key}",
                    )
