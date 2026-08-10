"""
©AngelaMos | 2026
app.py
"""

import logging
from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from not_sandboxed import config
from not_sandboxed.agent import Agent
from not_sandboxed.agent.mock import MockAgent
from not_sandboxed.context import Context
from not_sandboxed.firewall import Firewall
from not_sandboxed.policy import Policy
from not_sandboxed.proxy.infer import infer_context
from not_sandboxed.tools import AgentReply, Tool
from not_sandboxed.verdict import Decision, Verdict


_log = logging.getLogger(__name__)


class ChatRequest(BaseModel):
    """
    The subset of the OpenAI chat completion request this proxy reads
    """

    model: str = config.PROXY_MODEL_NAME
    messages: list[dict[str, str]] = []


def _verdict_payload(verdict: Verdict) -> dict[str, Any]:
    return {
        "decision":
        str(verdict.decision),
        "policy_id":
        verdict.policy_id,
        "findings": [
            {
                "layer": finding.layer,
                "rule": finding.rule,
                "severity": finding.severity.name,
                "invariant": finding.invariant,
            } for finding in verdict.findings
        ],
    }


def _completion(
    text: str,
    finish_reason: str,
    verdict: Verdict,
) -> dict[str,
          Any]:
    return {
        "object":
        config.PROXY_OBJECT_NAME,
        "model":
        config.PROXY_MODEL_NAME,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text,
                },
                "finish_reason": finish_reason,
            }
        ],
        config.PROXY_VERDICT_FIELD:
        _verdict_payload(verdict),
    }


def build_app(
    policy: Policy,
    registry: Mapping[str,
                      Tool] | None = None,
    upstream: Agent | None = None,
) -> FastAPI:
    """
    Build the OpenAI-compatible proxy, announcing on the way up that
    provenance here is inferred rather than declared
    """
    _log.warning(config.PROXY_WEAK_MODE_WARNING)

    app = FastAPI(title = config.PROXY_MODEL_NAME)
    agent = upstream or MockAgent(
        secret = policy.canaries[0] if policy.canaries else ""
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {
            "policy_id": policy.policy_id,
            "mode": "inferred-provenance",
        }

    @app.post("/v1/chat/completions")
    def completions(request: ChatRequest) -> dict[str, Any]:
        firewall = Firewall(policy, registry = registry or {})
        ctx = infer_context(request.messages)

        inbound = firewall.inspect(ctx)
        if inbound.decision is Decision.BLOCK:
            return _completion(
                config.PROXY_BLOCK_MESSAGE,
                config.PROXY_FINISH_REASON_BLOCKED,
                inbound,
            )

        reply = _ask(agent, firewall, ctx)
        outbound = firewall.inspect_egress(reply, ctx)
        if outbound.decision is Decision.BLOCK:
            return _completion(
                config.PROXY_BLOCK_MESSAGE,
                config.PROXY_FINISH_REASON_BLOCKED,
                outbound,
            )

        return _completion(
            reply.text,
            config.PROXY_FINISH_REASON_OK,
            outbound,
        )

    return app


def _ask(
    agent: Agent,
    firewall: Firewall,
    ctx: Context,
) -> AgentReply:
    return agent.respond(firewall.render(ctx))


__all__: Sequence[str] = ["build_app"]
