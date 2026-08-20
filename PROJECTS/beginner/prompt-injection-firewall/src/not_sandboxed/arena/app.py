"""
©AngelaMos | 2026
app.py
"""

from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from not_sandboxed import config
from not_sandboxed.agent.mock import MockAgent
from not_sandboxed.arena.levels import LEVELS, Level, active_layers
from not_sandboxed.arena.harvest import BypassLog, bypass_log_from_env
from not_sandboxed.arena.session import (
    RateLimitedError,
    Session,
    SessionStore,
)
from not_sandboxed.audit import AuditLog, audit_log_from_env
from not_sandboxed.context import Context, Origin
from not_sandboxed.firewall import Firewall, egress_surfaces
from not_sandboxed.layers.egress import EgressLayer
from not_sandboxed.policy import Policy
from not_sandboxed.tools import AgentReply, Effect, Guard, Tool
from not_sandboxed.verdict import Decision, Finding, Verdict


REGISTRY = {
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


class Attempt(BaseModel):
    """
    One submitted ticket from a player
    """

    session_id: str
    level: int = config.ARENA_FIRST_LEVEL
    ticket: str = ""


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "layer": finding.layer,
        "rule": finding.rule,
        "severity": finding.severity.name,
        "invariant": finding.invariant,
    }


def _call_payload(reply: AgentReply) -> list[dict[str, Any]]:
    return [
        {
            "name": call.name,
            "args": sorted(call.args),
        } for call in reply.tool_calls
    ]


def _level_payload(level: Level) -> dict[str, Any]:
    return {
        "number": level.number,
        "title": level.title,
        "teaches": level.teaches,
        "active_layers": list(active_layers(level)),
    }


def _policy_for(level: Level, session: Session) -> Policy:
    return level.policy.model_copy(
        update = {"canaries": (session.secret,
                               )}
    )


def escaped(session: Session, reply: AgentReply) -> bool:
    """
    Whether the secret actually left, measured with the same matcher
    the egress layer uses

    A substring test on the prose alone misses the tool argument the
    agent puts it in, and misses every encoding, which would tell a
    player they failed while the secret was already gone
    """
    probe = EgressLayer(canaries = (session.secret,
                                    ))
    return any(
        finding.rule == config.RULE_CANARY_LEAK
        for surface in egress_surfaces(reply)
        for finding in probe.inspect_text(surface)
    )


def _result(
    session: Session,
    level: Level,
    *,
    ticket: str,
    inbound: Verdict,
    outbound: Verdict | None,
    reply: AgentReply | None,
    bypasses: BypassLog,
) -> dict[str,
          Any]:
    blocked = outbound is None or outbound.decision is Decision.BLOCK
    left = reply is not None and not blocked and escaped(session, reply)

    findings = [
        *inbound.findings,
        *(outbound.findings if outbound else ()),
    ]

    if left and level.number == config.ARENA_BOUNTY_LEVEL:
        session.record_bypass(level.number, ticket)
        bypasses.write(level.number, ticket)

    return {
        "level":
        _level_payload(level),
        "request_decision":
        str(inbound.decision),
        "egress_decision": (str(outbound.decision) if outbound else None),
        "agent_text": ("" if blocked or reply is None else reply.text),
        "tool_calls":
        ([] if blocked or reply is None else _call_payload(reply)),
        "secret_escaped":
        left,
        "findings": [_finding_payload(f) for f in findings],
        "attempts":
        session.attempts,
    }


def play(
    session: Session,
    level: Level,
    ticket: str,
    *,
    audit: AuditLog | None = None,
    bypasses: BypassLog | None = None,
) -> dict[str,
          Any]:
    """
    Run one submitted ticket through this level's firewall and report
    what happened and which rule decided it
    """
    policy = _policy_for(level, session)
    firewall = Firewall(policy, registry = REGISTRY)
    log = audit or AuditLog()
    won = bypasses or BypassLog()

    ctx = (
        Context().system(
            config.ARENA_SYSTEM_PROMPT.format(
                company = config.ARENA_COMPANY
            )
        ).user(config.ARENA_USER_TURN).data(
            ticket,
            origin = Origin(
                channel = config.ARENA_TICKET_CHANNEL,
                ref = session.session_id[: 8],
            ),
        )
    )

    inbound = firewall.inspect(ctx)
    log.write(inbound, ctx)

    if inbound.decision is Decision.BLOCK:
        return _result(
            session,
            level,
            ticket = ticket,
            inbound = inbound,
            outbound = None,
            reply = None,
            bypasses = won,
        )

    reply = MockAgent(secret = session.secret).respond(
        firewall.render(ctx)
    )
    outbound = firewall.inspect_egress(reply, ctx)
    log.write(outbound, ctx)

    return _result(
        session,
        level,
        ticket = ticket,
        inbound = inbound,
        outbound = outbound,
        reply = reply,
        bypasses = won,
    )


def _client_of(request: Request) -> str:
    return (
        request.client.host
        if request.client else config.ARENA_ANONYMOUS_CLIENT
    )


def build_arena(
    store: SessionStore | None = None,
    audit: AuditLog | None = None,
    bypasses: BypassLog | None = None,
) -> FastAPI:
    """
    Build the arena, where each level is a firewall configuration and
    every verdict names the rule that produced it
    """
    app = FastAPI(title = "not-sandboxed arena")
    sessions = store or SessionStore()
    log = audit or audit_log_from_env(config.ARENA_AUDIT_PATH_VAR)
    won = bypasses or bypass_log_from_env(config.ARENA_BYPASS_PATH_VAR)

    @app.get("/api/levels")
    def levels() -> dict[str, Any]:
        return {
            "levels": [_level_payload(LEVELS[n]) for n in sorted(LEVELS)]
        }

    @app.get("/api/codepoints")
    def codepoints() -> dict[str, Any]:
        return {
            config.CODEPOINT_FIELD_TAG: [
                config.TAG_BLOCK_START,
                config.TAG_BLOCK_END,
            ],
            config.CODEPOINT_FIELD_BIDI:
            list(config.BIDI_CODEPOINTS),
            config.CODEPOINT_FIELD_ZERO_WIDTH:
            list(config.ZERO_WIDTH_CODEPOINTS),
        }

    @app.post("/api/session")
    def new_session(request: Request) -> dict[str, Any]:
        try:
            session = sessions.create(client = _client_of(request))
        except RateLimitedError as limited:
            raise HTTPException(
                status_code = 429,
                detail = str(limited),
            ) from limited

        return {
            "session_id": session.session_id,
            "secret_length": len(session.secret),
        }

    @app.post("/api/attempt")
    def attempt(request: Attempt) -> dict[str, Any]:
        session = sessions.get(request.session_id)
        if session is None:
            raise HTTPException(
                status_code = 404,
                detail = config.ERROR_UNKNOWN_SESSION,
            )

        try:
            sessions.charge(session, sessions.clock())
        except RateLimitedError as limited:
            raise HTTPException(
                status_code = 429,
                detail = str(limited),
            ) from limited

        level = LEVELS.get(request.level)
        if level is None:
            raise HTTPException(
                status_code = 404,
                detail = config.ERROR_UNKNOWN_LEVEL,
            )

        if len(request.ticket) > config.ARENA_MAX_PAYLOAD_CHARS:
            raise HTTPException(
                status_code = 413,
                detail = config.ERROR_PAYLOAD_TOO_LONG,
            )

        return play(
            session,
            level,
            request.ticket,
            audit = log,
            bypasses = won,
        )

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "levels": len(LEVELS),
            "audit": log.enabled,
            "bypasses": won.enabled,
        }

    return app
