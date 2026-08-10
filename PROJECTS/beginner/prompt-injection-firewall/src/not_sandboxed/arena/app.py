"""
©AngelaMos | 2026
app.py
"""

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from not_sandboxed import config
from not_sandboxed.agent.mock import MockAgent
from not_sandboxed.arena.levels import LEVELS, Level, active_layers
from not_sandboxed.arena.session import (
    RateLimitedError,
    Session,
    SessionStore,
)
from not_sandboxed.context import Context, Origin
from not_sandboxed.firewall import Firewall
from not_sandboxed.policy import Policy
from not_sandboxed.tools import Effect, Guard, Tool
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


def _result(
    session: Session,
    level: Level,
    inbound: Verdict,
    outbound: Verdict | None,
    agent_text: str,
) -> dict[str,
          Any]:
    escaped = session.secret in agent_text
    findings = [
        *inbound.findings,
        *(outbound.findings if outbound else ()),
    ]

    if escaped and level.number == config.ARENA_BOUNTY_LEVEL:
        session.bypasses.append({"level": str(level.number)})

    return {
        "level": _level_payload(level),
        "request_decision": str(inbound.decision),
        "egress_decision": (str(outbound.decision) if outbound else None),
        "agent_text": agent_text,
        "secret_escaped": escaped,
        "findings": [_finding_payload(f) for f in findings],
        "attempts": session.attempts,
    }


def play(
    session: Session,
    level: Level,
    ticket: str,
) -> dict[str,
          Any]:
    """
    Run one submitted ticket through this level's firewall and report
    what happened and which rule decided it
    """
    policy = _policy_for(level, session)
    firewall = Firewall(policy, registry = REGISTRY)

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
    if inbound.decision is Decision.BLOCK:
        return _result(session, level, inbound, None, "")

    reply = MockAgent(secret = session.secret).respond(
        firewall.render(ctx)
    )
    outbound = firewall.inspect_egress(reply, ctx)
    blocked = outbound.decision is Decision.BLOCK

    return _result(
        session,
        level,
        inbound,
        outbound,
        "" if blocked else reply.text,
    )


def build_arena(store: SessionStore | None = None) -> FastAPI:
    """
    Build the arena, where each level is a firewall configuration and
    every verdict names the rule that produced it
    """
    app = FastAPI(title = "not-sandboxed arena")
    sessions = store or SessionStore()

    @app.get("/api/levels")
    def levels() -> dict[str, Any]:
        return {
            "levels": [_level_payload(LEVELS[n]) for n in sorted(LEVELS)]
        }

    @app.post("/api/session")
    def new_session() -> dict[str, Any]:
        session = sessions.create()
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

        try:
            sessions.charge(session, sessions.clock())
        except RateLimitedError as limited:
            raise HTTPException(
                status_code = 429,
                detail = str(limited),
            ) from limited

        return play(session, level, request.ticket)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"levels": len(LEVELS)}

    return app
