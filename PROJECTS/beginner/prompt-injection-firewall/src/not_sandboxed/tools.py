"""
©AngelaMos | 2026
tools.py
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, JsonValue


class Effect(StrEnum):
    """
    What a tool does to the world if it runs
    """

    READ = "read"
    WRITE = "write"
    NETWORK_EGRESS = "network_egress"
    SPEND = "spend"


class Guard(StrEnum):
    """
    A condition the firewall checks before a tool call is permitted
    """

    NO_UNTRUSTED_INFLUENCE = "no_untrusted_influence"
    USER_CONFIRMED = "user_confirmed"
    ARGS_ALLOWLISTED = "args_allowlisted"


class Tool(BaseModel):
    """
    A capability the model may request, and the conditions under which
    the firewall will grant it
    """

    model_config = ConfigDict(frozen = True)

    name: str
    effects: frozenset[Effect] = frozenset()
    guards: frozenset[Guard] = frozenset()
    required_args: frozenset[str] = frozenset()
    optional_args: frozenset[str] = frozenset()
    allowlists: dict[str, frozenset[str]] = {}
    arg_schema: type[BaseModel] | None = None

    @property
    def permitted_args(self) -> frozenset[str]:
        """
        Every argument name this tool will accept, and no others
        """
        return self.required_args | self.optional_args


class ToolCallRequest(BaseModel):
    """
    What the model asked to do, which is a request and never a decision
    """

    model_config = ConfigDict(frozen = True)

    name: str
    args: dict[str, JsonValue] = {}
    user_confirmed: bool = False


class AgentReply(BaseModel):
    """
    What the model produced, both the prose and the actions it wants
    """

    model_config = ConfigDict(frozen = True)

    text: str = ""
    tool_calls: tuple[ToolCallRequest, ...] = ()


def render_arg(value: JsonValue) -> str:
    """
    Flatten one argument value to the text egress has to scan, because
    a secret nested inside a list or an object still leaves
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(
            f"{key} {render_arg(item)}" for key, item in value.items()
        )
    if isinstance(value, list):
        return " ".join(render_arg(item) for item in value)
    return str(value)
