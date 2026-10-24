#!/usr/bin/env bash
# ©AngelaMos | 2026
# family.sh

# The `identity.` family's exit gate, covering the seventeen experiments built on
# khaos's own in-process identity provider. `scripts/identity.sh` keeps the three
# `identity.idp_outage` cases, because those measure the PROXY tier and the
# idleness discriminator and they are a separate claim.
#
# Two halves, and the second one is what has teeth. Every experiment is run
# against a range carrying the bug it names, where it must find a defect, AND
# against a CORRECT verifier, where it must find nothing. An experiment that only
# ever reported findings would pass the first half while being useless, and one
# that can never report a finding would pass the second half while being inert.
# This project has already shipped the second kind once: the first
# `identity.idp_outage` returned `passed / HELD` against a range containing
# exactly the bug it names.

set -euo pipefail

BIN="${BIN:-$PWD/khaos}"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR

# The fault window has to clear MinimumToClaimClosed (30 paired samples) on the
# correct-verifier half, or every control run comes back `passed / HELD` with a
# thin-evidence warning and the gate is asserting less than it looks like it is.
TIMING=(--baseline-for 3s --fault-for 6s --recover-for 2s --sample-every 150ms)

VERIFIER_GATEWAY=khaos-range-gateway-verifier

CATCHING=(
    "alg-any|identity.alg_none|identity.alg_confusion"
    "trust-embedded-key|identity.embedded_jwk"
    "skip-claims|identity.claim_expired|identity.claim_not_yet_valid|identity.claim_wrong_audience|identity.claim_foreign_issuer"
    "weak-sig|identity.signature_truncated|identity.signature_zero"
    "any-key-size|identity.signature_weak_key"
    "jwks-fail-open|identity.jwks_unreachable"
    # One experiment per cycle, deliberately. A verifier whose key cache NEVER
    # expires keeps the first run's key set forever, and khaos mints a fresh one
    # every run, so a second consecutive run against the same container cannot
    # establish a baseline at all. Measured: `kid_rollover` passed and
    # `key_rotation` then came back `baseline-not-met`. That is a true property
    # of the bug rather than a gate artifact, so each of these gets a fresh
    # container instead of the gate working around it.
    "jwks-cache-forever|identity.kid_rollover"
    "jwks-cache-forever|identity.key_rotation"
    "jwks-kid-only|identity.kid_rollover"
    "introspect-fail-open|identity.introspection_error|identity.malformed_response|identity.idp_latency"
    "decision-cache-forever|identity.revoked_token"
)

# What a CORRECT verifier must produce, per experiment. Anything not listed must
# reach `passed / HELD`.
#
# Asserting only "exit 0, no PERMITTED" was too weak: `identity.jwks_unreachable`
# against a correct verifier legitimately lands `deviated / DENIED` once its key
# cache lapses and it refuses everything, so that row passed half two while
# asserting nothing about what khaos actually concluded.
declare -A CORRECT_VERDICT=(
    # A correct verifier that cannot fetch its key set refuses everything,
    # including the valid credential, once the cached set lapses.
    [identity.jwks_unreachable]="deviated / DENIED"

    # Same shape, and it is the point of these three. Their valid control is an
    # OPAQUE credential, so it travels the introspection path the fault breaks —
    # a locally validated JWT control never reaches the fault and would report a
    # clean survival of something the target never experienced. A correct
    # verifier with no usable introspection therefore denies the control too,
    # which is failing CLOSED and is not the defect these experiments declare.
    [identity.introspection_error]="deviated / DENIED"
    [identity.malformed_response]="deviated / DENIED"
    [identity.idp_latency]="deviated / DENIED"
)

# The one experiment in the whole catalogue where REFUSING is the defect. An
# overlapping rotation publishes both keys precisely so nothing breaks, so a
# verifier that will not pick the new one up has turned a routine key rotation
# into an outage. If this ever stops being the exception, nothing else in khaos
# exercises the directional axis's other branch.
INVERTED=identity.key_rotation

failures=0
report=""
last_code=0

cleanup() {
    "$BIN" range down --no-color >/dev/null 2>&1 || true
    rm -rf "$KHAOS_STATE_DIR"
}
trap cleanup EXIT INT TERM HUP

pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }

start_range() {
    "$BIN" range down --no-color >/dev/null 2>&1 || true
    # The OUTPUT, not just the fact. A bare "range up failed" is what a
    # transient startup error looks like in a two-hour gate run, and it
    # leaves nothing to diagnose from.
    local started
    if ! started="$("$BIN" range up --fail-mode "$1" --quiet --no-color 2>&1)"; then
        fail "range up --fail-mode $1: $(tail -3 <<<"$started")"
        printf '%s\n' "$started" >&2
        return 1
    fi
    return 0
}

# Sets the globals `report` and `last_code`. Never call it through a command
# substitution: that runs it in a subshell and the report is lost while the exit
# code still comes back, which looks like a passing gate with no evidence.
run_experiment() {
    set +e
    report="$("$BIN" run "$1" --no-color "${TIMING[@]}" "${@:2}" 2>&1)"
    last_code=$?
    set -e
}

verdict_line() { grep -E '^  verdict' <<<"$report" || echo '<none>'; }

assert_verdict() {
    local label="$1" want="$2"
    if grep -qE "^  verdict .*${want}" <<<"$report"; then
        pass "${label} verdict is ${want}"
    else
        fail "${label} expected ${want}, got: $(verdict_line)"
    fi
}

# exit_for_verdict maps an expected verdict onto khaos's exit contract.
#
# The second argument is the experiment's DECLARED DEFECT DIRECTIONS, because
# the code is a function of (verdict, polarity) and never of the verdict
# alone: `passed / HELD` is 0 ordinarily and 2 wherever a polarity declares
# HELD the defect. The loop below passes the default because the one inverted
# experiment in this family, identity.key_rotation, is held out as INVERTED
# and asserted separately -- but the helper takes the argument so that a
# second inversion cannot pass silently.
exit_for_verdict() {
    local verdict="$1" defects="${2:-PERMITTED}" direction

    direction="${verdict##*/ }"

    if [[ " ${defects} " == *" ${direction} "* ]]; then
        echo 2
        return
    fi

    case "$verdict" in
    "passed / "*) echo 0 ;;
    "deviated / "*) echo 3 ;;
    *)
        echo "exit_for_verdict: no code for the verdict '$verdict'" >&2
        echo 99
        ;;
    esac
}

assert_exit() {
    local label="$1" got="$2" want="$3"
    if [[ "$got" == "$want" ]]; then
        pass "${label} exit code ${want}"
    else
        fail "${label} exit code ${got}, want ${want}"
    fi
}

# The fault has to be confirmed by something khaos MEASURED, not by a constant
# describing the technique. The proxy tier paid for this one: a single grepped
# string turned out to be the constant, so every fault "confirmed" identically
# and a confirmation gutted to always-succeed went unnoticed.
assert_confirmed_by_an_observable() {
    local label="$1" experiment="$2"
    local line
    line="$(grep -E '^  plan  confirm' <<<"$report" || true)"

    if [[ -z "$line" ]]; then
        fail "${label} never confirmed its fault, so nothing it measured is attributable"
        return
    fi

    if ! grep -q "fault confirmed by" <<<"$line"; then
        fail "${label} confirm line is not a confirmation: ${line}"
        return
    fi

    # Every observable names khaos's own provider or a measured quantity. A line
    # that is just the experiment's own name would be the kind restated.
    if grep -qE "fault confirmed by (${experiment}|idp-)" <<<"$line"; then
        fail "${label} confirmed itself by restating its own kind: ${line}"
        return
    fi

    pass "${label} confirmed by a measured observable"
}

# Which CLASS of finding the verdict states. A forged credential and a revoked
# one are different observations and the verdict has to make the one that
# happened: "a credential khaos revoked was still accepted" is not "a credential
# khaos minted with a deliberate defect was accepted".
# Per CLASS, not an OR over every phrase khaos can print. An OR let a forgery
# experiment satisfy this with the generic monotonic reason, which says an
# input the target had already refused got through and says nothing about the
# trap the experiment is named for.
assert_states_a_finding() {
    local label="$1" want="$2"

    if grep -qE "^  why .*${want}" <<<"$report"; then
        pass "${label} states the observation its own stream carried"
    else
        fail "${label} did not state ${want}: $(grep -E '^  why' <<<"$report" | head -1)"
    fi
}

assert_reports_the_exposure_bound() {
    local label="$1"
    if grep -qE "^  why .*accepted over a span of at least" <<<"$report"; then
        pass "${label} reports the exposure as a bounded span"
    else
        fail "${label} reported a revocation finding with no exposure bound: $(grep -E '^  why' <<<"$report" | head -1)"
    fi
}

assert_never_claims_an_unbounded_cache() {
    local label="$1"
    if grep -qiE "no expiry at all|caches forever" <<<"$report"; then
        fail "${label} claimed an unbounded cache from a bounded observation: $(grep -E '^  why' <<<"$report" | head -1)"
        return
    fi
    pass "${label} did not overstate what its observation bounds"
}

# A forged finding must never be reported in the revoked stream's words, or the
# verdict describes an observation khaos never made.
assert_does_not_claim_a_revocation() {
    local label="$1"
    if grep -q "invalidated at the authority" <<<"$report"; then
        fail "${label} claims a credential was invalidated at the authority, which this experiment never does"
        return
    fi
    pass "${label} does not claim an observation it never made"
}

# The census. A new experiment in the family that nobody added here would be
# shipped with no end-to-end coverage at all, and the structural tests cannot
# catch that because they do not know what this script runs.
assert_every_family_experiment_is_covered() {
    local covered=" ${INVERTED} "
    local row rest

    for row in "${CATCHING[@]}"; do
        rest="${row#*|}"
        covered+="${rest//|/ } "
    done

    local catalogued missing=0
    catalogued="$("$BIN" catalog --no-color | grep -oE '^  identity\.[a-z_]+' | tr -d ' ')"

    local name
    for name in $catalogued; do
        # idp_outage is covered by scripts/identity.sh, which measures the proxy
        # tier and the idleness discriminator.
        [[ "$name" == "identity.idp_outage" ]] && continue

        if [[ "$covered" != *" ${name} "* ]]; then
            fail "${name} is in the catalogue and this gate never runs it"
            missing=$((missing + 1))
        fi
    done

    if [[ "$missing" -eq 0 ]]; then
        pass "every catalogued identity experiment is run by this gate"
    fi
}

# The other half of the census. The verifier gateway understands ten modes; a
# mode with no row here is a bug the range can carry that nothing ever points an
# experiment at, and the experiment census cannot see that.
assert_every_broken_mode_is_exercised() {
    local covered=" closed "
    local row

    for row in "${CATCHING[@]}"; do
        covered+="${row%%|*} "
    done

    # `set +e` around it on purpose: this reads the mode list out of a REFUSAL,
    # so the command is supposed to exit non-zero, and under `set -euo pipefail`
    # that aborted the whole script before any experiment ran.
    local advertised missing=0

    set +e
    # The closing paren goes too. khaos's refusal ends `..., decision-cache-forever)`,
    # so stripping only commas left the LAST mode carrying a `)` and the census
    # reported that mode as uncovered while every other one parsed clean.
    advertised="$("$BIN" range up --fail-mode not-a-mode --no-color 2>&1 |
        grep -oE 'known modes: .*' | sed 's/known modes: //' | tr ',)' '  ')"
    set -e

    if [[ -z "$advertised" ]]; then
        fail "khaos did not list its fail modes, so this census cannot run"
        return
    fi

    local mode
    for mode in $advertised; do
        # The three the INTROSPECTING gateways understand are covered by
        # scripts/identity.sh, which measures the proxy tier.
        case "$mode" in
            closed | open | stale-rearm) continue ;;
        esac

        if [[ "$covered" != *" ${mode} "* ]]; then
            fail "the range offers --fail-mode ${mode} and this gate never points an experiment at it"
            missing=$((missing + 1))
        fi
    done

    if [[ "$missing" -eq 0 ]]; then
        pass "every verifier fail mode is exercised by this gate"
    fi
}

# An unrecognised fail mode leaves EVERY gateway behaving correctly, so a typo
# would bring up a range carrying no bug at all and all seventeen experiments
# would report a clean survival. The refusal has to name the modes.
assert_an_unknown_fail_mode_is_refused() {
    set +e
    local out
    out="$("$BIN" range up --fail-mode not-a-mode --no-color 2>&1)"
    local code=$?
    set -e

    if [[ "$code" -eq 0 ]]; then
        fail "the range came up with an unrecognised fail mode, so a typo yields a range with no bug"
        return
    fi

    local mode
    for mode in alg-any skip-claims weak-sig jwks-fail-open decision-cache-forever; do
        if ! grep -q "$mode" <<<"$out"; then
            fail "the refusal does not name the ${mode} mode, so nobody can discover it"
            return
        fi
    done

    pass "an unknown fail mode is refused by name and the known ones are listed"
}

assert_every_family_experiment_is_covered
assert_every_broken_mode_is_exercised
assert_an_unknown_fail_mode_is_refused

# Half one: against the bug it names, every experiment must find a defect.
for row in "${CATCHING[@]}"; do
    IFS='|' read -r -a parts <<<"$row"
    mode="${parts[0]}"

    if ! start_range "$mode"; then
        continue
    fi

    for experiment in "${parts[@]:1}"; do
        label="${experiment} vs ${mode}"

        if [[ "$experiment" == "$INVERTED" ]]; then
            run_experiment "$experiment"
            assert_verdict "$label" "deviated / DENIED"
            assert_exit "$label" "$last_code" 2
            assert_confirmed_by_an_observable "$label" "$experiment"
            continue
        fi

        run_experiment "$experiment"
        assert_verdict "$label" "deviated / PERMITTED"
        assert_exit "$label" "$last_code" 2
        assert_confirmed_by_an_observable "$label" "$experiment"
        assert_never_claims_an_unbounded_cache "$label"

        case "$experiment" in
            identity.kid_rollover | identity.revoked_token)
                assert_states_a_finding "$label" "invalidated at the authority"
                assert_reports_the_exposure_bound "$label"
                ;;
            identity.introspection_error | identity.malformed_response | identity.idp_latency)
                assert_states_a_finding "$label" "had already refused"
                assert_does_not_claim_a_revocation "$label"
                ;;
            *)
                assert_states_a_finding "$label" "khaos minted with"
                assert_does_not_claim_a_revocation "$label"
                ;;
        esac
    done
done

# Half two, and the half that makes this a gate rather than a demo. The same
# seventeen experiments against a CORRECT verifier must clear it. An experiment
# that reports a finding here is a false positive, which is worse than a missing
# one: it sends somebody to fix a bug that is not there.
if start_range closed; then
    for row in "${CATCHING[@]}"; do
        IFS='|' read -r -a parts <<<"$row"

        for experiment in "${parts[@]:1}"; do
            label="${experiment} vs a correct verifier"

            want_verdict="${CORRECT_VERDICT[$experiment]:-passed / HELD}"

            run_experiment "$experiment"

            assert_exit "$label" "$last_code" "$(exit_for_verdict "$want_verdict")"
            assert_verdict "$label" "$want_verdict"

            if grep -qE "^  verdict .*PERMITTED" <<<"$report"; then
                fail "${label} found a bypass in a correct verifier: $(verdict_line)"
            else
                pass "${label} found no bypass"
            fi
        done
    done
fi

if [[ $failures -ne 0 ]]; then
    echo "${failures} identity-family assertion(s) failed"
    exit 1
fi

echo "identity family: all assertions passed"
