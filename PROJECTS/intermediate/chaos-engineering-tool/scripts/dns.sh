#!/usr/bin/env bash
# ©AngelaMos | 2026
# dns.sh

set -euo pipefail

#   1. The MASKED faults are refused by name, not approximated. Docker's
#      embedded resolver rewrites REFUSED to SERVFAIL and answers SERVFAIL
#      itself at a measured 4.001s rather than letting a query go unanswered,
#      so neither can reach a container on a user-defined bridge. Delivering
#      SERVFAIL while claiming REFUSED would be worse than refusing: a real
#      library branches on the rcode and the branch is the finding.
#
#   2. The delay ceiling is enforced from the same measurement. At or above
#      4.000s a slow answer silently becomes the timeout fault, so khaos
#      refuses the magnitude rather than serving a different experiment.
#
#   4. A fault the target never MET is aborted, not survived. A DNS fault can
#      be armed, confirmed at khaos's own resolver, and reach nothing: Go's
#      HTTP transport resolves a name once per kept-alive connection, measured
#      on this range's own gateway at two lookups across forty-six requests.
#      Every other tier collapses "armed" and "experienced" safely, because a
#      severed path or a broken certificate sits on a route the target cannot
#      avoid. A DNS answer is one it can simply not ask for again.

BIN="${BIN:-$PWD/khaos}"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR

# The fault window has to clear MinimumToClaimClosed, which is 30 paired
# samples. khaos refuses to call a HELD run conclusive below that, and this
# gate's truncation assertions are about a HELD verdict's exit code: at 8s and
# 400ms it got 19 samples, the verdict was honestly marked inconclusive, and it
# exited 4 instead of 0. That was the gate asking khaos to claim more than its
# own sample floor allows, which is the same way `tls.sh` failed its first run.
TIMING=(--baseline-for 5s --fault-for 20s --recover-for 3s --sample-every 300ms)

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

# The gateway's fail mode is fixed at container creation, deliberately, so a
# gate spanning both directions has to restart the range. A gateway that could
# be reconfigured mid-run would let khaos change the target it is measuring.
#
# The second argument is the DNS gateway's resolution behaviour, and it is fixed
# at creation for the same reason. `dns.ttl_rotate` needs both shapes: a client
# that re-resolves follows a zone rotation, and one that resolved once and
# reuses its connection never sees it.
start_range() {
    local dns_mode="${2:-reresolve}"

    "$BIN" range down --no-color >/dev/null 2>&1 || true
    # The OUTPUT, not just the fact. A bare "range up failed" is what a
    # transient startup error looks like in a two-hour gate run, and it
    # leaves nothing to diagnose from.
    local started
    if ! started="$("$BIN" range up --fail-mode "$1" --dns-mode "$dns_mode" \
        --no-color --quiet 2>&1)"; then
        fail "range up --fail-mode $1 --dns-mode $dns_mode: $(tail -3 <<<"$started")"
        printf '%s\n' "$started" >&2
        return 1
    fi
    return 0
}

# Sets the globals `report` and `last_code`. Never call it through a command
# substitution: that runs it in a subshell and the report is lost while the exit
# code still comes back, which looks like a passing gate with no evidence.
# Appended to by run_experiment, so the census at the bottom proves what the gate
# RAN rather than comparing one hand-written list to another.
ran=()

# rogue_asked reads the range rogue provider's own request counter, which is what
# separates a redirect finding from an outage finding. khaos cannot read it: the
# redirect address is an operator parameter and khaos has nothing at the far end
# of it. The host can, because it routes to container addresses on a bridge.
rogue_asked() {
    curl -s --max-time 5 "http://10.244.244.20:8080/khaos-rogue-count" 2>/dev/null |
        sed -E 's/.*"asked":([0-9]+).*/\1/' | grep -E '^[0-9]+$' || echo 0
}

run_experiment() {
    local experiment="$1"
    shift
    ran+=("$experiment")
    set +e
    report="$("$BIN" run "$experiment" --no-color "${TIMING[@]}" "$@" 2>&1)"
    last_code=$?
    set -e
}

assert_verdict() {
    local label="$1" want="$2"
    if grep -qE "^  verdict .*${want}" <<<"$report"; then
        pass "${label} verdict is ${want}"
    else
        fail "${label} expected ${want}, got: $(grep -E '^  verdict' <<<"$report" || echo '<none>')"
    fi
}

assert_exit() {
    local label="$1" want="$2"
    if [[ "$last_code" == "$want" ]]; then
        pass "${label} exit code ${want}"
    else
        fail "${label} exit code ${last_code}, want ${want}"
    fi
}

assert_confirmed() {
    local label="$1"
    if grep -qE '^  plan  confirm   fault confirmed by ' <<<"$report"; then
        pass "${label} confirmed by a measured observable"
    else
        fail "${label} reported no confirmation, so the run measured a fault it never proved landed"
    fi
}

assert_report_has() {
    local label="$1" want="$2"
    if grep -qF "$want" <<<"$report"; then
        pass "${label}"
    else
        fail "${label}: the report never says ${want}"
    fi
}

assert_report_lacks() {
    local label="$1" want="$2"
    if grep -qF "$want" <<<"$report"; then
        fail "${label}: the report says ${want}"
    else
        pass "${label}"
    fi
}

# The observable, not the verdict. This is the half of the gate that separates
# faults a target cannot tell apart: through the embedded resolver SERVFAIL,
# REFUSED and a dropped query all reach a Go target as `server misbehaving`
# with IsTemporary set, so khaos has to name which one it served.
observable_of() {
    grep -E '^  plan  confirm   fault confirmed by ' <<<"$report" |
        sed -E 's/^.*fault confirmed by //'
}

echo "== the masked faults are refused by name =="

# The range HAS to be up for this section, and the first version of this script
# said the opposite: "No range needed: the refusal has to arrive before khaos
# touches anything, and asserting it with no range running proves it does."
#
# Both halves were false. With no range, `khaos run dns.refused` dies in
# fillFromRange with "no running khaos range was found" and exit 1 — which the
# old `[[ $last_code == 0 ]] && fail || pass` read as a successful refusal,
# while the grep for the mechanism would have gone red. It passed only because
# the range happened to be up from earlier manual runs. Measured: with the range
# genuinely down, `grep -c "embedded resolver"` is 0.
#
# And the refusal is deliberately NOT early. The design doc says so: a masked
# fault builds, plans and describes like any other entry and is refused when
# khaos is asked to ARM one, because a catalogue entry that cannot be built
# broke five separate censuses that walk the catalogue.
if start_range closed; then
    for masked in dns.refused dns.timeout; do
        run_experiment "$masked"

        if [[ "$last_code" == 0 ]]; then
            fail "${masked} succeeded, so khaos delivered something else and called it this"
        else
            pass "${masked} is refused"
        fi

        # The MECHANISM, which is the assertion that distinguishes khaos's own
        # refusal from any other non-zero exit. Without it, a missing range, a
        # missing resolver and a half-specified invocation all read as "khaos
        # refused this fault by name".
        assert_report_has \
            "${masked} names the mechanism rather than just saying no" \
            "embedded resolver"

        # The remediation, anchored on the fault khaos actually tells you to run
        # instead. `grep -F "dns."` was inert: it matches the run header, the
        # plan lines and the experiment's own name.
        case "$masked" in
            dns.refused)
                assert_report_has \
                    "${masked} says to run dns.servfail instead" \
                    "Run \`dns.servfail\`"
                ;;
            dns.timeout)
                assert_report_has \
                    "${masked} says to run dns.slow_response instead" \
                    "Run \`dns.slow_response\`"
                ;;
        esac
    done

    # The ceiling is a measurement, not a preference: at or above 4.000s the
    # embedded resolver answers SERVFAIL itself at 4.001s and the delay never
    # reaches the client, so the operator would get the timeout fault under the
    # slow fault's name.
    run_experiment dns.slow_response --dns-delay 30s

    if [[ "$last_code" == 0 ]]; then
        fail "a 30s delay was accepted, which the embedded resolver turns into a different fault"
    else
        pass "a delay above the measured ceiling is refused"
    fi

    assert_report_has "the refusal names the ceiling" "3.999s"

    # And 3.9s is DELIVERED, not merely accepted. The old assertion was
    # `[[ $last_code == 1 ]] && fail || pass`, which passes on exit 0, 2 and 4
    # alike — its real content was "no generic error happened". Worse, nothing
    # in the gate ever delivered a 3.9s delay to anything, so the one number the
    # research swept to resolve its open question was unexercised.
    run_experiment dns.slow_response --dns-delay 3900ms

    assert_confirmed "a 3.9s delay"
    assert_report_has \
        "3.9s is delivered, one millisecond under the measured ceiling" \
        "3.9s"
    assert_report_lacks \
        "3.9s is not refused as above the ceiling" \
        "3.999s"
fi

echo "== against a gateway that fails OPEN =="

if start_range open; then
    # The whole point of the family. The dependency is HEALTHY and reachable
    # throughout; only the gateway's ability to find it changes, and it responds
    # by honouring a credential it had already rejected.
    for fault in nxdomain servfail slow_response wrong_address \
        cname_chain cname_loop truncation_no_tcp; do
        run_experiment "dns.${fault}"
        assert_verdict "${fault} vs fail-open" "deviated / PERMITTED"
        assert_exit "${fault} vs fail-open" 2
        assert_confirmed "${fault}"
    done

    # The REDIRECT faults have to be findings rather than outages, and this is
    # the assertion that separates them. Pointing a redirect at an unroutable
    # address only reproduces what three other tiers already do to an
    # unreachable dependency; pointed at the range's rogue provider, which
    # approves everything, the gateway authorises an attacker who won a name.
    # Asserted on the CONFIRM line, not on the report as a whole. `describeWrong`
    # already puts the address in the plan's condition line, so a bare grep was
    # satisfied by the address khaos was ASKED to serve whether or not the
    # observable ever named what it actually served.
    run_experiment dns.wrong_address

    if grep -E '^  plan  confirm   fault confirmed by ' <<<"$report" |
        grep -qF "10.244.244.20"; then
        pass "the redirect's own observable names the address it served"
    else
        fail "the confirmation does not name the served address: $(observable_of)"
    fi

    # And it has to say what it REPLACED, which is the honest differential. The
    # first version compared the served address against itself and read
    # "with [X] instead of X".
    if grep -E '^  plan  confirm   fault confirmed by ' <<<"$report" |
        grep -qF "instead of 10.244.244.10"; then
        pass "the redirect names the honest address it replaced"
    else
        fail "the confirmation does not name the honest address: $(observable_of)"
    fi

    # THE INSTRUMENT THAT SEPARATES A REDIRECT FROM AN OUTAGE, read from the
    # fixture because khaos cannot read it: the redirect address is an operator
    # parameter and khaos has nothing at the far end of it.
    #
    # Without this, `deviated / PERMITTED` on a redirect is produced identically
    # by "the gateway asked the rogue and the rogue approved" and "the gateway
    # could not reach the redirect at all and failed open" — and the second is
    # what three other tiers already test.
    asked="$(rogue_asked)"
    if [[ "$asked" -gt 0 ]]; then
        pass "the redirect was FOLLOWED: the rogue was asked ${asked} time(s)"
    else
        fail "the rogue was never asked, so this PERMITTED is an unreachable-dependency finding rather than a redirect finding"
    fi

    # And khaos must NOT claim the half it did not measure.
    assert_report_lacks \
        "khaos does not claim the target verified who it reached" \
        "verifies who it reached"

    # The two CNAME faults must not be confirmed by each other's answer. A loop
    # also has three hops, so a hop count alone confirmed the loop's reply as a
    # chain until the isolation control caught it.
    run_experiment dns.cname_chain
    chain_observable="$(observable_of)"
    run_experiment dns.cname_loop
    loop_observable="$(observable_of)"

    if [[ "$chain_observable" == "$loop_observable" ]]; then
        fail "the chain and the loop produced the same observable, so neither is disambiguated"
    else
        pass "the chain and the loop produce distinct observables"
    fi

    if [[ "$loop_observable" == *"cycle"* ]]; then
        pass "the loop's observable names the cycle"
    else
        fail "the loop's observable does not mention a cycle: ${loop_observable}"
    fi

    # TRUNCATION IS DELIVERABLE, and this is the assertion the research
    # correction rests on. The gateway sees `tc`, re-asks over TCP, gets the
    # complete answer and carries on: the control HELD, which is the correct
    # outcome and must not be called a defect.
    run_experiment dns.truncation
    assert_verdict "truncation vs fail-open" "passed / HELD"
    assert_exit "truncation vs fail-open" 0
    assert_confirmed "truncation"

    assert_report_has \
        "truncation proves the TCP half as well as the UDP half" \
        "completely over TCP"

    # Its sibling must be the OPPOSITE. Both set the bit over UDP, so UDP alone
    # cannot tell them apart and the difference is the whole finding: one tests
    # whether the client makes the retry, the other whether the retry is allowed
    # off the network.
    run_experiment dns.truncation_no_tcp
    assert_report_has \
        "the no-TCP variant proves no transport completes" \
        "over UDP and over TCP"

    # The TTL faults report UNSUPPORTED, measured rather than assumed. This
    # gateway re-resolves per request, so it holds no cached answer and the
    # lifetime khaos serves governs nothing it does. Go has no answer cache and
    # ignores TTL entirely, and khaos COUNTS that rather than inferring it from
    # a language it was never told.
    for fault in ttl_zero ttl_long; do
        run_experiment "dns.${fault}"
        assert_verdict "${fault} vs an uncached target" "unsupported"

        assert_exit "${fault} vs an uncached target" 9

        # Anchored on the LIFETIME khaos served, which is the measurement the
        # verdict is entitled to make. The target's lookups do not scale with
        # khaos's traffic -- the gateway caches decisions, so it calls its
        # dependency less often than khaos probes it -- so a per-request ratio
        # would be measuring the wrong cache.
        assert_report_has \
            "${fault} says it measured the absence of a cache" \
            "A target honouring it resolves once for the whole window"

        assert_report_lacks \
            "${fault} does not claim the target survived" \
            "no bypass was observed"
    done

    # The causal axis belongs to the idleness pause, and no DNS experiment runs
    # one. Reporting on a resumed window khaos never collected reads as khaos
    # having tried the pause and learned nothing, which is a claim about a
    # measurement it declined to attempt.
    run_experiment dns.nxdomain
    assert_report_lacks \
        "a family that never pauses traffic says nothing about the pause" \
        "resumed window"
fi

echo "== against a gateway that fails CLOSED =="

if start_range closed; then
    # The faults that make the dependency UNFINDABLE. A gateway that cannot
    # resolve its identity provider refuses everything: failed closed, correct,
    # with an availability cost this family declares acceptable.
    for fault in nxdomain servfail; do
        run_experiment "dns.${fault}"
        assert_verdict "${fault} vs fail-closed" "deviated / DENIED"

        assert_exit "${fault} vs fail-closed" 3
        assert_confirmed "${fault}"
    done

    # THE REDIRECT FAULTS ARE DIFFERENT, AND THIS IS THE FAMILY'S SHARPEST
    # RESULT: fail-closed is no defence against them.
    #
    # Failing closed only helps when the dependency is unreachable. A redirect
    # to a host that ANSWERS never makes the gateway fail at all — it succeeds,
    # against the wrong authority, and the rogue approves everything. So a
    # gateway explicitly configured to fail closed serves invalid credentials
    # exactly as the fail-open one does, and both report PERMITTED.
    #
    for fault in wrong_address cname_chain; do
        run_experiment "dns.${fault}"
        assert_verdict "${fault} vs fail-closed" "deviated / PERMITTED"
        assert_exit "${fault} vs fail-closed" 2
        assert_confirmed "${fault}"
    done

    # And the instrument that makes that claim rather than inferring it: the
    # gateway did not fail to reach anything, it reached the rogue.
    if [[ "$(rogue_asked)" -gt 0 ]]; then
        pass "fail-closed did not protect the gateway: it reached the rogue and the rogue approved"
    else
        fail "the rogue was never asked, so this PERMITTED is not a redirect finding"
    fi

    # The correct client still falls back to TCP, so the fault it CAN handle
    # leaves it serving. Both halves of this gate assert the same fault in
    # opposite fixtures, which is what stops a verdict being right by accident.
    run_experiment dns.truncation
    assert_verdict "truncation vs fail-closed" "passed / HELD"
    assert_exit "truncation vs fail-closed" 0
fi

echo "== claim 4: a fault the target never MET is aborted, not survived =="

# The script's own header names this as one of four things that have to be true,
# and the first version never asserted it: no `aborted`, no "never met", and no
# target that fails to re-resolve. Three of four claims were asserted.
#
# The gateway under test re-resolves per request deliberately, so the way to
# produce a non-delivering target is to point the experiment at a gateway that
# does NOT: the DIRECT gateway reaches its dependency by container name, which
# its own embedded resolver answers locally and never forwards to khaos. A fault
# armed at khaos's resolver therefore reaches it zero times.
if start_range closed; then
    # A REAL credential, issued the way the lab issues one. A bogus token makes
    # the baseline fail with "the valid credential was never accepted", which is
    # also an inconclusive verdict — so asserting on "any inconclusive verdict"
    # would have passed for entirely the wrong reason. The assertion below
    # anchors on the delivery reason's own text for the same reason.
    direct_url="$(NO_COLOR=1 "$BIN" range status 2>/dev/null |
        grep -oE 'docker-native tier +http://127\.0\.0\.1:[0-9]+/protected' |
        grep -oE 'http://127\.0\.0\.1:[0-9]+/protected' | head -1)"
    gateway="${direct_url%/protected}"
    token="$(curl -s --max-time 5 -X POST "${gateway}/token" |
        sed -E 's/.*"token":"([^"]+)".*/\1/')"

    if [[ -z "$direct_url" || -z "$token" || "$token" == *'{'* ]]; then
        fail "could not issue a credential against the direct gateway, so claim 4 is unasserted"
    else
        set +e
        report="$("$BIN" run dns.nxdomain --no-color "${TIMING[@]}" \
            --target khaos-range-gateway \
            --url "$direct_url" \
            --token "$token" \
            --dns-host dependency.khaos.test. \
            --resolver-network khaos-range 2>&1)"
        last_code=$?
        set -e
        ran+=("dns.nxdomain")

        # The DIRECT gateway reaches its dependency by CONTAINER NAME, which its
        # own embedded resolver answers out of its own table and never forwards.
        # So a fault armed at khaos's resolver reaches it zero times, however
        # correctly khaos armed it.
        #
        # Anchored on the reason's own wording, not merely on an inconclusive
        # verdict, because several unrelated problems also produce one.
        if grep -qF "did not re-resolve its dependency's name" <<<"$report"; then
            pass "a fault the target never met is reported as never met"
        elif grep -qF "never used khaos's chaos resolver" <<<"$report"; then
            pass "a target that never used khaos's resolver voids the run by name"
        else
            fail "a target that cannot meet the fault produced: $(grep -E '^  verdict|^  why' <<<"$report" | head -2)"
        fi

        # What is FORBIDDEN is the clean survival, in either form.
        if grep -qE '^  verdict .*passed' <<<"$report"; then
            fail "a fault the target never met was reported as PASSED"
        else
            pass "no clean survival was claimed over an undelivered fault"
        fi

        if [[ "$last_code" == 0 ]]; then
            fail "an undelivered fault exited 0"
        else
            pass "an undelivered fault does not exit 0 (${last_code})"
        fi
    fi
fi

echo "== the rotation: a zone change that does not reach the target =="

# Both directions, because the finding is which one happened:
#
#   reresolve  the target asks again, follows the rotation, and accepts what the
#              new host approves -> deviated / PERMITTED exit 2
#   pinned     the target resolved once and reuses its connection, never sees
#              the rotation -> passed / HELD exit 0, with the operational
#              finding STATED and explicitly not called a bypass
#
# The pinned row is the one that needed a target shape the range did not have.
if start_range closed reresolve; then
    run_experiment dns.ttl_rotate

    assert_verdict "ttl_rotate against a re-resolving target" "deviated / PERMITTED"
    assert_exit "ttl_rotate against a re-resolving target" 2
    assert_confirmed "ttl_rotate against a re-resolving target"

    # The confirmation names BOTH addresses and says the answer came from the
    # honest path, which is what distinguishes a rotation from a redirect.
    assert_report_has \
        "the confirmation names the address the rotation replaced" \
        "before khaos moved it"
    assert_report_has \
        "and says the honest path serves it" \
        "from the resolver's own honest path rather than from a fault"
    assert_report_has \
        "the rotation is reported as having reached the target" \
        "so the rotation reached it"
fi

if start_range closed pinned; then
    run_experiment dns.ttl_rotate

    assert_verdict "ttl_rotate against a pinning target" "passed / HELD"
    assert_exit "ttl_rotate against a pinning target" 0
    assert_confirmed "ttl_rotate against a pinning target"

    # The finding has to be STATED, with both counts, and must NOT be called a
    # bypass: no credential got through that would not have before.
    assert_report_has \
        "the rotation is reported as not having reached the target" \
        "ZERO during the fault window"
    assert_report_has \
        "and the operational consequence is named" \
        "would not have taken effect either"
    assert_report_has \
        "and khaos explicitly reports no bypass" \
        "This is NOT a credential bypass"
    assert_report_lacks \
        "no credential is claimed to have been accepted" \
        "was accepted"
fi

echo "== the census: every catalogued fault was actually run =="

# A catalogued experiment this gate never runs is a failure, for the same reason
# the identity family's census exists: a family that advertises a fault nothing
# verifies is the thing this project exists not to do.
catalogued="$(NO_COLOR=1 "$BIN" catalog 2>/dev/null |
    grep -oE '^  dns\.[a-z_]+' | tr -d ' ')"


missing=0
for name in $catalogued; do
    found=0
    for executed in "${ran[@]}"; do
        [[ "$executed" == "$name" ]] && found=1
    done
    if [[ "$found" == 0 ]]; then
        fail "the catalogue advertises ${name} and this gate never RAN it"
        missing=$((missing + 1))
    fi
done

if [[ "$missing" == 0 ]]; then
    pass "every catalogued dns. fault was actually run by this gate (${#ran[@]} runs)"
fi

# And the reverse: a name this gate ran that is NOT catalogued means the gate is
# asserting against something that no longer exists.
for executed in "${ran[@]}"; do
    if ! grep -qx "$executed" <<<"$catalogued"; then
        fail "${executed} was run by this gate and is not in the catalogue"
    fi
done

if [[ "$failures" -gt 0 ]]; then
    echo "dns: ${failures} assertion(s) failed"
    exit 1
fi

echo "dns: all assertions passed"
