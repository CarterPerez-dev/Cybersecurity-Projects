#!/usr/bin/env bash
# ©AngelaMos | 2026
# control.sh

set -euo pipefail

#   1. EVERY experiment is asserted in BOTH directions on a live range. A
#      fail-open target reports `deviated / PERMITTED` exit 2 and a fail-closed
#      one reports `passed / HELD` exit 0 on the identical fault. One direction
#      alone cannot tell a defect from a control that was never consulted.
#
#   2. The limiter is DATASTORE-backed, and these two rows are the proof.
#      Kong's rate-limiting plugin defaults to `policy = local`, an in-memory
#      per-node counter with no datastore to partition: against one of those,
#      severing the datastore changes nothing and both rows come back HELD. The
#      rows differing IS the assertion that the counter is on the severed path.
#
#   3. The three controls are severed INDEPENDENTLY, asserted two ways: the
#      three dependency addresses read out of ONE running gateway are pairwise
#      distinct, and the rule matcher still refuses what its rules match while
#      the policy store is reachable. Address distinctness is the structure;
#      the second is the property that matters.
#
#   4. The cold start RAN, asserted on the container's own start time rather
#      than on khaos's stage line -- the line is emitted BEFORE the restart is
#      attempted, so it stays green against a restart that never happened.
#
#   5. The profile split is real. Only the limiter needs the stateful tier, so
#      only it is refused without --with-db, and the other three must RUN on a
#      default range. Asserting one without the other would pass against a
#      family that quietly required the opt-in tier everywhere.

BIN="${BIN:-$PWD/khaos}"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR

# The fault window has to clear MinimumToClaimClosed, which is 30 paired
# samples, or a HELD verdict is honestly marked inconclusive and exits 4 rather
# than 0. At 300ms this gives ~66.
TIMING=(--baseline-for 5s --fault-for 20s --recover-for 3s --sample-every 300ms)

# A longer window for the cold start. NOT because the restart eats into it --
# coldStart runs before measureFault, so the restart and the settle poll cost
# the window nothing -- but because the target it measures has just booted,
# and a wider window is what makes a thin sample count unambiguous.
COLD_TIMING=(--baseline-for 5s --fault-for 60s --recover-for 3s --sample-every 300ms)

failures=0
report=""
last_code=0
ran=()

cleanup() {
    "$BIN" range down --no-color >/dev/null 2>&1 || true
    rm -rf "$KHAOS_STATE_DIR"
}
trap cleanup EXIT INT TERM HUP

pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }

# The fail mode is fixed at container creation, deliberately, so a gate
# spanning both directions has to recreate the stack. `with_db` is passed only
# for the limiter: the other three controls are in the default range and
# gating them on the stateful tier would cost two more engine startups.
start_range() {
    local fail_mode="$1" with_db="${2:-no}"
    local -a args=(range up --fail-mode "$fail_mode" --no-color --quiet)

    [[ "$with_db" == "yes" ]] && args+=(--with-db)

    "$BIN" range down --no-color >/dev/null 2>&1 || true

    # The OUTPUT, not just the fact. A bare "range up failed" is what a
    # transient startup error looks like in a two-hour gate run, and it
    # leaves nothing to diagnose from.
    local started
    if ! started="$("$BIN" "${args[@]}" 2>&1)"; then
        fail "range up --fail-mode $fail_mode (with-db=$with_db): $(tail -3 <<<"$started")"
        printf '%s\n' "$started" >&2
        return 1
    fi
    return 0
}

# Sets the globals `report` and `last_code`. Never call it through a command
# substitution: that runs it in a subshell and the report is lost while the
# exit code still comes back, which looks like a passing gate with no evidence.
run_experiment() {
    local experiment="$1"
    shift
    ran+=("$experiment")
    set +e
    report="$("$BIN" run "$experiment" --no-color "$@" 2>&1)"
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

# `--` before the pattern, or grep reads a phrase that starts with a dash as
# its own option: asserting that a refusal names `--with-db` died with
# "unrecognized option" and reported the product as silent about it.
assert_report_has() {
    local label="$1" want="$2"
    if grep -qF -- "$want" <<<"$report"; then
        pass "${label}"
    else
        fail "${label}: the report never says ${want}"
    fi
}

assert_report_lacks() {
    local label="$1" want="$2"
    if grep -qF -- "$want" <<<"$report"; then
        fail "${label}: the report says ${want}"
    else
        pass "${label}"
    fi
}

# Every grepping helper ends in `|| true`: with `set -e`, a grep inside a
# command substitution that legitimately matches nothing kills the script, and
# `grep -c` does it while printing a perfectly good 0.
# started_at is the restart OBSERVABLE. The cold-start stage line is emitted
# BEFORE khaos attempts the restart, so asserting the line proves only that
# khaos intended to restart: gutting Injector.Restart to a nil return leaves
# it green. The container's own start time cannot be faked by khaos.
started_at() {
    docker inspect -f '{{.State.StartedAt}}' \
        khaos-range-gateway-control 2>/dev/null || true
}

# dependency_ports reads all three addresses out of ONE running gateway, which
# is the only way this comparison means anything: each `range up` draws fresh
# random ports, so comparing addresses captured across two range lifetimes
# tests that FreePorts returns distinct numbers rather than that the three
# controls dial distinct dependencies.
dependency_ports() {
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' \
        khaos-range-gateway-control 2>/dev/null |
        grep -E 'KHAOS_RANGE_(LIMIT|POLICY|RULES)_STORE=' |
        sed -E 's/.*:([0-9]+)$/\1/' | sort || true
}

# A fail-open target serves what the control refused a moment ago. A
# fail-closed one keeps refusing it and pays an availability cost khaos does
# not measure, which is the correct outcome rather than a defect.
assert_open() {
    local label="$1"
    assert_confirmed "$label"
    assert_verdict "$label" "deviated"
    assert_report_has "${label} names the direction" "PERMITTED"
    assert_exit "$label" 2
}

assert_closed() {
    local label="$1"
    assert_confirmed "$label"
    assert_verdict "$label" "passed"
    assert_report_has "${label} names the direction" "HELD"
    assert_exit "$label" 0
}

# The limiter's own fail-closed row, and it is NOT the one above. A limiter
# that cannot count refuses EVERY request rather than only the over-budget
# one, so the valid stream stops being served and khaos reads DENIED --
# correct, with an availability cost, and recorded without being called a
# defect because the polarity declares only PERMITTED. Measured on the live
# range at 62 refusals of the valid credential across a 20s window.
assert_denied() {
    local label="$1"
    assert_confirmed "$label"
    assert_verdict "$label" "deviated"
    assert_report_has "${label} names the direction" "DENIED"
    assert_report_has \
        "${label} is not called a defect" \
        "without calling it a defect"

    assert_exit "$label" 3
}

echo "== the three default-range controls, fail-open =="

if start_range open; then
    run_experiment control.policy_store_down "${TIMING[@]}"
    assert_open "policy_store_down fail-open"

    # The counterpart of the cold-start assertion below: these two differ in
    # the DECLARED defect and in nothing else khaos prints.
    assert_report_has \
        "policy_store_down names the dropped policy" \
        "stops being enforced when its store is unreachable"

    run_experiment control.waf_rules_backend_down "${TIMING[@]}"
    assert_open "waf_rules_backend_down fail-open"

    before_restart="$(started_at)"

    run_experiment control.policy_store_cold_start "${COLD_TIMING[@]}"
    assert_open "policy_store_cold_start fail-open"

    # The container's OWN start time, which khaos cannot fake. Without this
    # the fail-open cold-start row is byte-identical in outcome to
    # policy_store_down's, and a gutted Injector.Restart stays green.
    after_restart="$(started_at)"
    if [[ -n "$before_restart" && "$before_restart" != "$after_restart" ]]; then
        pass "policy_store_cold_start restarted the container (start time moved)"
    else
        fail "the container's start time did not move, so no restart happened: ${before_restart} -> ${after_restart}"
    fi

    # The phase, not the verdict. This experiment reports the same direction on
    # the same observable as policy_store_down, so without this assertion a
    # deleted restart leaves the verdict, the exit code and the gate unchanged.
    assert_report_has \
        "policy_store_cold_start actually restarted the target" \
        "restarting the target so it initialises"

    # And the finding has to name the EMPTY policy set rather than a dropped
    # one. Both experiments read the same direction off the same observable,
    # so without this the two reports are identical and the verdict alone
    # cannot tell an operator which bug they have.
    assert_report_has \
        "policy_store_cold_start names the empty policy set" \
        "an empty policy set read as a policy that denies nothing"

    assert_report_lacks \
        "policy_store_cold_start does not claim a policy was dropped" \
        "stops being enforced when its store is unreachable"

    run_experiment control.ratelimit_store_down "${TIMING[@]}"
    if [[ "$last_code" == 0 ]]; then
        fail "ratelimit_store_down ran without the stateful tier, so it measured a datastore that is not there"
    else
        pass "ratelimit_store_down is refused without the stateful tier"
    fi
    assert_report_has \
        "the refusal names the tier rather than just saying no" \
        "--with-db"
fi

echo "== the same three, fail-closed =="

if start_range closed; then
    run_experiment control.policy_store_down "${TIMING[@]}"
    assert_closed "policy_store_down fail-closed"

    # The caveat is what a HELD finding carries instead of a leak reason, and
    # the availability cost is the half khaos must not claim to have measured.
    assert_report_has \
        "the held run states the availability cost it did not measure" \
        "availability cost"

    assert_report_lacks \
        "no credential is claimed to have been accepted" \
        "was accepted"

    run_experiment control.waf_rules_backend_down "${TIMING[@]}"
    assert_closed "waf_rules_backend_down fail-closed"

    # DENIED rather than HELD, and for the same reason as the limiter: a
    # target that INITIALISED with no policy at all refuses every request
    # rather than only the one the policy denies, so the valid stream stops
    # being served. Measured at 183 refusals across a 60s window. The
    # polarity declares only PERMITTED, so khaos records the direction and
    # explicitly does not call it a defect.
    run_experiment control.policy_store_cold_start "${COLD_TIMING[@]}"
    assert_denied "policy_store_cold_start fail-closed"
fi

echo "== the limiter, both directions, on the stateful tier =="

if start_range open yes; then
    run_experiment control.ratelimit_store_down "${TIMING[@]}"
    assert_open "ratelimit_store_down fail-open"

    # The defect in its own words. Kong's fault_tolerant = true is the one
    # genuine fail-open default in the twenty-two-row taxonomy, and this is
    # the sentence that says khaos measured it rather than inferred it.
    assert_report_has \
        "the run names the limiter's own defect" \
        "disables itself when its datastore is unreachable"
fi

if start_range closed yes; then
    run_experiment control.ratelimit_store_down "${TIMING[@]}"
    assert_denied "ratelimit_store_down fail-closed"
fi

echo "== the three controls are severed independently =="

# The structural half of the one-gateway design. Two of these dependencies
# terminate at the SAME backend container, so the only thing that makes them
# two faults is the gateway dialling a different address for each.
#
# Read from ONE running gateway. The previous version compared addresses
# captured across two different `range up` lifetimes, so it was comparing
# ports from two unrelated random draws: it would have passed with all three
# controls wired to the same port, and could only ever fail on a coincidence.
if start_range closed; then
    ports="$(dependency_ports)"
    distinct="$(echo "$ports" | sort -u | grep -c . || true)"
    total="$(echo "$ports" | grep -c . || true)"

    if [[ "$total" != 3 ]]; then
        fail "the control gateway carries ${total} dependency addresses, want 3; this section cannot fail"
    elif [[ "$distinct" == 3 ]]; then
        pass "all three controls dial distinct dependency addresses"
    else
        fail "the three controls resolve to ${distinct} distinct addresses, so one fault severs more than one control"
    fi

    # And the behavioural half: with the policy store severed mid-run, the
    # rule matcher must still refuse what its own rules match. Address
    # distinctness is structure; this is the property that matters.
    token_url="http://127.0.0.1:$(docker port khaos-range-gateway-control 8080 | head -1 | sed -E 's/.*://')"
    flagged="$(curl -s -X POST "${token_url}/flagged-token" |
        sed -E 's/.*"token":"([^"]+)".*/\1/' || true)"

    if [[ -z "$flagged" ]]; then
        fail "could not obtain a flagged credential, so the behavioural check cannot fail"
    else
        filtered_status="$(curl -s -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer ${flagged}" \
            "${token_url}/filtered" || true)"

        if [[ "$filtered_status" == 403 ]]; then
            pass "the rule matcher refuses a matching request while the policy store is reachable"
        else
            fail "the rule matcher answered ${filtered_status} to a request its rules match, want 403"
        fi
    fi
fi

echo "== the census: every catalogued fault was actually run =="

# Read from `run --help` rather than from `catalog`: catalog TRUNCATES an
# experiment name at 30 characters, and control.policy_store_cold_start is
# longer than that, so a census built on catalog would compare a truncated
# name and fail for the wrong reason.
catalogued="$(NO_COLOR=1 "$BIN" run --help 2>/dev/null |
    grep -oE 'control\.[a-z_]+' | sort -u || true)"

if [[ -z "$catalogued" ]]; then
    fail "the census read no control. experiments at all, so it cannot fail"
fi

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
    pass "every catalogued control. fault was actually run by this gate (${#ran[@]} runs)"
fi

# And the reverse: a name this gate ran that is NOT catalogued means the gate
# is asserting against something that no longer exists.
for executed in "${ran[@]}"; do
    if ! grep -qx "$executed" <<<"$catalogued"; then
        fail "${executed} was run by this gate and is not in the catalogue"
    fi
done

if [[ "$failures" -gt 0 ]]; then
    echo "control: ${failures} assertion(s) failed"
    exit 1
fi

echo "control: all assertions passed"
