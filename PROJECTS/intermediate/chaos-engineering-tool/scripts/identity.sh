#!/usr/bin/env bash
# ©AngelaMos | 2026
# identity.sh

set -euo pipefail

BIN="${BIN:-$PWD/khaos}"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR

# The pause has to outlast the range's staleness ceiling, which is a multiple of
# the cache lifetime. At a 2s lifetime the ceiling is 8s, so 14s is comfortably
# past it without making the gate crawl.
#
# The fault window then has to be AT LEAST the pause, and this gate shipped with
# 8s against a 14s pause — the exact configuration under which the TTL-extension
# diagnosis is unsound, because a fixed lifetime between those two durations
# produces the same observation. khaos now refuses the causal claim there, so a
# gate that still asked for it would be asserting what the tool declines to say.
CACHE_TTL=2s
TIMING=(--baseline-for 4s --fault-for 14s --recover-for 3s --sample-every 200ms --idle-for 14s)

EXPERIMENT=identity.idp_outage

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
    if ! started="$("$BIN" range up --fail-mode "$1" --cache-ttl "$CACHE_TTL" --quiet --no-color 2>&1)"; then
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
    report="$("$BIN" run "$EXPERIMENT" --no-color "${TIMING[@]}" "$@" 2>&1)"
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
    local label="$1" got="$2" want="$3"
    if [[ "$got" == "$want" ]]; then
        pass "${label} exit code ${want}"
    else
        fail "${label} exit code ${got}, want ${want}"
    fi
}

assert_cause() {
    local label="$1" want="$2"
    if grep -qE "^  cause .*${want}" <<<"$report"; then
        pass "${label} cause is ${want}"
    else
        fail "${label} expected cause ${want}, got: $(grep -E '^  cause' <<<"$report" || echo '<none>')"
    fi
}

assert_no_cause() {
    local label="$1"
    if grep -qE "^  cause " <<<"$report"; then
        fail "${label} reported a cause on a run with no leak to diagnose: $(grep -E '^  cause' <<<"$report")"
        return
    fi
    pass "${label} reported no cause, because there was nothing to diagnose"
}

# The two extra phases are what make this experiment different from severing a
# dependency, so the gate has to see both of them happen.
assert_phase() {
    local label="$1" stage="$2" because="$3"
    if grep -qE "^  plan  ${stage}" <<<"$report"; then
        pass "${label} ran the ${stage} phase"
    else
        fail "${label} never ran the ${stage} phase, ${because}"
    fi
}

# Two halves. The verdict has to say a REVOKED credential was honoured, and it
# has to say HOW khaos invalidated it in THIS experiment's own words.
#
# The second half exists because one shared sentence previously claimed every
# revocation happened "while that authority was unreachable", which is true only
# of this experiment: a key rollover and a plain revocation both leave the
# provider fully reachable, so two of the three experiments with a revoked stream
# were asserting something false about their own run.
assert_states_the_revocation() {
    local label="$1"

    if ! grep -q "invalidated at the authority" <<<"$report"; then
        fail "${label} did not state that a REVOKED credential was honoured: $(grep -E '^  why' <<<"$report" | head -1)"
        return
    fi

    if ! grep -q "an authority the target could no longer reach" <<<"$report"; then
        fail "${label} did not say HOW khaos invalidated the credential, so the verdict would read "\
"identically for every experiment with a revoked stream: $(grep -E '^  why' <<<"$report" | head -1)"
        return
    fi

    pass "${label} states what khaos actually observed, and how"
}

# The gate's negative control: khaos must not clear a target whose credential it
# never managed to revoke. Pointing the authority at a closed port makes the
# mid-run action fail for real.
assert_a_failed_revocation_voids_the_run() {
    run_experiment --authority http://127.0.0.1:1 \
        --target khaos-range-idp \
        --url "$(grep -oE 'http://127\.0\.0\.1:[0-9]+/protected' <<<"$report" | head -1)" \
        --token placeholder --revocable-token placeholder

    if [[ "$last_code" -eq 0 ]]; then
        fail "a run whose revocation failed exited 0, so khaos cleared a target it never tested"
        return
    fi

    if grep -qE "^  verdict .*deviated" <<<"$report"; then
        fail "a run whose revocation failed still reported a deviation: $(grep -E '^  verdict' <<<"$report")"
        return
    fi

    pass "a failed revocation voids the run instead of clearing the target"
}

# A cached allow being re-armed by every failed check. Steady traffic keeps it
# alive; the pause lets it lapse.
if start_range stale-rearm; then
    run_experiment
    assert_verdict "re-armed cache" "deviated / PERMITTED"
    assert_cause "re-armed cache" "LAPSED-ON-PAUSE"
    assert_exit "re-armed cache" "$last_code" 2
    assert_phase "re-armed cache" "act" "so nothing it measured had been revoked"
    assert_phase "re-armed cache" "idle" "so the two causes were never separated"
    assert_phase "re-armed cache" "resume" "so nothing was measured after the pause"
    assert_states_the_revocation "re-armed cache"
    assert_a_failed_revocation_voids_the_run
fi

# The other bug. Identical to the above under steady traffic, and the pause is
# the only thing that tells them apart.
if start_range open; then
    run_experiment
    assert_verdict "stale-past-pause cache" "deviated / PERMITTED"
    assert_cause "stale-past-pause cache" "STALE-PAST-PAUSE"
    assert_exit "stale-past-pause cache" "$last_code" 2
    assert_states_the_revocation "stale-past-pause cache"
fi

# The reference implementation. Refusing a credential it can no longer verify is
# correct, it is not the declared defect, and there is no cause to diagnose.
if start_range closed; then
    run_experiment
    assert_verdict "fail-closed" "deviated / DENIED"

    assert_exit "fail-closed" "$last_code" 3
    assert_no_cause "fail-closed"

    if grep -q "acceptable for this control" <<<"$report"; then
        pass "fail-closed polarity spared the safe direction"
    else
        fail "fail-closed polarity did not spare the safe direction"
    fi
fi

if [[ $failures -ne 0 ]]; then
    echo "${failures} identity assertion(s) failed"
    exit 1
fi

echo "identity: all assertions passed"
