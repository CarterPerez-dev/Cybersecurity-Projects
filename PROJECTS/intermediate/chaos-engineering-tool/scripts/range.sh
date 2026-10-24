#!/usr/bin/env bash
# ©AngelaMos | 2026
# range.sh

set -euo pipefail

BIN="${BIN:-$PWD/khaos}"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR

TIMING=(--baseline-for 3s --fault-for 6s --recover-for 3s --sample-every 200ms)

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
    if ! started="$("$BIN" range up --fail-mode "$1" --cache-ttl "${2:-2s}" --quiet --no-color 2>&1)"; then
        fail "range up --fail-mode $1 --cache-ttl ${2:-2s}: $(tail -3 <<<"$started")"
        printf '%s\n' "$started" >&2
        return 1
    fi
    return 0
}

# Sets the globals `report` and `last_code`. It must not be called through a
# command substitution: that runs it in a subshell and the report is lost while
# the exit code still comes back, which looks like a passing gate with no
# evidence behind it.
run_experiment() {
    set +e
    report="$("$BIN" run network.dependency_outage --no-color "${TIMING[@]}" 2>&1)"
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

# The gate's negative control: inputs it MUST reject, and the one safety
# property of a deliberately-vulnerable stack that nothing else checks.
assert_loopback_only() {
    local binding port
    binding="$(docker inspect -f '{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostIp}} {{.HostPort}}{{end}}{{end}}' khaos-range-gateway 2>/dev/null)"
    port="${binding##* }"

    if [[ "$binding" != "127.0.0.1 "* ]]; then
        fail "the range gateway is published on ${binding:-nothing}, not loopback; a stack built to fail open must never be reachable off the host"
        return
    fi

    if (( port < 30000 || port >= 60000 )); then
        fail "the range gateway is on host port ${port}, outside the random high range"
        return
    fi

    pass "the range is loopback-only on a random high port (${port})"
}

assert_refuses_foreign_compose() {
    local foreign out
    foreign="$(mktemp -d)"
    printf 'name: not-khaos\nservices: {}\n' > "${foreign}/compose.yml"

    set +e
    out="$(KHAOS_RANGE_DIR="$foreign" "$BIN" range down --no-color 2>&1)"
    local code=$?
    set -e
    rm -rf "$foreign"

    if [[ $code -eq 0 ]]; then
        fail "khaos ran compose down against a project it does not own"
        return
    fi

    if ! grep -q "does not belong to khaos" <<<"$out"; then
        fail "the refusal did not name the cause: ${out}"
        return
    fi

    pass "khaos refuses a compose file it does not own"
}

assert_refuses_half_specified() {
    local label="$1" out code
    shift

    set +e
    out="$("$BIN" plan network.dependency_outage --no-color "$@" 2>&1)"
    code=$?
    set -e

    if [[ $code -eq 0 ]] || ! grep -q "will not fill one half" <<<"$out"; then
        fail "a half-specified invocation (${label}) was silently completed from the range: ${out}"
        return
    fi

    pass "a half-specified invocation is refused rather than fused (${label})"
}

# A parameter no experiment declares must not be settable on it. The alternative
# is registering every experiment's parameters on one command, which at twelve
# experiments shows a beginner twenty flags that do nothing for the one they ran.
assert_rejects_undeclared_flag() {
    local out code
    set +e
    out="$("$BIN" run network.dependency_outage --ca-cert /dev/null --no-color 2>&1)"
    code=$?
    set -e

    if [[ $code -eq 0 ]] || ! grep -q "unknown flag" <<<"$out"; then
        fail "a flag this experiment never declared was accepted: ${out}"
        return
    fi

    pass "a flag the experiment never declared is rejected"
}

# Supplying everything the range could have answered means the operator is
# pointing khaos at their own stack, so khaos must not require a range at all.
assert_operator_stack_needs_no_range() {
    local out code
    "$BIN" range down --no-color >/dev/null 2>&1 || true

    set +e
    out="$("$BIN" plan network.dependency_outage --no-color \
        --target khaos-no-such-container --url http://127.0.0.1:1/ --token t 2>&1)"
    code=$?
    set -e

    if [[ $code -eq 0 ]]; then
        fail "khaos planned against a container that does not exist"
        return
    fi

    if grep -q "no running khaos range" <<<"$out"; then
        fail "a fully specified invocation still went looking for a range: ${out}"
        return
    fi

    pass "a fully specified invocation never looks for a range"
}

assert_zero_flags() {
    if grep -q "using the running range" <<<"$report"; then
        pass "$1 ran with no target flags at all"
    else
        fail "$1 did not discover the range on its own"
    fi
}

if start_range open; then
    run_experiment
    assert_zero_flags "fail-open"
    assert_verdict "fail-open" "deviated / PERMITTED"
    assert_exit "fail-open" "$last_code" 2
    assert_loopback_only
    assert_refuses_foreign_compose
    assert_refuses_half_specified "target only" --target something
    assert_refuses_half_specified "target and url, no token" --target t --url http://127.0.0.1:1/
    assert_rejects_undeclared_flag

    if grep -q "fault confirmed by" <<<"$report"; then
        pass "fail-open the fault was confirmed by read-back, not by an API return value"
    else
        fail "fail-open the fault was never confirmed"
    fi
fi

if start_range closed; then
    run_experiment
    assert_zero_flags "fail-closed"
    assert_verdict "fail-closed" "deviated / DENIED"

    assert_exit "fail-closed" "$last_code" 3

    if grep -q "acceptable for this control" <<<"$report"; then
        pass "fail-closed the deviation was recorded without calling it a defect"
    else
        fail "fail-closed polarity did not spare the safe direction"
    fi
fi

# The observer-effect cycle. Every other cycle runs the range at its default 2s
# decision cache against a 6s fault window, so a cached refusal expires INSIDE the
# fault and the hazard is never exercised. With the cache outliving the fault, a
# negative control that reuses one credential is answered entirely from that cache
# and a gateway explicitly configured to fail open reports `passed / HELD`,
# conclusive, exit 0 — the worst outcome this tool can produce. Measured: that is
# exactly what happens when the per-request nonce is removed.
if start_range open 30s; then
    run_experiment
    assert_verdict "fail-open with a cache outliving the fault" "deviated / PERMITTED"
    assert_exit "fail-open with a cache outliving the fault" "$last_code" 2
fi

assert_operator_stack_needs_no_range

if "$BIN" range down --no-color >/dev/null 2>&1; then
    remaining="$(docker ps -aq --filter label=khaos.range | wc -l)"
    nets="$(docker network ls -q --filter name=^khaos-range$ | wc -l)"
    images="$(docker images -q khaos-range:latest | wc -l)"

    if [[ "$remaining" -eq 0 && "$nets" -eq 0 && "$images" -eq 0 ]]; then
        pass "range down removed everything it created"
    else
        fail "range down left ${remaining} container(s), ${nets} network(s), ${images} image(s) behind"
    fi
else
    fail "range down errored"
fi

if [[ $failures -ne 0 ]]; then
    echo "${failures} range assertion(s) failed"
    exit 1
fi

echo "range: all assertions passed"
