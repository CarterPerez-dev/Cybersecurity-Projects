#!/usr/bin/env bash
# ©AngelaMos | 2026
# proxy.sh

set -euo pipefail

BIN="${BIN:-$PWD/khaos}"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR

# The fault window has to clear MinimumToClaimClosed (30 paired samples) or a
# HELD verdict carries `Conclusive=false` and now exits 4: khaos stopped treating
# "no bypass observed, but the sample cannot rule one out" as a success.
TIMING=(--baseline-for 2s --fault-for 8s --recover-for 2s --sample-every 200ms)

# slow-close is the one fault this range cannot be made to feel, and the reason
# is a property of the protocol rather than a gap in the fixture.
#
# It exists to find a caller that waits for the connection to END instead of
# reading a Content-Length, and every service in the range is a Go HTTP/1.1
# server talking to a Go HTTP client. Go's server always frames a response with
# either Content-Length or chunked encoding, so its client returns the moment the
# body is complete and never waits for the close. Measured through the proxy: the
# body arrives intact in 296 microseconds against a three second hold.
#
# This gate used to assert a bypass here and it PASSED, for the wrong reason: the
# fault applied its delay to the relay as well as to the close, so it was finding
# what `network.dependency_latency` finds and reporting it as slow closure. The
# fix removed the payload delay, and this is what was underneath.
#
# The fault is still confirmed at the socket, which is where it lives, and that
# assertion is kept below. What cannot be asserted end to end is a VERDICT, so
# this gate asserts the truth instead of the thing it would prefer to see.
EOF_DEPENDENT_FAULT=network.dependency_slow_close

# These mirror portFloor and portCeil in internal/rangelab, and the container name
# in internal/rangelab. A shell gate cannot import them; naming them here at least
# keeps the duplication in one place per file.
PORT_FLOOR=30000
PORT_CEIL=60000
PROXIED_GATEWAY=khaos-range-gateway-proxied

PROXY_EXPERIMENTS=(
    network.dependency_hang
    network.dependency_reset
    network.dependency_eof
    network.dependency_latency
    network.dependency_partial
    network.dependency_slow_close
)

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
# Extra arguments REPLACE the default timing rather than appending to it: two
# copies of --fault-for on one command line is an ambiguity, and a helper that
# silently dropped an override would make a section measure the default window
# while claiming to measure a short one.
run_experiment() {
    local experiment="$1"
    shift

    local -a timing=("${TIMING[@]}")
    if [[ $# -gt 0 ]]; then
        timing=("$@")
    fi

    set +e
    report="$("$BIN" run "$experiment" --no-color "${timing[@]}" 2>&1)"
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

# The run record must name the observable khaos MEASURED, and a different one per
# fault. The first version of this grepped a single shared substring, which turned
# out to be a constant describing the technique rather than anything measured:
# replacing the socket read-back with a counter comparison, and deleting it
# outright so confirmation always said yes, both left this gate 35/35 green.
# A shared substring regresses straight back to decorative, so each fault gets its
# own expected string and nothing else can satisfy it.
expected_observable() {
    case "$1" in
        network.dependency_hang)       echo "never through its proxy" ;;
        network.dependency_reset)      echo "resets through its proxy" ;;
        network.dependency_eof)        echo "closes without answering through its proxy" ;;
        network.dependency_latency)    echo "later through khaos's proxy than directly" ;;
        network.dependency_partial)    echo "arrive through khaos's proxy where the dependency answers" ;;
        network.dependency_slow_close) echo "after the last byte, which it does not do directly" ;;
        *) echo "" ;;
    esac
}

assert_confirmed_on_the_socket() {
    local label="$1" want
    want="$(expected_observable "$1")"

    if [[ -z "$want" ]]; then
        fail "${label} has no expected observable, so this gate cannot check it"
        return
    fi

    if grep -qF "$want" <<<"$report"; then
        pass "${label} confirmed by its own measured observable"
    else
        fail "${label} did not report ${want}: $(grep -E '^  plan  confirm' <<<"$report" || echo '<none>')"
    fi
}

# Every fault's observable must be DISTINCT, or one constant satisfies them all.
assert_observables_are_distinct() {
    local -a seen=()
    local experiment want

    for experiment in "${PROXY_EXPERIMENTS[@]}"; do
        want="$(expected_observable "$experiment")"
        seen+=("$want")
    done

    local unique
    unique="$(printf '%s\n' "${seen[@]}" | sort -u | wc -l)"

    if [[ "$unique" -ne "${#PROXY_EXPERIMENTS[@]}" ]]; then
        fail "only ${unique} distinct observables for ${#PROXY_EXPERIMENTS[@]} faults; a shared string makes this gate decorative"
        return
    fi

    pass "every fault has its own distinct observable (${unique})"
}

# A run that measured nothing must not exit 0. A fault too large to confirm used
# to abort before measuring, report that honestly in the verdict text, and still
# exit success, so pointing khaos at a fail-open target in CI was a green build.
assert_an_unconfirmable_fault_is_not_success() {
    set +e
    report="$("$BIN" run network.dependency_partial --no-color "${TIMING[@]}" --bytes 999999 2>&1)"
    last_code=$?
    set -e

    if [[ "$last_code" -eq 0 ]]; then
        fail "a fault khaos could not confirm exited 0 against a target that fails open"
        return
    fi

    if ! grep -qE "^  verdict .*(aborted|probe-error|baseline-not-met)" <<<"$report"; then
        fail "expected an inconclusive verdict, got: $(grep -E '^  verdict' <<<"$report" || echo '<none>')"
        return
    fi

    local epistemic
    epistemic="$(grep -E '^  verdict' <<<"$report" |
        sed -E 's/^  verdict +([a-z-]+).*/\1/' | head -1 || true)"

    local want
    case "$epistemic" in
    aborted) want=7 ;;
    probe-error) want=5 ;;
    baseline-not-met) want=8 ;;
    *)
        fail "could not read an epistemic word out of the verdict: ${epistemic}"
        return
        ;;
    esac

    assert_exit "an unconfirmable fault (${epistemic})" "$last_code" "$want"
}

assert_ran_with_no_flags() {
    local label="$1"
    if grep -q "using the running range" <<<"$report"; then
        pass "${label} ran with no target flags at all"
    else
        fail "${label} did not discover the range on its own"
    fi
}

# The proxy must be reachable by the container and by nothing else. A wildcard
# bind would put a fault proxy, in front of a stack built to fail open, on the
# operator's network.
assert_proxy_bound_where_the_container_looks() {
    local bound expected
    bound="$(grep -oE "fault proxy is listening on [0-9.]+:[0-9]+" <<<"$report" | awk '{print $NF}')"

    if [[ -z "$bound" ]]; then
        fail "the run never said where it bound its fault proxy"
        return
    fi

    # Not through a bare command substitution under `set -e`: a docker hiccup
    # would kill the whole script instead of reporting one failed assertion.
    set +e
    expected="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)"
    set -e

    if [[ -z "$expected" ]]; then
        fail "could not read the Docker bridge gateway, so this assertion cannot check anything"
        return
    fi

    if [[ "${bound%:*}" != "$expected" ]]; then
        fail "the proxy bound ${bound}, but containers reach this host at ${expected}"
        return
    fi

    # The wildcard case is covered in Go by TestOpenRefusesAnAddressThatWouldExposeTheProxy
    # and TestOpenRefusesThisHostsRoutableAddress. It is unreachable here: a
    # wildcard is refused before the proxy ever prints an address, so `bound`
    # would be empty and the check above fires instead.
    local port="${bound##*:}"
    if (( port < PORT_FLOOR || port >= PORT_CEIL )); then
        fail "the proxy bound host port ${port}, outside the random high range"
        return
    fi

    pass "the proxy bound the bridge gateway on a random high port (${bound})"
}

# There is deliberately NO assertion here that the listener is gone after the run.
# It was tried and it was a kernel test wearing a khaos label: the listener belongs
# to a process that always exits, so the OS closes it no matter what khaos does,
# and deleting khaos's own teardown left that assertion green. It also passed
# silently on a host without `ss`. The property it claimed to check is real but it
# is only falsifiable in-process, and
# `TestClosingTheProxyRemovesTheFaultEntirely` in internal/inject/proxy does check
# it: it asserts the listener refuses connections and that arming a closed proxy
# returns ErrClosed.

# The gate's negative control: a proxy-tier experiment against a range that has no
# proxied gateway must be refused by name, not silently run against a path khaos
# does not sit in front of.
assert_refuses_without_a_proxied_gateway() {
    local out code
    docker rm -f "$PROXIED_GATEWAY" >/dev/null 2>&1 || true

    set +e
    out="$("$BIN" run network.dependency_reset --no-color "${TIMING[@]}" 2>&1)"
    code=$?
    set -e

    if [[ $code -eq 0 ]]; then
        fail "a proxy experiment ran with no proxied gateway in the range"
        return
    fi

    if ! grep -qE "${PROXIED_GATEWAY}|no running khaos range" <<<"$out"; then
        fail "the refusal did not name the missing part: $(tail -2 <<<"$out")"
        return
    fi

    pass "a proxy experiment is refused when the range has no proxied gateway"
}

# A Docker-native experiment must NOT be routed through the proxy. If it were, it
# would stop being a measurement of the Docker-native tier.
assert_direct_tier_is_not_proxied() {
    run_experiment network.dependency_outage

    if grep -q "fault proxy is listening" <<<"$report"; then
        fail "a container-pause experiment stood up a fault proxy"
        return
    fi

    # assert_verdict reports for itself. An unconditional pass here printed `ok`
    # even on the run where the verdict check had just failed.
    assert_verdict "direct tier" "deviated / PERMITTED"
    pass "the Docker-native tier ran without standing up a proxy"
}

if start_range open; then
    for experiment in "${PROXY_EXPERIMENTS[@]}"; do
        run_experiment "$experiment"
        assert_ran_with_no_flags "$experiment"
        assert_confirmed_on_the_socket "$experiment"

        if [[ "$experiment" == "$EOF_DEPENDENT_FAULT" ]]; then
            assert_verdict "$experiment" "passed / HELD"
            assert_exit "$experiment" "$last_code" 0
            continue
        fi

        assert_verdict "$experiment" "deviated / PERMITTED"
        assert_exit "$experiment" "$last_code" 2
    done

    assert_observables_are_distinct
    assert_proxy_bound_where_the_container_looks
    assert_direct_tier_is_not_proxied
    assert_an_unconfirmable_fault_is_not_success
    assert_refuses_without_a_proxied_gateway
fi

# The mirror. A control that fails CLOSED refuses the credential it had been
# honouring, and that is not a defect for this polarity, so it must not exit 2.
if start_range closed; then
    for experiment in "${PROXY_EXPERIMENTS[@]}"; do
        run_experiment "$experiment"

        if [[ "$experiment" == "$EOF_DEPENDENT_FAULT" ]]; then
            assert_verdict "${experiment} fail-closed" "passed / HELD"
            assert_exit "${experiment} fail-closed" "$last_code" 0
            continue
        fi

        assert_verdict "${experiment} fail-closed" "deviated / DENIED"

        assert_exit "${experiment} fail-closed" "$last_code" 3

        if grep -q "acceptable for this control" <<<"$report"; then
            pass "${experiment} fail-closed polarity spared the safe direction"
        else
            fail "${experiment} fail-closed polarity did not spare the safe direction"
        fi
    done
fi

# Asserted as a PAIR. "exit 4 on a short window" alone is satisfied by any
# failure; the same experiment with a full window exiting 0 is what proves the
# 4 came from the sample floor and not from something else going wrong.
if start_range closed; then
    run_experiment "$EOF_DEPENDENT_FAULT" \
        --baseline-for 4s --fault-for 3s --recover-for 2s --sample-every 300ms

    assert_verdict "a thin HELD window" "passed / HELD"
    assert_exit "a thin HELD window" "$last_code" 4

    # The SHORTFALL, named with both numbers. Without this the assertion
    # cannot tell a sample floor from any other inconclusive cause.
    if grep -qE 'paired samples cannot rule one out' <<<"$report"; then
        pass "a thin HELD window says how many samples it had and how many it needed"
    else
        fail "a thin HELD window did not name the sample shortfall: $(grep -E '^  why' <<<"$report" | head -2)"
    fi

    # The negative control: the same fault, a full window, exit 0.
    run_experiment "$EOF_DEPENDENT_FAULT" "${TIMING[@]}"

    assert_verdict "a full HELD window" "passed / HELD"
    assert_exit "a full HELD window" "$last_code" 0

    if grep -qE 'cannot rule one out' <<<"$report"; then
        fail "a full window still claimed its evidence was thin"
    else
        pass "a full HELD window claims its conclusion without a caveat"
    fi
fi

if [[ $failures -ne 0 ]]; then
    echo "${failures} proxy assertion(s) failed"
    exit 1
fi

echo "proxy: all assertions passed"
