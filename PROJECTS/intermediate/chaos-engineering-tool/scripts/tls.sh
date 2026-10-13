#!/usr/bin/env bash
# ©AngelaMos | 2026
# tls.sh

set -euo pipefail

# M7's exit gate. Two things have to be true of the `tls.` family, and both of
# them are about khaos declining to say more than it knows.
#
#   1. `revoked` reports UNSUPPORTED against a target that never checks
#      revocation, and a DEFECT-CAPABLE verdict against one that does. Go's
#      crypto/x509 performs no revocation checking of any kind and has no
#      option to turn it on, so calling an acceptance PASSED would clear a
#      target that used a revoked certificate, and calling it PERMITTED would
#      accuse it of bypassing a check it never had.
#
#   2. The byte-identical faults are disambiguated. Five of them produce one of
#      two identical client errors, measured on go1.26.5, so nothing a target
#      logs can say which happened and khaos has to report what it SERVED.

BIN="${BIN:-$PWD/khaos}"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR

# The fault window has to produce at least MinimumToClaimClosed paired samples,
# which is 30. khaos refuses to call a HELD run conclusive below that, and two
# of this gate's assertions are about a HELD verdict's exit code: at 5s and
# 400ms it got 13 samples, the verdict was honestly marked inconclusive, and
# both exited 4 instead of the code the gate was checking for. That was the gate
# asking khaos to claim more than its own sample floor allows.
TIMING=(--baseline-for 4s --fault-for 12s --recover-for 3s --sample-every 300ms)

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

# The range's TLS gateway runs one reference client per `range up`, so a gate
# that spans modes has to restart it. That is slow and unavoidable: the mode is
# fixed at container creation, deliberately, because a gateway that could be
# reconfigured mid-run would let khaos change the target it is measuring.
start_range() {
    "$BIN" range down --no-color >/dev/null 2>&1 || true
    if ! "$BIN" range up --tls-mode "$1" --no-color --quiet >/dev/null 2>&1; then
        fail "range up --tls-mode $1"
        return 1
    fi
    return 0
}

# Sets the globals `report` and `last_code`. Never call it through a command
# substitution: that runs it in a subshell and the report is lost while the exit
# code still comes back, which looks like a passing gate with no evidence.
run_experiment() {
    local experiment="$1"
    shift
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

# The observable, not the verdict. This is the half of the gate that makes the
# identical-error faults tractable.
observable_of() {
    grep -E '^  plan  confirm   fault confirmed by ' <<<"$report" |
        sed -E 's/^.*fault confirmed by //'
}

echo "== the correct client =="

if start_range closed; then
    # Go REFUSES this chain, the correct client refuses it, and the gateway
    # declines to serve. DENIED is the right answer for a certificate fault and
    # this family declares it acceptable, so it must not be called a defect.
    run_experiment tls.leaf_expired
    assert_verdict "leaf-expired vs a correct client" "deviated / DENIED"
    assert_exit "leaf-expired vs a correct client" 0
    assert_confirmed "leaf-expired"

    # THE CONTRAST, and the reason the unsupported verdict is honest rather
    # than an excuse. This client DOES check revocation, so a revoked
    # certificate is a finding it can actually have.
    run_experiment tls.revoked_via_crl
    assert_verdict "revoked vs a client that checks" "deviated / DENIED"
    assert_exit "revoked vs a client that checks" 0

    if grep -qE '^  verdict .*unsupported' <<<"$report"; then
        fail "revoked was called unsupported against a client that fetches the CRL, which excuses a real defect"
    else
        pass "revoked is not excused as unsupported when the target does check"
    fi

    # The trust-store fault, whose acceptance is NOT a finding about the
    # target. Once the anchor is replaced the chain is genuinely valid and no
    # client-side check can see it, so declaring HELD a defect here would
    # accuse every correct TLS implementation of a bug.
    run_experiment tls.ca_swap
    assert_exit "ca-swap vs a correct client" 0

    # The PRECISE phrase, because the not-a-defect sentence also contains the
    # word "defect" -- it ends "without calling it a defect" -- and a loose
    # grep matched both and failed this assertion against correct behaviour.
    if grep -qE 'to be the defect for this control' <<<"$report"; then
        fail "ca-swap was reported as a defect, which accuses a correct client of a bug it cannot avoid"
    else
        pass "ca-swap is not a defect, because no client-side check can detect it"
    fi
fi

echo "== M7 exit gate, first half: revocation is UNSUPPORTED, never a pass =="

if start_range no-revocation-check; then
    run_experiment tls.revoked_via_crl
    assert_verdict "revoked vs a client that never asks" "unsupported"

    # NOT zero. A revoked certificate in active use must never exit 0, and
    # every inconclusive epistemic outcome exits 4.
    assert_exit "revoked vs a client that never asks" 4

    if grep -qE '^  verdict .*passed' <<<"$report"; then
        fail "a revoked certificate in active use was reported as a pass"
    else
        pass "a revoked certificate in active use is never a pass"
    fi

    if grep -qE '^  verdict .*PERMITTED' <<<"$report"; then
        fail "the target was accused of permitting a bypass, which needs a check to have been bypassed"
    else
        pass "the target is not accused of bypassing a check it never had"
    fi

    if grep -qE '^  why .*never performed revocation checking' <<<"$report"; then
        pass "the verdict says WHY it makes no claim"
    else
        fail "the unsupported verdict carries no reason: $(grep -E '^  why' <<<"$report" || echo '<none>')"
    fi
fi

echo "== M7 exit gate, second half: identical errors are disambiguated =="

if start_range closed; then
    # All three produce `x509: certificate signed by unknown authority`, with
    # no reason code and nothing in the string to separate them.
    declare -A observed=()

    for experiment in tls.self_signed tls.untrusted_ca tls.missing_intermediate; do
        run_experiment "$experiment"
        assert_confirmed "$experiment"

        seen="$(observable_of)"
        if [[ -z "$seen" ]]; then
            fail "$experiment produced no observable to disambiguate it by"
            continue
        fi

        for other in "${!observed[@]}"; do
            if [[ "${observed[$other]}" == "$seen" ]]; then
                fail "$experiment and $other report the SAME observable (${seen}), so khaos cannot say which it served"
            fi
        done

        observed["$experiment"]="$seen"
    done

    if [[ "${#observed[@]}" -eq 3 ]]; then
        pass "the three unknown-authority faults report three distinct observables"
    else
        fail "only ${#observed[@]} of the three unknown-authority faults were observable"
    fi

    # The SECOND identical group, which research 04's fault table got wrong.
    # Both extended key-usage faults come back as InvalidReason 4 on go1.26.5;
    # the row claiming the CA-level one yields Reason 9 is impossible, because
    # crypto/x509 never constructs that reason at all.
    declare -A eku=()

    for experiment in tls.eku_client_auth_only tls.eku_constrained_intermediate; do
        run_experiment "$experiment"
        assert_confirmed "$experiment"
        eku["$experiment"]="$(observable_of)"
    done

    if [[ -n "${eku[tls.eku_client_auth_only]:-}" ]] &&
        [[ "${eku[tls.eku_client_auth_only]}" != "${eku[tls.eku_constrained_intermediate]:-}" ]]; then
        pass "the two key-usage faults report distinct observables despite sharing a reason code"
    else
        fail "the two key-usage faults are indistinguishable: $(printf '%s | ' "${eku[@]}")"
    fi
fi

echo "== a gateway that uses the certificate anyway =="

if start_range skip-verify; then
    # InsecureSkipVerify. The gateway accepts an expired certificate, reaches
    # its dependency, authorises normally, and NOTHING looks wrong. That is
    # HELD, and for this family it is a defect: the target will talk to
    # anything presenting a certificate.
    run_experiment tls.leaf_expired
    assert_verdict "leaf-expired vs InsecureSkipVerify" "passed / HELD"

    # 2 is the defect exit code. A target that used a certificate khaos
    # deliberately broke must not exit 0.
    assert_exit "leaf-expired vs InsecureSkipVerify" 2

    if grep -qE 'to be the defect for this control' <<<"$report"; then
        pass "carrying on unchanged is reported as the defect it is"
    else
        fail "the verdict does not name the defect: $(grep -E '^  why' <<<"$report" || echo '<none>')"
    fi
fi

if [[ "$failures" -gt 0 ]]; then
    echo "tls: ${failures} assertion(s) failed"
    exit 1
fi

echo "tls: all assertions passed"
