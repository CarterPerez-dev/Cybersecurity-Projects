#!/usr/bin/env bash
# ©AngelaMos | 2026
# report.sh

set -euo pipefail

#   1. The EXIT CODE TAXONOMY is exercised end to end against a live range.
#      A single non-zero code would collapse "a control failed open", "the
#      experiment was invalid" and "khaos could not measure" into one signal,
#      and those need three different human responses. Every code this gate
#      can reach is driven and asserted; the four it cannot are named below
#      with the reason, rather than left to look covered.
#
#   2. `--fail-on` NARROWS and never widens. The default keeps every non-pass
#      non-zero, because a run khaos declined to conclude from exiting 0 is a
#      green build on no evidence. No value may suppress a rollback failure.
#
#   3. The record is the canonical artifact and the events file is linked to
#      it BY HASH, so a record cannot be silently separated from the
#      observations it summarises.
#
#   4. The projections are projections. The JUnit XML and the metrics file are
#      derived from the record, so they must name the same run and the same
#      exit code, and a real parser has to accept each of them: `promtool`
#      for the metrics and an XML parser for the suite.
#
#   5. A record the operator ASKED FOR and did not get is never silent, and
#      never masks a verdict either.

BIN="${BIN:-$PWD/khaos}"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR

WORK="$(mktemp -d)"

# Three sample bands, because the verdict's own thresholds are what separate
# three different exit codes: under MinimumPaired (5) khaos cannot measure,
# under MinimumToClaimClosed (30) it will not call a hold conclusive, and
# above it a hold is a hold.
FULL=(--baseline-for 5s --fault-for 20s --recover-for 3s --sample-every 300ms)
THIN=(--baseline-for 4s --fault-for 3s --recover-for 2s --sample-every 300ms)
TINY=(--baseline-for 4s --fault-for 600ms --recover-for 2s --sample-every 300ms)

failures=0
report=""
last_code=0

cleanup() {
    "$BIN" range down --no-color >/dev/null 2>&1 || true
    rm -rf "$KHAOS_STATE_DIR" "$WORK"
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
    if ! started="$("$BIN" range up --fail-mode "$1" --no-color --quiet 2>&1)"; then
        fail "range up --fail-mode $1: $(tail -3 <<<"$started")"
        printf '%s\n' "$started" >&2
        return 1
    fi
    return 0
}

# Never through a command substitution: that runs in a subshell and the
# report is lost while the exit code still comes back, which reads as a
# passing gate with no evidence.
run_experiment() {
    local experiment="$1"
    shift
    set +e
    report="$("$BIN" run "$experiment" --no-color "$@" 2>&1)"
    last_code=$?
    set -e
}

assert_exit() {
    local label="$1" want="$2"
    if [[ "$last_code" == "$want" ]]; then
        pass "${label} exit ${want}"
    else
        fail "${label} exit ${last_code}, want ${want}"
    fi
}

assert_verdict() {
    local label="$1" want="$2"
    if grep -qE "^  verdict .*${want}" <<<"$report"; then
        pass "${label} verdict is ${want}"
    else
        fail "${label} expected ${want}, got: $(grep -E '^  verdict' <<<"$report" || echo '<none>')"
    fi
}

echo "== the exit codes, driven against a live range =="

if start_range open; then
    # 2, the gate. The only code a pipeline should break on by default.
    run_experiment control.policy_store_down "${FULL[@]}"
    assert_verdict "a defect" "deviated / PERMITTED"
    assert_exit "a defect" 2

    # 4. A HELD verdict khaos declined to call conclusive. This used to exit
    # 0: khaos asserting a control held on evidence it refused to stand
    # behind, as a green build.
    run_experiment network.dependency_slow_close "${THIN[@]}"
    assert_verdict "a thin hold" "passed / HELD"
    assert_exit "a thin hold" 4

    # 5. Fewer paired samples than khaos needs to measure anything at all,
    # which is a different problem from a hold it will not call conclusive.
    run_experiment network.dependency_slow_close "${TINY[@]}"
    assert_exit "a window too short to measure" 5

    # 7. A fault khaos could not confirm. Measuring nothing is not passing.
    run_experiment network.dependency_partial "${FULL[@]}" --bytes 999999
    assert_exit "a fault that could not be confirmed" 7

    # 1. Usage. Refused before anything is injected.
    run_experiment control.policy_store_down --fail-on not-an-outcome
    assert_exit "an outcome khaos cannot gate on" 1

    if grep -q 'is not an outcome khaos can gate on' <<<"$report"; then
        pass "the refusal names the cause rather than just failing"
    else
        fail "the usage refusal did not name the cause"
    fi
fi

if start_range closed; then
    # 0 and 3 are the pair that makes the directional axis visible: the same
    # fault, the same correct target, and khaos separates "nothing moved"
    # from "it refused to serve, which is correct and costs availability".
    run_experiment network.dependency_slow_close "${FULL[@]}"
    assert_verdict "a clean hold" "passed / HELD"
    assert_exit "a clean hold" 0

    run_experiment network.dependency_reset "${FULL[@]}"
    assert_verdict "a non-defect deviation" "deviated / DENIED"
    assert_exit "a non-defect deviation" 3
fi

echo "== --fail-on narrows, and never past the two it cannot touch =="

if start_range open; then
    run_experiment control.policy_store_down "${FULL[@]}" --fail-on never
    assert_exit "a defect under --fail-on never" 0

    run_experiment control.policy_store_down "${FULL[@]}" --fail-on inconclusive
    assert_exit "a defect under a gate that does not name it" 0

    run_experiment control.policy_store_down "${FULL[@]}" --fail-on defect
    assert_exit "a defect under a gate that names it" 2
fi

echo "== the record is canonical and its events are linked by hash =="

if start_range open; then
    into="${WORK}/record"

    run_experiment control.policy_store_down "${FULL[@]}" \
        --record "$into" \
        --junit "${WORK}/khaos.xml" \
        --metrics-out "${WORK}/khaos.prom"

    assert_exit "a recorded run" 2

    for file in run.json events.jsonl; do
        if [[ -s "${into}/${file}" ]]; then
            pass "the run wrote ${file}"
        else
            fail "the run wrote no ${file}"
        fi
    done

    claimed="$(python3 -c "
import json
print(json.load(open('${into}/run.json'))['events']['sha256'])
" 2>/dev/null || true)"
    actual="$(sha256sum "${into}/events.jsonl" | cut -d' ' -f1)"

    if [[ -n "$claimed" && "$claimed" == "$actual" ]]; then
        pass "the record's hash matches the events file beside it"
    else
        fail "the record claims ${claimed:-<none>} and the file hashes to ${actual}"
    fi

    # The record has to explain the code khaos returned, because the exit
    # status is the only part of a run most CI ever sees.
    recorded="$(python3 -c "
import json
print(json.load(open('${into}/run.json'))['exit']['code'])
" 2>/dev/null || true)"

    if [[ "$recorded" == 2 ]]; then
        pass "the record carries the exit code khaos returned"
    else
        fail "the record says exit ${recorded:-<none>} and khaos returned 2"
    fi
fi

echo "== the projections are accepted by real parsers =="

# promtool is the format's own linter, and it rejects every malformed shape
# this gate cares about: a missing trailing newline is `unexpected end of
# input stream`, a repeated TYPE line and an unescaped label quote are both
# parse errors. Verified against promtool 3.15.0.
if [[ ! -s "${WORK}/khaos.prom" ]]; then
    fail "no metrics file was written, so this section cannot fail"
elif ! command -v promtool >/dev/null 2>&1; then
    fail "promtool is not installed, so khaos's exposition format is unverified"
else
    if promtool check metrics <"${WORK}/khaos.prom" >/dev/null 2>&1; then
        pass "promtool accepts khaos's exposition format"
    else
        fail "promtool rejects khaos's metrics: $(promtool check metrics <"${WORK}/khaos.prom" 2>&1 | head -2)"
    fi

    # The NEGATIVE control on the linter itself: a checker that always says
    # yes cannot detect a malformed file, and the trailing newline is the
    # rule that fails silently.
    if printf '# TYPE x_m gauge\nx_m 1' |
        promtool check metrics >/dev/null 2>&1; then
        fail "promtool accepted a file with no trailing newline, so its approval above proves nothing"
    else
        pass "promtool rejects a file with no trailing newline"
    fi
fi

if [[ ! -s "${WORK}/khaos.xml" ]]; then
    fail "no JUnit file was written, so this section cannot fail"
else
    if python3 -c "
import sys, xml.etree.ElementTree as ET
root = ET.parse('${WORK}/khaos.xml').getroot()
assert root.tag == 'testsuites', root.tag
suite = root.find('testsuite')
assert suite is not None
case = suite.find('testcase')
assert case is not None
assert case.find('failure') is not None, 'a defect is not a failure'
assert int(root.get('failures')) == 1, root.get('failures')
" 2>/dev/null; then
        pass "the JUnit suite parses and reports the defect as a failure"
    else
        fail "the JUnit suite is malformed or does not report the defect"
    fi

    # The way back to the record, for a consumer that only has the XML.
    if grep -q 'name="run_id"' "${WORK}/khaos.xml"; then
        pass "the JUnit suite carries the run id back to the record"
    else
        fail "the JUnit suite carries no run id"
    fi
fi

echo "== a record khaos could not write is never silent =="

if start_range open; then
    # The verdict outranks the bookkeeping: a run that found a bypass still
    # exits on the bypass, and still says the record is missing.
    run_experiment control.policy_store_down "${FULL[@]}" \
        --record /proc/khaos-cannot-write-here

    assert_exit "a defect whose record could not be written" 2

    if grep -q 'could not write the run record' <<<"$report"; then
        pass "the write failure is reported rather than swallowed"
    else
        fail "a record khaos could not write was silent"
    fi

    # But a clean run that could not write the record the operator asked for
    # fails on the write: in CI they believe they have an artifact and do not.
    run_experiment control.policy_store_down "${FULL[@]}" \
        --fail-on never \
        --record /proc/khaos-cannot-write-here

    assert_exit "a clean run whose record could not be written" 1
fi

echo "== the codes this gate cannot reach, named rather than implied =="

# Four codes are deliberately not driven here, and saying so is the point: a
# gate that looked complete while skipping them would be the inert kind.
#
#   6  ROLLBACK    needs khaos to fail to revert a fault it applied, which
#                  means breaking the daemon mid-run. `scripts/survive.sh`
#                  owns the rollback paths; forcing the failure here would
#                  leave the operator's range dirty, which is the one thing
#                  this tool must not do.
#   8  BASELINE    needs a target outside steady state BEFORE injection. The
#                  range is healthy by construction, and the unit census in
#                  internal/cli covers the mapping.
#   9  UNSUPPORTED driven by scripts/dns.sh and scripts/tls.sh, against the
#                  targets whose question genuinely does not apply.
#   70 INTERNAL    a recovered panic, recovered at the process boundary in
#                  cmd/khaos and driven by a unit test that panics through
#                  it, asserting the code AND that deferred reverts ran.
#
# A CENSUS rather than a comment, so a thirteenth code cannot arrive with
# nothing covering it. [[:space:]] rather than \t, which grep -E reads as a
# literal `t`.
declared="$(grep -cE '^[[:space:]]+Code[A-Za-z]+ += ' internal/cli/exit.go || true)"

if [[ "$declared" == 12 ]]; then
    pass "the taxonomy is twelve codes, which is what this gate and the unit census cover"
else
    fail "the source declares ${declared} exit codes and this gate accounts for 12; a new code needs a home here or a named reason it cannot have one"
fi

# And the unit census that covers what a live range cannot reach has to
# exist, or the four codes named above are covered by nothing at all.
if grep -q 'func TestNoTwoOutcomesShareACode' internal/cli/exit_test.go; then
    pass "the unit census that pins every code is present"
else
    fail "the unit census is gone, so the codes this gate cannot drive are unverified"
fi

# Counting constants proves DECLARATION and never REACHABILITY, so the code
# needs a producer too.
if grep -q 'code = cli.CodeInternal' cmd/khaos/main.go &&
    grep -q 'func TestAPanicBecomesTheInternalCodeWithCleanupIntact' cmd/khaos/main_test.go; then
    pass "the internal code has a producer and a test that panics through it"
else
    fail "exit 70 is declared with no production path, so the taxonomy publishes a code khaos never returns"
fi

# A non-positive interval reaches time.NewTicker, after the workspace lock.
if ! out="$("$BIN" reap --interval 0 --no-color 2>&1)"; then
    if grep -q "longer than zero" <<<"$out"; then
        pass "a non-positive reap interval is refused by name instead of panicking"
    else
        fail "reap --interval 0 failed without naming the cause: ${out}"
    fi
else
    fail "reap --interval 0 was accepted"
fi

if grep -q "panic" <<<"$out"; then
    fail "reap --interval 0 still panics: ${out}"
else
    pass "reap --interval 0 produces no stack trace"
fi

if [[ "$failures" -gt 0 ]]; then
    echo "report: ${failures} assertion(s) failed"
    exit 1
fi

echo "report: all assertions passed"
