#!/usr/bin/env bash
# ©AngelaMos | 2026
# credential.sh

set -euo pipefail

# This is the first family whose authority behaves CORRECTLY. Every other tier
# exists because no correct dependency will emit the defect - no correct
# provider mints `alg: none`, no correct CA signs an expired leaf. Here the
# engines are right and the operator's model is wrong: authentication is
# evaluated once, at connection establishment, and never again. So khaos drives
# three stock engines rather than replacing them, and the gate's job is to prove
# the pair inverts.
#
#   1. THE PAIR. `db_rotate` returns `deviated / PERMITTED` exit 2 on every
#      engine, because the session khaos held keeps answering. The same fault
#      plus one statement, `db_rotate_terminate`, returns `passed / HELD` exit 0
#      on the same engine. One statement is the entire difference between a
#      change of admission policy and a revocation.
#
#   3. EVERY OBSERVABLE IS THE ENGINE'S OWN MESSAGE. The confirmation quotes
#      what the engine said, per engine, and the four faults produce DISTINCT
#      strings. A shared constant describing the technique measures nothing,
#      which `scripts/proxy.sh` learned at the cost of two implementations.
#
#   4. THE VERSION COMES FROM THE SERVER. On this host `postgres:18` resolved to
#      18.3 for one measurement and 18.6 hours later, and `mariadb:11.4` moved a
#      patch release the same way. A run record naming a tag names nothing.
#
#   5. NOTHING IS LEFT BEHIND. khaos mints a role per run and the engine must
#      hold none of them afterwards. The revert RESTORES rather than removes,
#      because dropping the role would make khaos's own cleanup read as a target
#      that never came back - measured, as a degraded recovery on a run where
#      nothing about the engine had degraded.
#
#   6. THE CLASSIFIER IS A DIFFERENTIAL, not a table khaos agrees with itself
#      about. `internal/dbx`'s live tests run against all three engines from
#      here, including the confirmation oracle's inert control, because a
#      self-consistent client agrees with its own mistake.

BIN="${BIN:-$PWD/khaos}"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR

# The HELD half of the pair has to clear MinimumToClaimClosed, which is 30
# paired samples: khaos refuses to call a HELD run conclusive below that and
# exits 4 instead of 0. `tls.sh` and `dns.sh` both failed their first run on
# exactly this, so the window is sized for it rather than discovered again.
TIMING=(--baseline-for 4s --fault-for 20s --recover-for 3s --sample-every 300ms)

ENGINES=(postgres mysql mariadb)

declare -A CONTAINER=(
    [postgres]=khaos-range-postgres
    [mysql]=khaos-range-mysql
    [mariadb]=khaos-range-mariadb
)

declare -A ADMIN_VAR=(
    [postgres]=POSTGRES_PASSWORD
    [mysql]=MYSQL_ROOT_PASSWORD
    [mariadb]=MARIADB_ROOT_PASSWORD
)

declare -A ADMIN_ROLE=(
    [postgres]=postgres
    [mysql]=root
    [mariadb]=root
)

declare -A ENGINE_PORT=(
    [postgres]=5432
    [mysql]=3306
    [mariadb]=3306
)

failures=0
report=""
last_code=0
ran=()
active_pid=""

cleanup() {
    if [[ -n "$active_pid" ]]; then
        kill -9 "$active_pid" 2>/dev/null || true
        wait "$active_pid" 2>/dev/null || true
    fi
    "$BIN" reclaim --no-color >/dev/null 2>&1 || true
    "$BIN" range down --no-color >/dev/null 2>&1 || true
    rm -rf "$KHAOS_STATE_DIR"
}
trap cleanup EXIT INT TERM HUP

pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }

# Never call through a command substitution: that runs it in a subshell and the
# report is lost while the exit code still comes back, which looks like a
# passing gate with no evidence.
run_experiment() {
    local experiment="$1"
    shift
    ran+=("$experiment")
    run_unmeasured "$experiment" "$@"
}

# run_unmeasured is for a run that is NOT a measurement of the experiment: a
# refusal, or a read of something khaos printed before the baseline. It does not
# enter the census, because a refused run that counted would alibi an experiment
# this gate never actually measured.
#
# The first version of this script achieved that by clearing the census array
# after such a run, which wiped the record of every earlier one and reported
# that the gate had run nothing at all.
run_unmeasured() {
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

# exit_for_verdict maps an expected verdict onto khaos's exit contract.
#
# It takes the experiment's DECLARED DEFECT DIRECTIONS as its second argument,
# and that is not decoration: the exit code is a function of (verdict,
# polarity), never of the verdict alone. `passed / HELD` is 0 for most of the
# catalogue and 2 for the pooled family, where poolPolarity declares HELD the
# defect -- a lifetime that converts a rotation into a revocation is the thing
# those experiments hunt. An earlier version of this helper read the verdict
# string by itself and reported four pooled assertions as exit 0 when khaos
# correctly returned 2.
#
# The directions are passed per section rather than looked up, so an inverted
# polarity is visible at the call site instead of buried in a helper.
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

assert_control_held() {
    local label="$1"
    # The subject is a parameter because this one helper now serves two kinds of
    # target. For ten experiments it is an engine checking a password; for the
    # service-to-service one it is a caller authenticating a credential, and
    # that distinction is the whole reason the fixture is measurable at all.
    local subject="${2:-the engine checks passwords}"
    assert_report_lacks \
        "${label} established that ${subject} at all" \
        "the invalid credential was never rejected"
}

# EVERY helper below that greps ends in `|| true`, and that is not defensive
# noise: with `set -e`, a grep inside a command substitution that legitimately
# matches nothing kills the script, and `grep -c` does it even when printing a
# perfectly good `0`. The symptom is a gate that exits 1 with no FAIL line at
# all, which reads like a mystery rather than like a bug. It has fired three
# times in this one file: on an unmatched confirmation line, on a count of
# leftovers that was correctly zero, and on an absent environment variable.
observable_of() {
    grep -E '^  plan  confirm   fault confirmed by ' <<<"$report" |
        sed -E 's/^.*fault confirmed by //' || true
}

admin_password() {
    docker inspect "${CONTAINER[$1]}" \
        --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null |
        grep "^${ADMIN_VAR[$1]}=" | cut -d= -f2- || true
}

engine_address() {
    docker inspect "${CONTAINER[$1]}" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        2>/dev/null
}

# leftover_roles counts roles khaos minted and did not remove. Read over
# loopback INSIDE the container on purpose: that is the `trust` path research
# 07 section 6.1 warns about, which makes it useless as a probe and exactly
# right as the gate's own administrative read.
leftover_roles() {
    local engine="$1"
    case "$engine" in
    postgres)
        docker exec "${CONTAINER[$engine]}" psql -U postgres -tAc \
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'khaos_cred_%'" \
            2>/dev/null | tail -1 | tr -d '[:space:]'
        ;;
    *)
        docker exec "${CONTAINER[$engine]}" sh -c \
            "exec \"\$(command -v mariadb || command -v mysql)\" -uroot -p\"\$${ADMIN_VAR[$engine]}\" -N -B -e \"SELECT count(*) FROM mysql.user WHERE user LIKE 'khaos\\_cred\\_%'\"" \
            2>/dev/null | tail -1 | tr -d '[:space:]'
        ;;
    esac
}

kill_credential_at() {
    local engine="$1" stage="$2" log attempt reached=0 had_role=0 baseline=4s
    if [[ "$stage" == baseline ]]; then
        baseline=60s
    fi
    log="${KHAOS_STATE_DIR}/kill-${engine}-${stage}.log"
    "$BIN" run credential.db_rotate --target "${CONTAINER[$engine]}" \
        --engine "$engine" --baseline-for "$baseline" --fault-for 2s \
        --recover-for 60s --sample-every 300ms --no-color \
        >"$log" 2>&1 &
    active_pid=$!
    for ((attempt = 0; attempt < 60; attempt++)); do
        if grep -qE "plan[[:space:]]+${stage}[[:space:]]" "$log"; then
            reached=1
            break
        fi
        kill -0 "$active_pid" 2>/dev/null || break
        sleep 1
    done
    if [[ "$reached" != 1 ]]; then
        fail "${engine} did not reach ${stage} before interruption"
        cat "$log"
    elif [[ "$(leftover_roles "$engine")" != 1 ]]; then
        fail "${engine} ${stage} did not hold exactly one temporary role"
    else
        had_role=1
    fi
    kill -9 "$active_pid" 2>/dev/null || true
    wait "$active_pid" 2>/dev/null || true
    active_pid=""
    if "$BIN" reclaim --no-color >>"$log" 2>&1 && \
        [[ "$(leftover_roles "$engine")" == 0 && "$had_role" == 1 ]]; then
        pass "${engine} kill during ${stage} left a role that cold reclaim removed"
    else
        fail "${engine} cold cleanup after ${stage} left a role or failed"
        cat "$log"
    fi
}

# The pool configuration is fixed at container creation, deliberately, so a
# gate spanning all three has to restart the range. A fixture that could be
# reconfigured mid-run would let khaos change the target it is measuring.
held_containers() {
    docker ps -a --format '{{.Names}}' |
        grep -c -- '-khaos-held' | tr -d '[:space:]' || true
}

env_of() {
    docker inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' \
        2>/dev/null | grep -E "^$2=" | tail -1 || true
}

start_range() {
    local pool="${1:-unbounded}"
    local secret="${2:-unchecked}"

    "$BIN" range down --no-color >/dev/null 2>&1 || true
    # The OUTPUT, not just the fact. A bare "range up failed" is what a
    # transient startup error looks like in a two-hour gate run, and it
    # leaves nothing to diagnose from.
    local started
    if ! started="$("$BIN" range up --with-db --pool-mode "$pool" \
        --secret-mode "$secret" --no-color --quiet 2>&1)"; then
        fail "range up --with-db --pool-mode $pool --secret-mode $secret: $(tail -3 <<<"$started")"
        printf '%s\n' "$started" >&2
        return 1
    fi
    return 0
}

secret_leftovers() {
    docker ps -a --filter "label=khaos.mutator=true" --format '{{.Names}}' |
        wc -l | tr -d '[:space:]'
}

held_originals() {
    docker exec khaos-range-gateway-secret \
        sh -c 'ls /run/khaos-secrets/ 2>/dev/null' 2>/dev/null |
        grep -c 'khaos-held' | tr -d '[:space:]' || true
}

echo "== the stateful tier is refused by name when it is not running =="

# The refusal has to arrive with a range UP and the database tier DOWN, which is
# the state an operator reaches by running `khaos range up` and then asking for
# a credential experiment. With no range at all the run dies in fillFromRange
# with a different message, and a gate that accepted either would pass against
# the wrong one.
"$BIN" range down --no-color >/dev/null 2>&1 || true
if "$BIN" range up --no-color --quiet >/dev/null 2>&1; then
    run_unmeasured credential.db_rotate

    assert_exit "a credential experiment with no stateful tier" 1
    assert_report_has \
        "the refusal names the missing tier" \
        "the running range has none"
    assert_report_has \
        "the refusal names the command that fixes it" \
        "khaos range up --with-db"
    assert_report_has \
        "the refusal says why khaos does not fake it" \
        "the finding IS what correct ones do"
else
    fail "range up (without the stateful tier)"
fi

echo "== THE PAIR: rotation is not revocation, and termination is =="

if start_range unbounded; then
    for engine in "${ENGINES[@]}"; do
        container="${CONTAINER[$engine]}"

        run_experiment credential.db_rotate \
            --target "$container" --engine "$engine"

        assert_verdict "${engine} db_rotate" "deviated / PERMITTED"
        assert_exit "${engine} db_rotate" 2
        assert_confirmed "${engine} db_rotate"
        assert_control_held "${engine} db_rotate"
        assert_report_has \
            "${engine} db_rotate names what khaos did to the credential" \
            "by rotating its password at the engine and terminating nothing"
        assert_report_has \
            "${engine} db_rotate reports the exposure as a lower bound" \
            "which is the lower bound on the exposure"

        rotate_observable="$(observable_of)"

        run_experiment credential.db_rotate_terminate \
            --target "$container" --engine "$engine"

        assert_verdict "${engine} db_rotate_terminate" "passed / HELD"
        assert_exit "${engine} db_rotate_terminate" 0
        assert_confirmed "${engine} db_rotate_terminate"
        assert_control_held "${engine} db_rotate_terminate"
        assert_report_has \
            "${engine} db_rotate_terminate says what HELD means here" \
            "closed by the engine, which is what makes termination"

        # The inversion, read off the FINDING rather than off the verdict
        # label: the rotation half reports the invalidated credential being
        # honoured, and the half that also terminated must report no such
        # thing. Two assertions on two reports, which is what makes the pair
        # the exit gate rather than two unrelated runs.
        assert_report_lacks \
            "${engine} nothing was honoured once the sessions were terminated" \
            "was still accepted"

        if [[ -n "$rotate_observable" ]]; then
            pass "${engine} the rotation produced an observable to compare"
        else
            fail "${engine} the rotation produced no observable to compare"
        fi
    done
fi


echo "== the pooled fixture: the fail-open is the DEFAULT configuration =="

# Three pool configurations, and the verdict has to follow the configuration
# rather than the fault. The fault is identical in all three runs.
#
#   unbounded  the shape a Go service has when nobody called
#              SetConnMaxLifetime. HELD is the defect: the service carried on.
#   bounded    the knob that converts a rotation into a revocation. DENIED is
#              correct, and it arrives as UNAVAILABILITY rather than a refusal,
#              which is why the experiment declares what failing closed means.
#   held       the same lifetime as bounded, plus one connection checked out
#              and never returned. The cleaner only walks the IDLE list, so the
declare -A WANT_VERDICT=(
    [unbounded]="passed / HELD"
    [bounded]="deviated / DENIED"
    [held]="passed / HELD"
)

# What khaos DID is carried by the HELD CAVEAT for these two, not by the defect
# phrase: that phrase is part of a leak reason and a leak is exactly what a
# HELD finding does not have. Asserting the defect phrase here failed six times
# against a product that was reporting correctly.
declare -A WANT_CAVEAT=(
    [credential.db_pool_stale]="khaos rotated the credential and the service carried on"
    [credential.db_pending_window]="the liveness endpoint answered throughout on a connection that authenticated before the rotation"
)

for pool in unbounded bounded held; do
    if ! start_range "$pool"; then
        continue
    fi

    for experiment in credential.db_pool_stale credential.db_pending_window; do
        run_experiment "$experiment"

        label="${experiment#credential.} on a ${pool} pool"

        assert_verdict "$label" "${WANT_VERDICT[$pool]}"
        assert_exit "$label" \
            "$(exit_for_verdict "${WANT_VERDICT[$pool]}" "HELD PERMITTED")"
        assert_confirmed "$label"
        assert_control_held "$label"

        # A HELD verdict has to say what khaos did and what HELD means here.
        # A DENIED one carries no caveat at all, deliberately: the caveat is
        # the explanation of a survival.
        if [[ "${WANT_VERDICT[$pool]}" == "passed / HELD" ]]; then
            assert_report_has \
                "${label} says what khaos did and what surviving it means" \
                "${WANT_CAVEAT[$experiment]}"
        else
            assert_report_lacks \
                "${label} does not explain a survival that did not happen" \
                "${WANT_CAVEAT[$experiment]}"
        fi

        # The sharpest row, asserted per experiment rather than after the loop,
        # where $report held the LAST experiment's output: a lifetime IS set in
        # held mode and the service still carried on.
        if [[ "$pool" == "held" &&
            "$experiment" == "credential.db_pool_stale" ]]; then
            assert_report_has \
                "a checked-out connection is not bounded by the lifetime" \
                "a connection that is checked out rather than idle is not bounded by it at all"
        fi

        # The correct configuration has to lose access rather than merely slow
        # down, or DENIED would be an artefact of the probe timing out.
        if [[ "$pool" == "bounded" ]]; then
            assert_report_has \
                "${label} stopped being able to serve" \
                "the valid credential stopped being accepted"
        fi
    done
done

echo "== the secret file: one fault of four is a finding, and the other three say why =="

declare -A WANT_SECRET_UNCHECKED=(
    [credential.secret_file_empty]="deviated / PERMITTED"
    [credential.secret_file_truncated]="deviated / DENIED"
    [credential.secret_file_missing]="deviated / DENIED"
    [credential.secret_file_unreadable]="deviated / DENIED"
)

if start_range unbounded unchecked; then
    declare -A SECRET_OBSERVABLE=()

    for experiment in "${!WANT_SECRET_UNCHECKED[@]}"; do
        run_experiment "$experiment"

        label="${experiment#credential.} against a verifier that does not check the length"

        assert_verdict "$label" "${WANT_SECRET_UNCHECKED[$experiment]}"
        assert_exit "$label" "$(exit_for_verdict "${WANT_SECRET_UNCHECKED[$experiment]}")"
        assert_confirmed "$label"
        assert_control_held "$label"

        SECRET_OBSERVABLE[$experiment]="$(observable_of)"
    done

    # The confirmation is read off the TARGET's own filesystem, so each fault
    # has to name what the target now has rather than what khaos asked for.
    assert_report_has \
        "the empty-secret confirmation names the target's own copy" \
        "is now zero bytes, and os.ReadFile returns no error on one"

    distinct=$(printf '%s\n' "${SECRET_OBSERVABLE[@]}" | sort -u | wc -l)
    if [[ "$distinct" == "${#SECRET_OBSERVABLE[@]}" ]]; then
        pass "all four secret faults produce DISTINCT observables"
    else
        fail "the four secret faults produced ${distinct} distinct observables, so some of them are not evidence"
    fi

    # khaos's helper is short-lived by construction, and an orphan would be a
    # container holding two file-permission capabilities over the operator's
    # own volume.
    left="$(secret_leftovers)"
    if [[ "$left" == "0" ]]; then
        pass "no mutator container is left behind"
    else
        fail "${left} mutator container(s) left behind"
    fi

    # The original is kept BESIDE the secret, inside the target's own mount, so
    # khaos never carries it out - and the revert has to remove it again.
    held="$(held_originals)"
    if [[ "$held" == "0" ]]; then
        pass "the original khaos kept beside the secret is gone after the revert"
    else
        fail "khaos left ${held} copy of the original inside the target's mount"
    fi
fi

echo "== the length check is the fix, and khaos says so =="

if start_range unbounded validated; then
    run_experiment credential.secret_file_empty

    assert_verdict \
        "secret_file_empty against a verifier that checks the length" \
        "deviated / DENIED"
    assert_exit \
        "secret_file_empty against a verifier that checks the length" 3
    assert_confirmed \
        "secret_file_empty against a verifier that checks the length"
    assert_report_lacks \
        "no credential was honoured once the length was checked" \
        "was accepted"
fi

echo "== a secret khaos cannot reach reversibly is refused by name =="

if start_range unbounded unchecked; then
    # A path on no mount at all. A helper cannot reach it, and a cold-started
    # revert could not put it back, so khaos declines rather than breaking
    # something it could not undo.
    run_unmeasured credential.secret_file_empty \
        --target khaos-range-gateway-secret \
        --url "http://127.0.0.1:1/protected" \
        --token nothing \
        --secret-path /etc/hostname

    if [[ "$last_code" != 0 ]]; then
        pass "a secret on no mount at all is refused"
    else
        fail "khaos broke a file it could not have restored"
    fi

    assert_report_has \
        "the refusal names the reason and the fix" \
        "Deliver the secret on a volume or a bind-mounted directory"

    # A tmpfs is private to the container's own namespace, so a helper mounting
    # the same spec gets an EMPTY filesystem: khaos would write a secret into
    # nowhere and report a fault that landed.
    run_unmeasured credential.secret_file_empty \
        --target khaos-range-postgres \
        --url "http://127.0.0.1:1/protected" \
        --token nothing \
        --secret-path /var/lib/postgresql/khaos-probe

    if [[ "$last_code" != 0 ]]; then
        pass "a secret on a tmpfs mount is refused"
    else
        fail "khaos accepted a secret on a tmpfs, which a helper cannot reach"
    fi

    assert_report_has \
        "the tmpfs refusal names why a helper cannot reach it" \
        "private to the container"
fi

echo "== the environment: the one fault class that REPLACES the container =="

# A container's environment is fixed at creation. `ContainerUpdate` accepts an
# Env field, returns HTTP 200 with no warning, and changes nothing - measured -
# so these two replace the container, and the mechanism was chosen to keep the
# ORIGINAL rather than to rebuild it: a recreate from an inspection loses the
# anonymous volume with its data stranded, every prior log line, and the
# container id invariant 8 re-verifies against. khaos renames the original
# aside and renames it back on the way out.
#
# The two faults are INDISTINGUISHABLE to a service that reads with os.Getenv,
# which is the whole teaching point, so both are expected to read the same
# against each fixture mode.
declare -A WANT_ENV=(
    [unchecked]="deviated / PERMITTED"
    [validated]="deviated / DENIED"
)

for secret in unchecked validated; do
    if ! start_range unbounded "$secret"; then
        continue
    fi

    for experiment in credential.env_empty credential.env_unset; do
        run_experiment "$experiment"

        label="${experiment#credential.} against a ${secret} verifier"

        assert_verdict "$label" "${WANT_ENV[$secret]}"
        assert_exit "$label" "$(exit_for_verdict "${WANT_ENV[$secret]}")"
        assert_confirmed "$label"
        assert_control_held "$label"
    done

    # The original has to be back, running, under its own name - and nothing
    # held aside. A revert that renamed it back and forgot to start it left the
    # next run reporting the range as missing the fixture entirely.
    if docker ps --filter name=khaos-range-gateway-env --filter status=running \
        --format '{{.Names}}' | grep -q 'khaos-range-gateway-env$'; then
        pass "the original container is back and running after the revert"
    else
        fail "the original container did not come back running"
    fi

    held="$(held_containers)"
    if [[ "$held" == "0" ]]; then
        pass "no container is left renamed aside"
    else
        fail "${held} container(s) left renamed aside"
    fi

    # The variable is back with its ORIGINAL value, not an empty one: the
    # revert restores the container rather than patching the environment.
    restored="$(env_of khaos-range-gateway-env KHAOS_RANGE_SECRET_VALUE)"
    if [[ -n "$restored" && "$restored" != "KHAOS_RANGE_SECRET_VALUE=" ]]; then
        pass "the variable is back with its original value"
    else
        fail "the variable came back as ${restored:-<absent>}"
    fi
done

echo "== an environment fault khaos cannot deliver is refused by name =="

if start_range unbounded unchecked; then
    port="$(docker port khaos-range-gateway-env 8080 2>/dev/null |
        head -1 | cut -d: -f2)"
    token="$(curl -s --max-time 5 -X POST \
        "http://127.0.0.1:${port}/secret-token" 2>/dev/null |
        sed -E 's/.*"token":"([^"]+)".*/\1/')"

    # A variable the IMAGE defines as well. The daemon merges the image's
    # environment into any key a create request omits, so a replacement made
    # without it gets the image's value back and khaos would report a fault the
    # daemon had undone for it.
    run_unmeasured credential.env_unset \
        --target khaos-range-gateway-env \
        --url "http://127.0.0.1:${port}/protected" \
        --token "$token" \
        --variable PATH

    if [[ "$last_code" != 0 ]]; then
        pass "a variable the image defines is refused"
    else
        fail "khaos reported an unset the daemon would have undone"
    fi

    assert_report_has \
        "the refusal names the mechanism and the fault to use instead" \
        "gets the image's value back"

    # A variable that is not there at all. Nothing to take away, and the
    # refusal names what IS there so the operator can see the typo.
    run_unmeasured credential.env_unset \
        --target khaos-range-gateway-env \
        --url "http://127.0.0.1:${port}/protected" \
        --token "$token" \
        --variable KHAOS_NOT_A_VARIABLE

    if [[ "$last_code" != 0 ]]; then
        pass "a variable the target does not carry is refused"
    else
        fail "khaos took away a variable that was never there"
    fi

    assert_report_has \
        "the refusal names the variables the target DOES carry" \
        "It carries:"
fi

echo "== the pooled faults put BOTH containers to the refusal predicates =="

# khaos measures one container and performs the rotation at another, so the
# engine's consent is not implied by the target's. A rotation at a container
# that never consented would be khaos mutating something nobody approved.
if start_range unbounded; then
    run_unmeasured credential.db_pool_stale \
        --target khaos-range-gateway-db \
        --engine-target khaos-range-idp \
        --engine postgres \
        --subject-role appuser \
        --subject-password-var KHAOS_RANGE_DB_PASSWORD \
        --ready-url "http://127.0.0.1:1/ready" \
        --url "http://127.0.0.1:1/protected" \
        --token nothing

    if [[ "$last_code" != 0 ]]; then
        pass "an engine container with no administrative credential is refused"
    else
        fail "khaos accepted an engine container it could not read a credential from"
    fi
fi

echo "== the two other controls an operator reaches for do not revoke either =="

for engine in "${ENGINES[@]}"; do
    container="${CONTAINER[$engine]}"

    run_experiment credential.db_account_lock \
        --target "$container" --engine "$engine"

    assert_verdict "${engine} db_account_lock" "deviated / PERMITTED"
    assert_exit "${engine} db_account_lock" 2
    assert_confirmed "${engine} db_account_lock"
    assert_control_held "${engine} db_account_lock"
    assert_report_has \
        "${engine} db_account_lock confirmation quotes the engine on the lock" \
        "because the account is locked"

    lock_observable="$(observable_of)"

    run_experiment credential.db_credential_expiry \
        --target "$container" --engine "$engine"

    assert_verdict "${engine} db_credential_expiry" "deviated / PERMITTED"
    assert_exit "${engine} db_credential_expiry" 2
    assert_confirmed "${engine} db_credential_expiry"
    assert_control_held "${engine} db_credential_expiry"
    assert_report_has \
        "${engine} db_credential_expiry confirmation names the validity" \
        "because the credential's validity has passed"

    expiry_observable="$(observable_of)"

    # Distinct observables, per engine. The lock and the expiry both refuse a
    # correct password at a new connection, so a confirmation that described the
    # technique rather than reading the engine back would be identical for both.
    if [[ "$lock_observable" != "$expiry_observable" ]]; then
        pass "${engine} the lock and the expiry produce DISTINCT observables"
    else
        fail "${engine} the lock and the expiry produced the same observable, so neither is evidence"
    fi
done

echo "== the engine version comes from the server, not from the image tag =="

for engine in "${ENGINES[@]}"; do
    run_unmeasured credential.db_rotate \
        --target "${CONTAINER[$engine]}" --engine "$engine"

    if grep -qE '^  plan  credential tier open on .*which reports "' <<<"$report"; then
        reported="$(grep -oE 'which reports "[^"]+"' <<<"$report")"

        case "$engine" in
        postgres) expect='PostgreSQL 18\.[0-9]+' ;;
        mysql) expect='8\.4\.[0-9]+' ;;
        mariadb) expect='11\.4\.[0-9]+-MariaDB' ;;
        esac

        if grep -qE "$expect" <<<"$reported"; then
            pass "${engine} reports a patch level its image tag does not carry (${reported})"
        else
            fail "${engine} reported ${reported}, which does not carry a patch level and so could be the tag echoed back"
        fi
    else
        fail "${engine} never reported the version the server gave it"
    fi
done

echo "== khaos leaves no role of its own behind =="

for engine in "${ENGINES[@]}"; do
    left="$(leftover_roles "$engine")"

    if [[ "$left" == "0" ]]; then
        pass "${engine} holds no khaos-minted role after the runs"
    else
        fail "${engine} still holds ${left:-<unreadable>} khaos-minted role(s)"
    fi
done

echo "== the classifier is a differential against all three engines =="

for engine in "${ENGINES[@]}"; do
    kill_credential_at "$engine" baseline
    kill_credential_at "$engine" recover
done

# Including the confirmation oracle's inert control, which is the one assertion
# an oracle gutted to `return true` cannot satisfy.
differential_env=()
for engine in "${ENGINES[@]}"; do
    address="$(engine_address "$engine")"
    password="$(admin_password "$engine")"
    database=""
    if [[ "$engine" == "postgres" ]]; then
        database="postgres"
    fi

    if [[ -z "$address" || -z "$password" ]]; then
        fail "could not read ${engine}'s address or administrative credential from its own container"
        continue
    fi

    name="KHAOS_DBX_LIVE_$(echo "$engine" | tr '[:lower:]' '[:upper:]')"
    differential_env+=(
        "${name}=${address}:${ENGINE_PORT[$engine]},${database},${ADMIN_ROLE[$engine]},${password}"
    )
done

if [[ "${#differential_env[@]}" == "${#ENGINES[@]}" ]]; then
    set +e
    differential="$(env "${differential_env[@]}" \
        go test ./internal/dbx/ -count=1 2>&1)"
    differential_code=$?
    set -e

    if [[ "$differential_code" == 0 ]]; then
        pass "internal/dbx agrees with all three live engines"
    else
        fail "internal/dbx disagrees with a live engine: $(tail -5 <<<"$differential")"
    fi

    # A differential that SKIPPED every engine would also exit 0, which is the
    # inert-control shape this project has shipped before.
    skipped="$(env "${differential_env[@]}" \
        go test ./internal/dbx/ -count=1 -v -run TestRotationIsNotRevocation 2>&1 |
        grep -c 'SKIP' || true)"

    if [[ "$skipped" == "0" ]]; then
        pass "the differential ran against every engine rather than skipping them"
    else
        fail "the differential SKIPPED ${skipped} engine(s), so it proved nothing"
    fi
fi

echo "== service to service: a DENY and a SILENCE are different answers =="

start_authz_range() {
    local mode="$1"

    "$BIN" range down --no-color >/dev/null 2>&1 || true
    local started
    if ! started="$("$BIN" range up --authz-mode "$mode" --no-color --quiet 2>&1)"; then
        fail "range up --authz-mode $mode: $(tail -3 <<<"$started")"
        printf '%s\n' "$started" >&2
        return 1
    fi
    return 0
}

declare -A WANT_AUTHZ=(
    [collapses]="deviated / PERMITTED"
    [distinguishes]="passed / HELD"
    [retries]="passed / HELD"
    [cached]="passed / HELD"
)

for mode in collapses distinguishes retries cached; do
    if ! start_authz_range "$mode"; then
        continue
    fi

    run_experiment credential.apikey_revoked

    label="apikey_revoked against a ${mode} caller"

    assert_verdict "$label" "${WANT_AUTHZ[$mode]}"
    assert_exit "$label" \
        "$(exit_for_verdict "${WANT_AUTHZ[$mode]}" "PERMITTED DENIED")"
    assert_confirmed "$label"
    assert_control_held "$label" "the caller authenticates credentials"

    # The confirmation is TWO-SIDED, and both halves are quoted: the credential
    # under test is refused AND a control credential khaos never named is still
    # allowed. Without the second half a dependency that had started refusing
    # everything would confirm every deny khaos armed, and this experiment
    # reports a refusal of the valid credential as a defect of the target.
    assert_report_has \
        "${label}: the confirmation reads both sides of the deny" \
        "403 for the credential under test and 200 for a control credential"

    # The SECOND WINDOW has to have run. Without this the gate would pass on
    # phase one alone: the collapsing caller's acceptance of a denied
    # credential is a finding by itself, so deleting the shift entirely would
    # leave the verdict and the exit code unchanged.
    assert_report_has \
        "${label}: khaos measured a second window" \
        "plan  shift"
    assert_report_has \
        "${label}: the second window is named in the evidence" \
        "answered 503 to everything"
done

echo "== the two phases are read as four callers, not two =="

# The discriminator, stated as the gate's own comparison. The verdicts above
# already differ; what these assert is that khaos SAYS which caller it saw,
# because "deviated" with no mechanism is a finding an operator cannot act on.
if start_authz_range collapses; then
    run_experiment credential.apikey_revoked

    assert_report_has \
        "the collapse is named as serving in both phases" \
        "permitted access during both"
    assert_report_has \
        "both dependency outcomes are named" \
        "definitive denial and an unavailable dependency"
    assert_report_lacks \
        "a collapsing caller is not credited with the third branch" \
        "That is the third branch"
fi

if start_authz_range distinguishes; then
    run_experiment credential.apikey_revoked

    assert_report_has \
        "the correct caller is credited with the third branch, observed" \
        "That is the third branch, and khaos observed it rather than inferring it"
    assert_report_lacks \
        "and is not reported as having collapsed anything" \
        "permitted access during both"

    # The negative control for the retry-storm instrument. A caller that asks
    # once per request must NOT be reported as retrying, or the instrument says
    # yes to everything and the row below proves nothing.
    assert_report_lacks \
        "a caller that asked once per request is not called a retry storm" \
        "asked again about a credential it had already been told no about"
fi

if start_authz_range retries; then
    run_experiment credential.apikey_revoked

    # Measured from OUTSIDE the target, by counting what khaos's own dependency
    # answered: only the credential under test is ever answered with a
    # definitive refusal, so that count is the number of times the caller asked
    # about a credential it had already been told no about.
    assert_report_has \
        "the retry storm is counted against the requests that caused it" \
        "asked again about a credential it had already been told no about"

    # And it still fails CLOSED, which is why this is a third mode rather than
    # a variant of the collapse: the right verdict reached the wrong way.
    assert_report_has \
        "a retrying caller is still credited with both branches" \
        "That is the third branch"
fi

echo "== the regression control: a correct caller that refuses with 503 =="

if start_authz_range cached; then
    run_experiment credential.apikey_revoked

    assert_verdict "a caller that refuses with 503" "passed / HELD"
    assert_exit "a caller that refuses with 503" 0
    assert_confirmed "a caller that refuses with 503"

    assert_report_lacks \
        "a correct caller is not told its fallback is to allow" \
        "this target's fallback is to allow"
    assert_report_lacks \
        "and is not reported as having served in both phases" \
        "permitted access during both"
    assert_report_lacks \
        "and no bypass is claimed against it" \
        "was still accepted"
    assert_report_has \
        "it is credited with the third branch like any correct caller" \
        "That is the third branch"
fi

echo "== the authorization fixture is refused by name when it is not running =="

# The refusal has to arrive with a range UP and this one fixture stopped, which
# is the state an operator reaches when a container has died. A missing fixture
# otherwise surfaces as a published port of zero, and the run blames the target
# for not enforcing anything.
if start_authz_range distinguishes; then
    docker stop khaos-range-gateway-authz >/dev/null 2>&1 || true

    run_unmeasured credential.apikey_revoked

    assert_exit "an authorization experiment with no caller fixture" 1
    assert_report_has \
        "the refusal names the missing fixture" \
        "the running range has no khaos-range-gateway-authz"

    docker start khaos-range-gateway-authz >/dev/null 2>&1 || true
fi

echo "== census: every catalogued credential. experiment was run here =="

catalogued="$(NO_COLOR=1 "$BIN" run --help |
    grep -oE '^  credential\.[a-z_]+' | tr -d ' ' | sort -u || true)"

if [[ -z "$catalogued" ]]; then
    fail "the census read no credential experiments at all, so it cannot fail for the right reason"
fi

missing=""
for name in $catalogued; do
    found=0
    for was in "${ran[@]}"; do
        if [[ "$was" == "$name" ]]; then
            found=1
            break
        fi
    done
    if [[ "$found" == 0 ]]; then
        missing="${missing} ${name}"
    fi
done

if [[ -z "$missing" ]]; then
    pass "every catalogued credential. fault was actually run by this gate"
else
    fail "this gate never ran:${missing}"
fi

echo
if [[ "$failures" == 0 ]]; then
    echo "credential gate: all assertions passed"
    exit 0
fi

echo "credential gate: ${failures} assertion(s) failed"
exit 1
