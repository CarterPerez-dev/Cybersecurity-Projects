#!/usr/bin/env bash
# ©AngelaMos | 2026
# credential.sh

set -euo pipefail

# M9's exit gate for the database half of the `credential.` family: rotation
# distinguishes rotation from revocation on all three engines.
#
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
#   2. THE NEGATIVE CONTROL EARNS ITS KEEP HERE. Research 07 section 6.1 is a
#      write-up of a probe that reported PostgreSQL accepting a rotated-away
#      password: it connected over loopback inside the server container, where
#      `postgres:18` ships `host all all 127.0.0.1 trust` AHEAD of scram, so no
#      password was ever evaluated. khaos's invalid stream presents a password
#      that was never correct and requires the engine to refuse it, which is the
#      control that was missing. A run that cannot establish it is void.
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

cleanup() {
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

# The baseline guard that research 07 section 6.1 paid for. If the engine ever
# accepted the never-valid password, khaos voids the run by name rather than
# reporting a finding, and this asserts the run was NOT voided that way.
assert_control_held() {
    local label="$1"
    assert_report_lacks \
        "${label} established that the engine checks passwords at all" \
        "the invalid credential was never rejected"
}

observable_of() {
    grep -E '^  plan  confirm   fault confirmed by ' <<<"$report" |
        sed -E 's/^.*fault confirmed by //'
}

admin_password() {
    docker inspect "${CONTAINER[$1]}" \
        --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null |
        grep "^${ADMIN_VAR[$1]}=" | cut -d= -f2-
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

start_range() {
    "$BIN" range down --no-color >/dev/null 2>&1 || true
    if ! "$BIN" range up --with-db --no-color --quiet >/dev/null 2>&1; then
        fail "range up --with-db"
        return 1
    fi
    return 0
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
        "the finding IS what three correct engines do"
else
    fail "range up (without the stateful tier)"
fi

echo "== THE PAIR: rotation is not revocation, and termination is =="

if start_range; then
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

echo "== census: every catalogued credential.db_ experiment was run here =="

catalogued="$(NO_COLOR=1 "$BIN" run --help |
    grep -oE '^  credential\.[a-z_]+' | tr -d ' ' | sort -u)"

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
