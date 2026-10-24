#!/usr/bin/env bash
# ©AngelaMos | 2026
# survive.sh

set -euo pipefail

BIN="${BIN:-$PWD/khaos}"
IMAGE="${SMOKE_IMAGE:-alpine:3.22}"

RUN_ID="$$"
OWNER_LABEL="khaos.survive=${RUN_ID}"
TARGET="ks-surv-${RUN_ID}"
DECOY="ks-decoy-${RUN_ID}"
NET="ksnet-${RUN_ID}"
ALIAS="api-under-test"

KHAOS_STATE_DIR="$(mktemp -d)"
export KHAOS_STATE_DIR
JOURNAL="${KHAOS_STATE_DIR}/journal.jsonl"

failures=0
children=()

cleanup() {
    local pid owned
    for pid in "${children[@]:-}"; do
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done
    owned="$(docker ps -aq --filter "label=${OWNER_LABEL}" 2>/dev/null || true)"
    if [[ -n "$owned" ]]; then
        docker unpause $owned >/dev/null 2>&1 || true
        docker rm -f $owned >/dev/null 2>&1 || true
    fi
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$KHAOS_STATE_DIR"
}
trap cleanup EXIT INT TERM HUP

pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }

paused() { [[ "$(docker inspect -f '{{.State.Paused}}' "$1" 2>/dev/null)" == "true" ]]; }

networks_of() {
    docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}
{{end}}' "$1" 2>/dev/null
}

attached() { networks_of "$1" | grep -qx "$NET"; }

aliases_of() {
    docker inspect -f "{{range \$n, \$cfg := .NetworkSettings.Networks}}{{if eq \$n \"$NET\"}}{{\$cfg.Aliases}}{{end}}{{end}}" "$1" 2>/dev/null
}

await() {
    local predicate="$1" limit="${2:-15}" waited=0
    while (( waited < limit * 10 )); do
        eval "$predicate" && return 0
        sleep 0.1
        waited=$((waited + 1))
    done
    return 1
}

inject_bg() {
    "$BIN" inject "$1" "$TARGET" --ttl "$2" --no-color >/dev/null 2>&1 &
    local pid=$!
    children+=("$pid")
    echo "$pid"
}

assert_no_outstanding() {
    local out
    out="$("$BIN" reclaim --no-color 2>&1 || true)"
    if grep -q "nothing outstanding" <<<"$out"; then
        pass "$1"
    else
        fail "$1 (reclaim still found work: ${out//$'\n'/ })"
    fi
}

assert_decoy_untouched() {
    if paused "$DECOY" || ! attached "$DECOY"; then
        fail "$1 khaos touched a container it was never pointed at"
        return
    fi
    pass "$1"
}

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" >/dev/null
docker network create "$NET" >/dev/null

docker run -d --name "$TARGET" --label "$OWNER_LABEL" --label khaos.target=true \
    --network "$NET" --network-alias "$ALIAS" "$IMAGE" sleep 900 >/dev/null
docker run -d --name "$DECOY" --label "$OWNER_LABEL" --label khaos.target=true \
    --network "$NET" "$IMAGE" sleep 900 >/dev/null

pid="$(inject_bg container-pause 60s)"
if await "paused $TARGET"; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    if await "! paused $TARGET"; then
        pass "L1 in-process revert on signal"
    else
        fail "L1 the fault survived a graceful stop"
    fi
else
    fail "L1 the fault was never applied"
fi
assert_no_outstanding "L1 the journal records the revert"
assert_decoy_untouched "L1 decoy"

pid="$(inject_bg container-pause 60s)"
if await "paused $TARGET"; then
    refusal="$("$BIN" inject container-pause "$TARGET" --no-color 2>&1 || true)"
    if grep -qi "already running" <<<"$refusal"; then
        pass "lock second instance refused by the lock"
    else
        fail "lock a second instance was not stopped by the lock, it said: ${refusal}"
    fi
else
    fail "lock the fault was never applied"
fi
kill -9 "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

if paused "$TARGET"; then
    pass "L2 the fault outlived kill -9, as designed"
else
    fail "L2 the fault vanished on its own, so nothing was really applied"
fi

if "$BIN" reclaim --no-color >/dev/null 2>&1 && await "! paused $TARGET"; then
    pass "L2 journal replay reverted a fault khaos never got to revert"
else
    fail "L2 reclaim did not revert the orphaned fault"
fi
assert_no_outstanding "L2 the journal is clean after reclaim"

pid="$(inject_bg container-pause 3s)"
if await "paused $TARGET"; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    "$BIN" reap --interval 1s --no-color >/dev/null 2>&1 &
    reaper=$!
    children+=("$reaper")

    if await "! paused $TARGET" 20; then
        pass "L3 the lease expired and the reaper reverted it unattended"
    else
        fail "L3 the fault outlived its lease"
    fi

    kill -TERM "$reaper" 2>/dev/null || true
    wait "$reaper" 2>/dev/null || true
else
    fail "L3 the fault was never applied"
fi

pid="$(inject_bg container-pause 120s)"
if await "paused $TARGET"; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    "$BIN" reclaim --expired-only --no-color >/dev/null 2>&1 || true
    sleep 1

    if paused "$TARGET"; then
        pass "lease an unexpired fault was left alone by --expired-only"
    else
        fail "lease --expired-only reverted a fault whose lease was still live"
    fi

    "$BIN" reclaim --no-color >/dev/null 2>&1 || true
    await "! paused $TARGET" || fail "final reclaim did not restore the target"
fi

before_aliases="$(aliases_of "$TARGET")"
if "$BIN" inject network-disconnect "$TARGET" --hold 2s --no-color >/dev/null 2>&1; then
    if attached "$TARGET"; then
        pass "disconnect the target was reattached"
    else
        fail "disconnect the target was left detached"
    fi

    after_aliases="$(aliases_of "$TARGET")"
    if [[ "$after_aliases" == "$before_aliases" ]] && grep -q "$ALIAS" <<<"$after_aliases"; then
        pass "disconnect the network alias survived the revert"
    else
        fail "disconnect aliases went from ${before_aliases} to ${after_aliases}; peers addressing it by name are now broken"
    fi
else
    fail "disconnect the clean inject/revert cycle errored"
fi
assert_no_outstanding "disconnect the journal is clean"
assert_decoy_untouched "disconnect decoy"

pid="$(inject_bg network-disconnect 120s)"
if await "! attached $TARGET"; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    if "$BIN" reclaim --no-color >/dev/null 2>&1 && attached "$TARGET"; then
        recovered="$(aliases_of "$TARGET")"
        if grep -q "$ALIAS" <<<"$recovered"; then
            pass "disconnect kill -9 then reclaim restored the alias too"
        else
            fail "disconnect reclaim reattached but lost the alias: ${recovered}"
        fi
    else
        fail "disconnect reclaim did not reattach the target after kill -9"
    fi
else
    fail "disconnect the fault was never applied"
fi
assert_no_outstanding "disconnect the journal is clean after kill -9"

pid="$(inject_bg network-disconnect 120s)"
if await "! attached $TARGET"; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    docker network connect --alias changed-by-operator "$NET" "$TARGET"
    set +e
    mismatch="$("$BIN" reclaim --no-color 2>&1)"
    mismatch_code=$?
    set -e
    if [[ "$mismatch_code" != 0 ]] && grep -q 'different aliases' <<<"$mismatch"; then
        pass "disconnect a changed alias keeps recovery outstanding"
    else
        fail "disconnect altered endpoint was treated as restored: $mismatch"
    fi
    if aliases_of "$TARGET" | grep -q changed-by-operator; then
        pass "disconnect recovery did not overwrite an altered endpoint"
    else
        fail "disconnect recovery overwrote an altered endpoint"
    fi
    docker network disconnect "$NET" "$TARGET"
    docker network connect --alias "$ALIAS" "$NET" "$TARGET"
    "$BIN" reclaim --no-color >/dev/null 2>&1 || fail "disconnect corrected endpoint did not settle"
    assert_no_outstanding "disconnect restored configuration settles on replay"
else
    fail "disconnect alias drift control never detached the target"
fi

docker rm -f "$DECOY" >/dev/null 2>&1 || true
pid="$(inject_bg container-pause 3s)"
if await "paused $TARGET"; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    docker rm -f "$TARGET" >/dev/null 2>&1 || true

    if "$BIN" reclaim --no-color >/dev/null 2>&1; then
        pass "gone a fault on a deleted container resolves instead of wedging"
    else
        fail "gone a deleted container left a permanently unrevertable record"
    fi
else
    fail "gone the fault was never applied"
fi

if [[ $failures -ne 0 ]]; then
    echo "${failures} survival assertion(s) failed"
    exit 1
fi

echo "survive: all assertions passed"
