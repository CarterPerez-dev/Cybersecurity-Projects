#!/usr/bin/env bash
# ©AngelaMos | 2026
# smoke.sh

set -euo pipefail

BIN="${BIN:-./khaos}"
IMAGE="${SMOKE_IMAGE:-alpine:3.22}"

RUN_ID="$$"
OWNER_LABEL="khaos.smoke=${RUN_ID}"
PREFIX="ks-${RUN_ID}"
WORKDIR="$(mktemp -d)"

failures=0

cleanup() {
    local owned
    owned="$(docker ps -aq --filter "label=${OWNER_LABEL}" 2>/dev/null || true)"
    if [[ -n "$owned" ]]; then
        docker rm -f $owned >/dev/null 2>&1 || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM HUP

spawn() {
    local name="$1"
    shift
    docker run -d --name "${PREFIX}-${name}" --label "$OWNER_LABEL" "$@" "$IMAGE" sleep 600 >/dev/null
}

assert_status() {
    local name="$1" want="$2" line
    line="$(grep -E "^[[:space:]]+${PREFIX}-${name}[[:space:]]" <<<"$OUTPUT" || true)"

    if [[ -z "$line" ]]; then
        echo "FAIL ${name}: absent from the listing, expected status ${want}"
        failures=$((failures + 1))
        return
    fi

    if [[ "$line" != *"$want"* ]]; then
        echo "FAIL ${name}: expected ${want}, got: ${line}"
        failures=$((failures + 1))
        return
    fi

    echo "ok   ${name} -> ${want}"
}

assert_absent() {
    local name="$1"
    if grep -qE "^[[:space:]]+${PREFIX}-${name}[[:space:]]" <<<"$OUTPUT"; then
        echo "FAIL ${name}: a container without the consent label was enumerated"
        failures=$((failures + 1))
        return
    fi
    echo "ok   ${name} -> never enumerated"
}

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "pulling ${IMAGE}"
    docker pull "$IMAGE" >/dev/null
fi

# A decoy socket. The predicate reasons about the mount path, never the file,
# so the live daemon socket is never handed to a test fixture.
mkdir -p "${WORKDIR}/run"
touch "${WORKDIR}/run/docker.sock"

spawn ok        --label khaos.target=true
spawn badval    --label khaos.target=yes
spawn sock      --label khaos.target=true -v "${WORKDIR}/run/docker.sock:/var/run/docker.sock:ro"
spawn sockdir   --label khaos.target=true -v "/var/run:/hostrun:ro"
spawn hostnet   --label khaos.target=true --network host
spawn privileged --label khaos.target=true --privileged
spawn netadmin  --label khaos.target=true --cap-add NET_ADMIN
spawn hostpid   --label khaos.target=true --pid host
spawn nolabel

docker create --name "${PREFIX}-stopped" --label "$OWNER_LABEL" \
    --label khaos.target=true "$IMAGE" sleep 600 >/dev/null

peer="${PREFIX}-ok"
docker run -d --name "${PREFIX}-joiner" --label "$OWNER_LABEL" \
    --network "container:${peer}" "$IMAGE" sleep 600 >/dev/null

OUTPUT="$("$BIN" targets --all --no-color)"

assert_status ok         "namespace-joined-by-peer"
assert_status badval     "consent-label-not-true"
assert_status sock       "docker-socket-reachable"
assert_status sockdir    "docker-socket-reachable"
assert_status hostnet    "host-network-mode"
assert_status privileged "privileged-container"
assert_status netadmin   "dangerous-capability"
assert_status hostpid    "host-namespace"
assert_status stopped    "container-not-running"
assert_absent nolabel
assert_absent joiner

docker rm -f "${PREFIX}-joiner" >/dev/null
OUTPUT="$("$BIN" targets --all --no-color)"
assert_status ok "ready"

READY_ONLY="$("$BIN" targets --no-color)"
if grep -qE "^[[:space:]]+${PREFIX}-(badval|sock|sockdir|hostnet|privileged|netadmin|hostpid|stopped)[[:space:]]" <<<"$READY_ONLY"; then
    echo "FAIL default view listed a refused target"
    failures=$((failures + 1))
else
    echo "ok   default view hides refused targets"
fi

if [[ $failures -ne 0 ]]; then
    echo "${failures} smoke assertion(s) failed"
    exit 1
fi

echo "smoke: all assertions passed"
