#!/usr/bin/env bash
# ©AngelaMos | 2026
# version-matrix.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROBE="${HERE}/test/support/matrix_probe.rb"
RENDER="${HERE}/scripts/render_matrix.rb"
OUT="${HERE}/tmp/matrix.jsonl"
RENDER_IMAGE="ruby:4.0-slim"

IMAGES=(
    "ruby:3.1-slim"
    "ruby:3.2-slim"
    "ruby:3.3-slim"
    "ruby:3.4-slim"
    "ruby:4.0.2-slim"
    "ruby:4.0-slim"
)

if [[ $# -gt 0 ]]; then
    IMAGES=("$@")
fi

mkdir -p "${HERE}/tmp"
: >"${OUT}"

echo "probing ${#IMAGES[@]} images"

incomplete=()

for image in "${IMAGES[@]}"; do
    printf '  %-18s ' "${image}"

    if ! docker image inspect "${image}" >/dev/null 2>&1; then
        if ! docker pull -q "${image}" >/dev/null 2>&1; then
            echo "UNAVAILABLE"
            incomplete+=("${image} unavailable")
            continue
        fi
    fi

    if result=$(docker run --rm --network none \
        -e "MATRIX_IMAGE=${image}" \
        -v "${PROBE}:/probe.rb:ro" \
        "${image}" ruby /probe.rb 2>/dev/null); then
        echo "${result}" >>"${OUT}"
        echo "ok"
    else
        echo "PROBE FAILED"
        incomplete+=("${image} probe failed")
    fi
done

echo
render_status=0
docker run --rm --network none \
    -v "${OUT}:/matrix.jsonl:ro" \
    -v "${RENDER}:/render.rb:ro" \
    -v "${HERE}/lib:/app/lib:ro" \
    -w /app \
    "${RENDER_IMAGE}" ruby -Ilib /render.rb /matrix.jsonl || render_status=$?

echo
if [[ ${#incomplete[@]} -gt 0 ]]; then
    echo "GATE FAILED - ${#incomplete[@]} of ${#IMAGES[@]} images produced no probe result:"
    printf '  %s\n' "${incomplete[@]}"
    echo "  a matrix built from a subset cannot certify a version boundary"
    exit 1
fi

if [[ ${render_status} -ne 0 ]]; then
    echo "GATE FAILED - renderer rejected the matrix"
fi

exit ${render_status}
