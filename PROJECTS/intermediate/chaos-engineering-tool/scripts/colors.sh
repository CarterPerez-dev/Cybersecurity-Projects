#!/usr/bin/env bash
# ©AngelaMos | 2026
# colors.sh

set -euo pipefail

BIN="${BIN:-./khaos}"
ART="${ART:-internal/banner/khaos.ascii}"

failures=0

check_bare() {
    local label="$1" command="$2" count
    count="$(eval "$command" | grep -c $'\x1b' || true)"

    if [[ "$count" -ne 0 ]]; then
        echo "FAIL ${label}: ${count} escape sequence(s), want 0"
        failures=$((failures + 1))
        return
    fi

    echo "ok   ${label}"
}

check_bare "clean env, piped"      "env -i PATH=\$PATH $BIN banner"
check_bare "NO_COLOR=1"            "NO_COLOR=1 $BIN banner"
check_bare "NO_COLOR + FORCE"      "NO_COLOR=1 CLICOLOR_FORCE=1 $BIN banner"
check_bare "--no-color"            "$BIN banner --no-color"
check_bare "--no-color=true"       "$BIN banner --no-color=true"
check_bare "--no-color=1"          "$BIN banner --no-color=1"
check_bare "--no-color=T"          "$BIN banner --no-color=T"
check_bare "TERM=dumb"             "env -i PATH=\$PATH TERM=dumb $BIN banner"

expected="$(grep -o $'█' "$ART" | wc -l)"
rendered="$($BIN banner --no-color | grep -o $'█' | wc -l)"

if [[ "$rendered" -ne "$expected" ]]; then
    echo "FAIL glyph survival: rendered ${rendered} full blocks, the asset has ${expected}"
    failures=$((failures + 1))
else
    echo "ok   glyph survival (${expected} full blocks, derived from the asset)"
fi

if [[ $failures -ne 0 ]]; then
    echo "${failures} color assertion(s) failed"
    exit 1
fi

echo "colors: all assertions passed"
