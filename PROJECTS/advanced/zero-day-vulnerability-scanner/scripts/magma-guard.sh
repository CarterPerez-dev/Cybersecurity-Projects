# ©AngelaMos | 2026
# magma-guard.sh
# shellcheck shell=bash

# The hand-written magma harness is the one build input no stamp covered. `build-magma-libpng.sh`
# already refuses to run against a drifted magma commit or a changed canary selection, but the
# harness it compiles into the target was only ever existence-checked, so editing
# `harnesses/libpng_read.c` and running a gate graded the previous binary and reported PASS.
# Measured 2026-08-18: with LISDEX_MAX_PIXELS cut from 1<<24 to 1<<2, a change that rejects
# essentially every seed before it reaches png_read_row, `just m1-gate` still printed
# "M1 EXIT GATE PASSED" at exit 0 against a byte-identical binary.

LISDEX_HARNESS_SRC="${LISDEX_HARNESS:-/work/harnesses/libpng_read.c}"
LISDEX_HARNESS_STAMP_NAME=".lisdex-harness-sha"

lisdex_harness_sha() {
    sha256sum "$LISDEX_HARNESS_SRC" | cut -d' ' -f1
}

lisdex_stamp_harness() {
    local out_root="$1"
    lisdex_harness_sha > "$out_root/$LISDEX_HARNESS_STAMP_NAME"
}

# Sourced by every gate that runs the hand-written target, so the diagnosis is written once.
# Exits rather than returning: a gate that graded the wrong binary has no result worth printing.
require_harness_current() {
    local out_root="$1"
    local stamp="$out_root/$LISDEX_HARNESS_STAMP_NAME"
    local want have

    if [ ! -f "$LISDEX_HARNESS_SRC" ]; then
        printf '\n[gate] FAIL: hand-written harness missing at %s\n' \
            "$LISDEX_HARNESS_SRC" >&2
        exit 1
    fi

    want="$(lisdex_harness_sha)"

    if [ ! -f "$stamp" ]; then
        printf '\n[gate] FAIL: %s was built before the harness was stamped, so nothing proves it
       matches %s - run: just magma-libpng\n' "$out_root" "$LISDEX_HARNESS_SRC" >&2
        exit 1
    fi

    have="$(cat "$stamp")"
    if [ "$want" != "$have" ]; then
        printf '\n[gate] FAIL: %s changed since the target was built, so this gate would grade
       the previous binary - run: just magma-libpng
         source now : %s
         built from : %s\n' "$LISDEX_HARNESS_SRC" "$want" "$have" >&2
        exit 1
    fi
}
