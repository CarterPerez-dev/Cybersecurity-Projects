#!/usr/bin/env bash
# ©AngelaMos | 2026
# m9-gate.sh

set -euo pipefail

# shellcheck source=scripts/magma-guard.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/magma-guard.sh"

WORK="${MAGMA_WORK:-/opt/magma-work}"
OUT_ROOT="$WORK/out/libpng"
SEEDS="$WORK/libpng/corpus/libpng_read_fuzzer"
GATE="$WORK/m9"
FINDINGS="$GATE/findings"
DB="$GATE/lisdex.sqlite"
EMPTY="$GATE/empty"
GATE_LOG="$GATE/stage.log"
CAMPAIGN_LOG="$GATE/campaign.log"
LISDEX_BIN="${CARGO_TARGET_DIR:-/cargo-target}/debug/lisdex"
TARGET="$OUT_ROOT/afl/lisdex_libpng_read"
CMPLOG="$OUT_ROOT/cmplog/lisdex_libpng_read"
GATE_DURATION="${LISDEX_M9_DURATION:-240}"
GATE_JOBS="${LISDEX_M9_JOBS:-2}"

TUI_MANIFEST="crates/lisdex-tui/Cargo.toml"
TUI_SRC="crates/lisdex-tui/src"
ANALYSIS_SRC=(
    "crates/lisdex-monitor/src"
    "crates/lisdex-core/src"
    "crates/lisdex-fuzz/src"
    "crates/lisdex-triage/src"
)
LIVE_WAIT_SECONDS=90
RENDER_WIDTH=170
RENDER_HEIGHT=46

ANALYSIS_SYMBOLS=(
    "classify"
    "group_crashes"
    "SanitizerReport"
    "plot::parse"
    "stack_hash"
    "libcasr"
    "rusqlite"
)

FAILURES=0

log() { printf '\n[m9] %s\n' "$1"; }
die() { printf '\n[m9] FAIL: %s\n' "$1" >&2; exit 1; }
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

if [ "${1:-}" = "reset" ]; then
    log "resetting $GATE"
    rm -rf "$GATE"
fi

[ -x "$TARGET" ] || die "magma libpng not built; run: just magma-libpng"
require_harness_current "$OUT_ROOT"
[ -x "$CMPLOG" ] || die "cmplog target missing at $CMPLOG"
[ -d "$SEEDS" ] || die "seed corpus missing at $SEEDS"
[ -f "$TUI_MANIFEST" ] || die "run this from the project root; $TUI_MANIFEST not found"

mkdir -p "$GATE" "$EMPTY"

log "stage 1/8: build lisdex"
cargo build -p lisdex
[ -x "$LISDEX_BIN" ] || die "lisdex binary not found at $LISDEX_BIN"

log "stage 2/8: the view cannot reach analysis, because it does not link it"
# Only [dependencies] is inspected. A dev-dependency cannot be reached by the
# shipped view code, so it can build fixtures without weakening this property.
LINKED="$(awk '/^\[dependencies\]/{on=1;next} /^\[/{on=0} on' "$TUI_MANIFEST" \
    | grep -oE '^lisdex-[a-z]+' | sort -u | tr '\n' ' ' | sed 's/ $//')"
if [ "$LINKED" = "lisdex-monitor" ]; then
    pass "lisdex-tui links exactly one lisdex crate: $LINKED"
else
    fail "lisdex-tui links [$LINKED]; a pure view must link only lisdex-monitor"
fi

log "stage 3/8: no analysis symbol appears anywhere in the view's source"
for symbol in "${ANALYSIS_SYMBOLS[@]}"; do
    HITS="$(grep -rF -- "$symbol" "$TUI_SRC" | grep -c . || true)"
    if [ "$HITS" -eq 0 ]; then
        pass "view is free of '$symbol'"
    else
        fail "view mentions '$symbol' $HITS time(s); analysis belongs in the model"
    fi
done

log "stage 3b/8: control - the same searches find those symbols in the analysis layer"
# Without this, stage 3 passes on a wrong path or a typo'd pattern and certifies
# nothing. Each symbol is searched across every crate the view refuses to link,
# because that is where the analysis it must not contain actually lives.
MISSING=""
for symbol in "${ANALYSIS_SYMBOLS[@]}"; do
    HITS="$(grep -rF -- "$symbol" "${ANALYSIS_SRC[@]}" | grep -c . || true)"
    [ "$HITS" -eq 0 ] && MISSING="$MISSING $symbol"
done
if [ -z "$MISSING" ]; then
    pass "all ${#ANALYSIS_SYMBOLS[@]} searched symbols are live in the analysis layer"
else
    fail "searched symbol(s) absent from the analysis layer:$MISSING; stage 3 proves nothing about them"
fi

log "stage 4/8: the model and the view answer for themselves"
if cargo test -p lisdex-monitor -p lisdex-tui > "$GATE_LOG" 2>&1; then
    TESTS="$(grep -oE 'test result: ok\. [0-9]+' "$GATE_LOG" \
        | grep -oE '[0-9]+' | paste -sd+ | bc)"
    pass "lisdex-monitor and lisdex-tui: $TESTS tests"
else
    fail "model or view tests (see $GATE_LOG)"
fi

log "stage 5/8: a live campaign renders while it is still running (${GATE_DURATION}s)"
rm -rf "$FINDINGS" "$DB"
"$LISDEX_BIN" fuzz --target "$TARGET" --cmplog "$CMPLOG" --seeds "$SEEDS" \
    --findings "$FINDINGS" --db "$DB" --duration "$GATE_DURATION" \
    --jobs "$GATE_JOBS" > "$CAMPAIGN_LOG" 2>&1 &
CAMPAIGN_PID=$!

WAITED=0
while [ "$WAITED" -lt "$LIVE_WAIT_SECONDS" ]; do
    if find "$FINDINGS" -name plot_data -size +1c 2>/dev/null | grep -q .; then
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

LIVE_FRAME="$GATE/live.frame"
"$LISDEX_BIN" tui --db "$DB" --findings "$FINDINGS" --once \
    --width "$RENDER_WIDTH" --height "$RENDER_HEIGHT" > "$LIVE_FRAME" 2>&1 \
    || fail "rendering a running campaign failed (see $LIVE_FRAME)"

if grep -q 'FUZZING' "$LIVE_FRAME"; then
    pass "the panel reports the campaign as FUZZING while afl-fuzz is still up"
else
    fail "a running campaign did not render as FUZZING (see $LIVE_FRAME)"
fi
if grep -q 'lisdex_libpng_read' "$LIVE_FRAME"; then
    pass "the panel names the target the campaign is fuzzing"
else
    fail "the target name is missing from the live frame"
fi

wait "$CAMPAIGN_PID" || die "campaign failed (see $CAMPAIGN_LOG)"

log "stage 6/8: the finished campaign renders on every panel"
for panel in overview findings instances; do
    "$LISDEX_BIN" tui --db "$DB" --findings "$FINDINGS" --once --panel "$panel" \
        --width "$RENDER_WIDTH" --height "$RENDER_HEIGHT" > "$GATE/$panel.frame" 2>&1 \
        || fail "rendering panel $panel failed"
done

grep -q 'EDGE COVERAGE' "$GATE/overview.frame" \
    && pass "overview draws the coverage gauge" \
    || fail "overview is missing the coverage gauge"
grep -q 'SANITIZER REPORT' "$GATE/findings.frame" \
    && pass "findings draws the raw report an advisory would quote" \
    || fail "findings is missing the sanitizer report pane"
grep -q 'EXEC RATE BY INSTANCE' "$GATE/instances.frame" \
    && pass "instances draws the per-instance rate chart" \
    || fail "instances is missing the per-instance chart"

RENDERED_INSTANCES="$(grep -cE '^│(main|secondary[0-9]+) ' "$GATE/instances.frame" || true)"
if [ "$RENDERED_INSTANCES" -eq "$GATE_JOBS" ]; then
    pass "$RENDERED_INSTANCES instance row(s) rendered, matching the $GATE_JOBS that ran"
else
    fail "expected $GATE_JOBS instance rows, rendered $RENDERED_INSTANCES"
fi

# Stage 3 proves the view cannot CALL analysis. It cannot prove the view does not
# ASSERT. afl-fuzz leaves fuzzer_stats on disk after it exits, so any liveness
# word printed over a finished campaign is a claim the tool cannot observe.
# The pattern matches the CLAIM ("2 running", "live campaign"), not the bare word:
# the findings panel quotes the target's own stderr, and magma's canary harness
# prints "Monitor not running. Canaries will be disabled." on every crash.
LIVENESS_CLAIM='[0-9]+ running|live campaign'
LIVENESS_CLAIMS=0
for panel in overview findings instances; do
    grep -qE "$LIVENESS_CLAIM" "$GATE/$panel.frame" \
        && LIVENESS_CLAIMS=$((LIVENESS_CLAIMS + 1))
done
if ! grep -q 'COMPLETED' "$GATE/overview.frame"; then
    fail "this campaign did not render as COMPLETED, so the liveness check below is vacuous"
elif [ "$LIVENESS_CLAIMS" -eq 0 ]; then
    pass "no panel calls a finished campaign running or live"
else
    fail "$LIVENESS_CLAIMS panel(s) assert liveness over a campaign that has already exited"
fi

log "stage 7/8: the panel agrees with the tools it is a view over"
CLI_CRASHES="$("$LISDEX_BIN" crashes --db "$DB" --campaign 1 | grep -c 'stack_hash' || true)"
CLI_BUGS="$("$LISDEX_BIN" crashes --db "$DB" --campaign 1 \
    | grep -oE 'stack_hash [0-9a-f]+' | sort -u | grep -c . || true)"
CLI_PEAK="$("$LISDEX_BIN" coverage --findings "$FINDINGS" \
    | awk '/curve_peak_edges/ {print $2}')"

TUI_CRASHES="$(grep -oE 'crashes [0-9]+' "$GATE/overview.frame" | head -1 | grep -oE '[0-9]+')"
TUI_BUGS="$(grep -oE 'bugs [0-9]+' "$GATE/overview.frame" | head -1 | grep -oE '[0-9]+')"
TUI_PEAK="$(grep -oE 'peak edges *[0-9,]+' "$GATE/overview.frame" | head -1 \
    | grep -oE '[0-9,]+' | tr -d ',' || true)"

if [ "$CLI_CRASHES" -gt 0 ]; then
    pass "the campaign persisted $CLI_CRASHES crash(es), so the comparison is not vacuous"
else
    fail "no crash was persisted; the findings comparison below proves nothing"
fi
if [ "$TUI_CRASHES" = "$CLI_CRASHES" ]; then
    pass "crash count agrees with 'lisdex crashes': $TUI_CRASHES"
else
    fail "panel shows $TUI_CRASHES crashes, 'lisdex crashes' reports $CLI_CRASHES"
fi
if [ "$TUI_BUGS" = "$CLI_BUGS" ]; then
    pass "distinct-bug count agrees with 'lisdex crashes': $TUI_BUGS"
else
    fail "panel shows $TUI_BUGS bugs, 'lisdex crashes' reports $CLI_BUGS"
fi
if [ "$TUI_PEAK" = "$CLI_PEAK" ]; then
    pass "peak edges agrees with 'lisdex coverage': $TUI_PEAK"
else
    fail "panel charts a peak of $TUI_PEAK, 'lisdex coverage' reports $CLI_PEAK"
fi

log "stage 8/8: control - an empty campaign must not render the numbers of a real one"
EMPTY_FRAME="$GATE/empty.frame"
"$LISDEX_BIN" tui --db "$EMPTY/none.sqlite" --findings "$EMPTY" --once \
    --width "$RENDER_WIDTH" --height "$RENDER_HEIGHT" > "$EMPTY_FRAME" 2>&1 \
    || fail "rendering an empty source failed instead of reporting it"

if grep -q 'no campaign in store' "$EMPTY_FRAME"; then
    pass "an empty source renders its reason rather than a blank panel"
else
    fail "an empty source did not say why it is empty (see $EMPTY_FRAME)"
fi
if grep -q 'lisdex_libpng_read' "$EMPTY_FRAME"; then
    fail "the empty frame names a target it was never given; the panel is printing a template"
else
    pass "the empty frame names no target, so the live frame really was read from disk"
fi
if cmp -s "$GATE/overview.frame" "$EMPTY_FRAME"; then
    fail "the real and empty frames are byte-identical; the renderer ignores its input"
else
    pass "the real and empty frames differ, so the panel renders what it was pointed at"
fi

log "RESULT"
if [ "$FAILURES" -eq 0 ]; then
    printf '\n[m9] M9 EXIT GATE PASSED\n'
    printf '  CHECK 1  the view links only the read-model, and names no analysis symbol\n'
    printf '  CHECK 2  a campaign still running renders live, on every panel\n'
    printf '  CHECK 3  its counts equal what lisdex crashes and lisdex coverage report\n'
    printf '  CHECK 4  an empty source renders its reason, and not the numbers of a real run\n'
    exit 0
fi
printf '\n[m9] M9 EXIT GATE FAILED: %s check(s)\n' "$FAILURES" >&2
exit 1
