#!/usr/bin/env bash
# ©AngelaMos | 2026
# m4-gate.sh

set -euo pipefail

WORK="${MAGMA_WORK:-/opt/magma-work}"
MAGMA="${MAGMA_ROOT:-/opt/magma}/magma"
REPO="$WORK/libpng/repo"
OUT_ROOT="$WORK/out/libpng"
GATE="$WORK/m4"
SYNTH="$GATE/synth"
CORPUS="$GATE/corpus"
INVALID="$GATE/invalid"
CONTROLS="$GATE/controls"
FINDINGS="$GATE/findings"
DB="$GATE/lisdex.sqlite"
GATE_LOG="$GATE/stage.log"
DRIVER="${LISDEX_AFL_DRIVER:-/usr/local/lib/afl/libAFLDriver.a}"
LISDEX_BIN="${CARGO_TARGET_DIR:-/cargo-target}/debug/lisdex"
GATE_DURATION="${LISDEX_M4_DURATION:-600}"
TOP="${LISDEX_M4_TOP:-12}"
CANARY_PREFIX="PNG"
CFLAGS_CANARY="-include $MAGMA/src/canary.h -DMAGMA_ENABLE_CANARIES -DMAGMA_FATAL_CANARIES -g -O0"

FAILURES=0

log() { printf '\n[m4] %s\n' "$1"; }
die() { printf '\n[m4] FAIL: %s\n' "$1" >&2; exit 1; }
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

if [ "${1:-}" = "reset" ]; then
    log "resetting $GATE"
    rm -rf "$GATE"
fi

[ -d "$REPO" ] || die "magma libpng not fetched; run: just magma-libpng"
[ -f "$OUT_ROOT/afl/libpng16.a" ] || die "magma libpng not built; run: just magma-libpng"
[ -f "$DRIVER" ] || die "libAFLDriver.a missing at $DRIVER"

mkdir -p "$GATE"

log "stage 1/14: build lisdex"
cargo build -p lisdex
[ -x "$LISDEX_BIN" ] || die "lisdex binary not found at $LISDEX_BIN"

log "stage 2/14: every oracle answers for itself"
# The end-to-end controls below cannot isolate one coverage oracle from another: the stub
# and the unpopulated variant are each rejected by BOTH 3a and 3c, so either one alone
# keeps the gate green while the other is gutted. Each oracle owns unit tests that no
# other oracle can satisfy, so running them here is what makes a single gutted oracle red.
if cargo test -p lisdex-harness --lib > "$GATE_LOG" 2>&1; then
    pass "$(grep -m1 'test result' "$GATE_LOG") in lisdex-harness"
else
    tail -20 "$GATE_LOG" >&2
    fail "the oracle crate's own tests do not pass - one of the four oracles is not doing its job"
fi

log "stage 3/14: assemble the two corpora the oracles need"
mkdir -p "$GATE"
rm -rf "$CORPUS" "$INVALID" "$CONTROLS"
mkdir -p "$CORPUS" "$INVALID" "$CONTROLS"
cp "$REPO"/contrib/pngsuite/*.png "$CORPUS/"
SEEDS="$(find "$CORPUS" -name '*.png' | wc -l)"
[ "$SEEDS" -ge 2 ] || die "only $SEEDS valid seed(s); the coverage oracle needs at least 2"
FIRST_PNG="$(find "$CORPUS" -name '*.png' | sort | head -1)"
head -c 40 "$FIRST_PNG" > "$INVALID/truncated.png"
printf 'not a png at all, not even close\n' > "$INVALID/text.png"
head -c 200 /dev/urandom > "$INVALID/random.png"
pass "$SEEDS valid seeds and 3 invalid seeds staged"

# Every oracle assertion below runs through the shipped judge(), never a shell
# reimplementation of it. Gutting oracle::judge must turn this gate red.
oracle_flags() {
    printf '%s\0' \
        --seeds "$CORPUS" \
        --invalid-seeds "$INVALID" \
        --archive "$OUT_ROOT/afl/libpng16.a" \
        --driver "$DRIVER" \
        --link-arg "-L$OUT_ROOT/afl" \
        --link-arg "-l:magma.o" \
        --link-arg "-lrt" \
        --link-arg "-lz" \
        --link-arg "-g" \
        --cflag "-include" \
        --cflag "$MAGMA/src/canary.h" \
        --cflag "-DMAGMA_ENABLE_CANARIES" \
        --cflag "-DMAGMA_FATAL_CANARIES" \
        --cflag "-g" \
        --cflag "-O0"
}

lisdex_verify() {
    SRC="$1"; SCRATCH="$2"
    rm -rf "$SCRATCH"
    mapfile -d '' FLAGS < <(oracle_flags)
    "$LISDEX_BIN" verify "$SRC" --include "$REPO" --work "$SCRATCH" "${FLAGS[@]}"
}

log "stage 4/14: lisdex synthesizes AND self-verifies a harness with NO LLM"
rm -rf "$SYNTH"
mapfile -d '' HARNESS_FLAGS < <(oracle_flags)
"$LISDEX_BIN" harness "$REPO" --out "$SYNTH" --top "$TOP" "${HARNESS_FLAGS[@]}" \
    | tee "$GATE/synth.log"
# lisdex emits the SET of survivors now, so `find | head -1` would pick whichever name the
# filesystem happened to return first. The log lists promotions in RANK order, so the first
# `synthesized` line is the top-ranked harness and that is the one this gate fuzzes.
ENTRY_FILE="$(grep -m1 '^synthesized ' "$GATE/synth.log" | awk '{print $2}')"
ENTRY="$SYNTH/$ENTRY_FILE"
[ -n "$ENTRY_FILE" ] && [ -f "$ENTRY" ] || die "no harness was synthesized"
ENTRY_NAME="$(basename "$ENTRY" .c)"
if grep -q '^oracles run:' "$GATE/synth.log"; then
    pass "lisdex accepted $ENTRY_NAME through its own oracle layer"
    printf '        %s\n' "$(grep -m1 '^oracles run:' "$GATE/synth.log" | cut -c1-120)"
else
    fail "lisdex emitted a harness without reporting which oracles judged it"
fi
if grep -q '3c valid-vs-invalid differential' "$GATE/synth.log"; then
    pass "the valid-versus-invalid differential ran (an invalid corpus was supplied)"
else
    fail "oracle 3c did not run - the gate must exercise the differential"
fi

# B51(a). The run keeps every survivor instead of returning at the first acceptance, which
# is the only way oracle 4 ever has an accepted set to be novel AGAINST. Ties the summary to
# the artifacts on disk, so a run that reports a set it did not write fails here. libpng
# yields exactly one survivor (its other planning candidates are 4-byte header readers that
# oracle 3a rejects), so the REJECTING direction of oracle 4 is measured on libwebp - see
# doc 02 D31 - and asserted by the judge_global_novelty unit tests in stage 1.
SUMMARY="$(grep -m1 -oE '^[0-9]+ harness\(es\) survived' "$GATE/synth.log" | grep -oE '^[0-9]+')"
WRITTEN="$(find "$SYNTH" -maxdepth 1 -name '*.c' | wc -l)"
if [ -n "$SUMMARY" ] && [ "$SUMMARY" -eq "$WRITTEN" ] && [ "$WRITTEN" -ge 1 ]; then
    pass "the survivor set is reported and matches the $WRITTEN harness(es) written"
else
    fail "survivor summary '$SUMMARY' does not match $WRITTEN harness(es) on disk"
fi
# B80. magma's libpng16.a is an LTO-BITCODE archive, so it is re-instrumented at every link and
# two separately linked harnesses do not number the same edge the same way - measured at 0 of 24
# real (pair, seed) cases. Every number in this summary that spans MORE THAN ONE harness is
# therefore not a measurement, and the union total must not be printed as though it were. The
# opposite direction is asserted in stage 13 against an object archive, where it MUST appear.
if grep -q 'harness(es) survived the oracles, covering' "$GATE/synth.log"; then
    fail "a cross-harness edge total was published against an LTO-bitcode archive (B80)"
else
    pass "no cross-harness total is claimed against an archive that is relinked every time"
fi
# The honesty line: with one survivor, oracle 4 could NOT discriminate and must say so
# rather than claim it ran.
if grep -q '4 global novelty could only reject a harness reaching nothing' "$GATE/synth.log"; then
    pass "a single-survivor run says oracle 4 could not discriminate rather than claiming it ran"
else
    fail "the oracle report overclaims global novelty on a first acceptance"
fi

if grep -q 'LLVMFuzzerTestOneInput' "$ENTRY"; then
    pass "harness defines LLVMFuzzerTestOneInput"
else
    fail "harness does not define LLVMFuzzerTestOneInput"
fi

if grep -qE '^\s*int\s+main\s*\(' "$ENTRY"; then
    fail "harness defines its own main - it would silently shadow the AFL driver"
else
    pass "harness defines no main (the driver's weak main is not shadowed)"
fi

build_harness() {
    SRC="$1"; BIN="$2"; LIB="$3"; EXTRA="${4:-}"
    (
        cd "$REPO"
        env AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_QUIET=1 ${EXTRA:+AFL_LLVM_CMPLOG=1} \
            afl-clang-lto $CFLAGS_CANARY -I. "$SRC" -o "$BIN" \
            "$OUT_ROOT/$LIB/libpng16.a" -L"$OUT_ROOT/$LIB" -l:magma.o -lrt "$DRIVER" -lz -g
    )
}

log "stage 5/14: independent cross-check - it compiles and every valid seed runs clean"
if build_harness "$ENTRY" "$GATE/harness" afl 2>"$GATE/compile.log"; then
    pass "synthesized harness compiles and links"
else
    tail -5 "$GATE/compile.log" >&2
    die "synthesized harness does not compile"
fi
build_harness "$ENTRY" "$GATE/harness_cmplog" cmplog cmplog >/dev/null 2>&1 \
    || die "cmplog variant does not compile"

CLEAN=0; CRASHED=0
for SEED in "$CORPUS"/*.png; do
    if ASAN_OPTIONS=detect_leaks=1 "$GATE/harness" "$SEED" >/dev/null 2>&1; then
        CLEAN=$((CLEAN + 1))
    else
        CRASHED=$((CRASHED + 1))
    fi
done
if [ "$CRASHED" -eq 0 ]; then
    pass "$CLEAN/$SEEDS valid seeds run clean with leak detection ON"
else
    fail "$CRASHED/$SEEDS valid seeds crash or leak - the oracle would be unsound"
fi

log "stage 6/14: the shipped judge ACCEPTS the harness it chose"
if lisdex_verify "$ENTRY" "$GATE/verify-accepted" > "$GATE/verify-accepted.log" 2>&1; then
    EDGES="$(grep -m1 -oE 'ACCEPTED.* - [0-9]+ edges' "$GATE/verify-accepted.log" \
        | grep -oE '[0-9]+ edges' | grep -oE '^[0-9]+' || echo 0)"
    if [ "${EDGES:-0}" -gt 0 ]; then
        pass "$(grep -m1 ACCEPTED "$GATE/verify-accepted.log")"
    else
        fail "accepted with $EDGES edges - a harness that reaches nothing is not a harness"
    fi
else
    tail -5 "$GATE/verify-accepted.log" >&2
    fail "the shipped judge rejects the harness lisdex itself accepted"
fi

log "stage 7/14: NEGATIVE CONTROL - a stub that ignores its input must be REJECTED"
cat > "$CONTROLS/stub.c" <<'STUB'
// ©AngelaMos | 2026
// stub.c

#include <stddef.h>
#include <stdint.h>

#include "png.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    return 0;
}
STUB
if lisdex_verify "$CONTROLS/stub.c" "$GATE/verify-stub" > "$GATE/verify-stub.log" 2>&1; then
    fail "the shipped judge ACCEPTED a stub harness - the coverage oracle is not running"
else
    if grep -q 'REJECTED' "$GATE/verify-stub.log"; then
        pass "$(grep -m1 REJECTED "$GATE/verify-stub.log")"
    else
        tail -5 "$GATE/verify-stub.log" >&2
        fail "the stub was not rejected by an oracle - it failed for some other reason"
    fi
fi

log "stage 8/14: NEGATIVE CONTROL - the unpopulated struct variant must be REJECTED"
VARIANTS="$(find "$SYNTH/candidates" -maxdepth 1 -name "$ENTRY_NAME.v*.c" | sort -V)"
VARIANT_COUNT="$(printf '%s\n' "$VARIANTS" | grep -c . || true)"
if [ "${VARIANT_COUNT:-0}" -lt 2 ]; then
    fail "only $VARIANT_COUNT variant(s) planned for $ENTRY_NAME - struct population is not \
being exercised and this control is vacuous"
else
    BARE="$(printf '%s\n' "$VARIANTS" | tail -1)"
    if lisdex_verify "$BARE" "$GATE/verify-bare" > "$GATE/verify-bare.log" 2>&1; then
        fail "the shipped judge ACCEPTED $(basename "$BARE") - struct population is not load-bearing"
    else
        pass "unpopulated variant $(basename "$BARE") correctly REJECTED"
    fi
fi

log "stage 9/14: NEGATIVE CONTROL - a harness that crashes on a valid seed must be REJECTED"
cat > "$CONTROLS/crasher.c" <<'CRASHER'
// ©AngelaMos | 2026
// crasher.c

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "png.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *copy = (uint8_t *)malloc(size + 1);
    volatile uint8_t seen;

    if (copy == NULL) {
        return 0;
    }
    memcpy(copy, data, size);
    seen = copy[size + 1];
    (void)seen;
    free(copy);
    return 0;
}
CRASHER
if lisdex_verify "$CONTROLS/crasher.c" "$GATE/verify-crasher" > "$GATE/verify-crasher.log" 2>&1; then
    fail "the shipped judge ACCEPTED a harness that overflows the heap on every seed"
else
    if grep -qE 'REJECTED.*(crashed on seed|does not compile)' "$GATE/verify-crasher.log"; then
        pass "$(grep -m1 REJECTED "$GATE/verify-crasher.log")"
    else
        tail -5 "$GATE/verify-crasher.log" >&2
        fail "the crashing harness was rejected, but not by the execution oracle"
    fi
fi

log "stage 10/14: NEGATIVE CONTROL - a harness that leaks on a valid seed must be REJECTED"
cat > "$CONTROLS/leaker.c" <<'LEAKER'
// ©AngelaMos | 2026
// leaker.c

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "png.h"

static volatile void *lisdex_sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    png_image ctx;

    memset(&ctx, 0, sizeof ctx);
    ctx.version = PNG_IMAGE_VERSION;
    (void)MAGMA_png_image_begin_read_from_memory(&ctx, (const void *)data, size);
    lisdex_sink = malloc(4096);
    return 0;
}
LEAKER
if lisdex_verify "$CONTROLS/leaker.c" "$GATE/verify-leaker" > "$GATE/verify-leaker.log" 2>&1; then
    fail "the shipped judge ACCEPTED a harness that leaks on every seed - LeakSanitizer is not \
armed on the direct run, so an unpaired constructor would forge a crash on every triage replay"
else
    if grep -qE 'REJECTED.*crashed on seed' "$GATE/verify-leaker.log"; then
        pass "leaking harness correctly REJECTED (LeakSanitizer fires on the direct run)"
    else
        tail -5 "$GATE/verify-leaker.log" >&2
        fail "the leaking harness was rejected, but not by the execution oracle"
    fi
fi

log "stage 11/14: lisdex drives a campaign against the SYNTHESIZED harness"
rm -rf "$FINDINGS" "$DB"
"$LISDEX_BIN" fuzz \
    --target "$GATE/harness" \
    --cmplog "$GATE/harness_cmplog" \
    --seeds "$CORPUS" \
    --findings "$FINDINGS" \
    --db "$DB" \
    --duration "$GATE_DURATION" \
    --until-crash \
    --label m4-synthesized | tee "$GATE/fuzz.log"

if grep -q '^persistent_mode    true' "$GATE/fuzz.log"; then
    pass "the campaign ran in persistent shmem_testcase deferred mode"
else
    fail "the campaign did not run in persistent mode - the harness may shadow the driver"
fi

[ -f "$DB" ] || die "no database was created at $DB"
CRASH_ROWS="$(sqlite3 "$DB" 'SELECT COUNT(*) FROM crashes;')"
if [ "${CRASH_ROWS:-0}" -ge 1 ]; then
    pass "crashes persisted: $CRASH_ROWS"
else
    fail "the synthesized harness found no crash in ${GATE_DURATION}s"
fi

REPORT="$(sqlite3 "$DB" 'SELECT sanitizer_report FROM crashes WHERE id = (SELECT MIN(id) FROM crashes);')"
CANARY_LOC="$(printf '%s\n' "$REPORT" | grep -A1 'in magma_log' | tail -1 \
    | grep -oE '/[^ ]+\.c:[0-9]+' | head -1 || true)"
if [ -n "$CANARY_LOC" ]; then
    CANARY_FILE="${CANARY_LOC%:*}"
    CANARY_LINE="${CANARY_LOC##*:}"
    BUG_ID="$(awk -v n="$CANARY_LINE" 'NR == n' "$CANARY_FILE" 2>/dev/null \
        | grep -oE "MAGMA_LOG\(\"${CANARY_PREFIX}[0-9]+\"" | grep -oE "${CANARY_PREFIX}[0-9]+" | head -1 || true)"
    if [ -n "$BUG_ID" ]; then
        pass "SYNTHESIZED harness re-found magma bug $BUG_ID at $CANARY_LOC"
    else
        fail "canary at $CANARY_LOC did not resolve to a $CANARY_PREFIX bug id"
    fi
else
    fail "crash is not an attributable magma canary trigger"
fi

log "stage 12/14: oracle 3b judges an UPWARD extension, in both directions"
# B51(b). Oracle 3b measures a candidate against the shorter call sequence it EXTENDS, so it
# needs a library whose author sequence continues past the entry point with a call this harness
# can copy. The census says no tree in the validation set has one - libpng's tail is
# `png_image_finish_read`, whose pixel buffer needs a caller-supplied extent (B67) - so the
# oracle is exercised on a synthetic library built here, the same way B30's second assertion
# needs a synthetic tree. Everything below runs through the shipped `judge()`.
#
# TWO trees over ONE library, differing only in WHICH call the author appended. That is what
# makes this a control rather than a demonstration: the harness shape, the seeds, the library and
# the entry point are identical, so only the appended call's own behaviour can move the verdict.
LAB="$GATE/upward"
rm -rf "$LAB"
mkdir -p "$LAB/lib" "$LAB/seeds" "$LAB/scan/include" "$LAB/scan/fuzz" "$LAB/touch/include" \
    "$LAB/touch/fuzz"
cat >"$LAB/lib/mylib.h" <<'LAB_H'
#include <stddef.h>

struct mylib;
struct mylib_entry;

struct mylib *mylib_new(void);
int mylib_open_memory(struct mylib *m, const void *buff, size_t size);
int mylib_scan(struct mylib *m);
int mylib_touch(struct mylib *m);
int mylib_next_entry(struct mylib *m, struct mylib_entry **entry);
void mylib_free(struct mylib *m);
LAB_H
cat >"$LAB/lib/mylib.c" <<'LAB_C'
#include <stdlib.h>

#include "mylib.h"

/* B81. The entry belongs to the LIBRARY and is freed with it, which is what
   archive_read_next_header does - the harness owns only the slot it passes the address of. An
   entry the caller had to free would be a LeakSanitizer report inside the target, and stage 10
   proves this gate rejects those. */
struct mylib_entry {
    unsigned long tag;
};

struct mylib {
    const unsigned char *data;
    size_t size;
    size_t pos;
    unsigned long acc;
    struct mylib_entry entry;
};

/* Eight distinct blocks per switch, because the base harness has to clear oracle 3a's
   inter-seed divergence floor of 5 edges before there is anything to extend at all. */
#define STEP(n) static void step##n(struct mylib *m) { m->acc += n * 7u + 1u; }
STEP(0) STEP(1) STEP(2) STEP(3) STEP(4) STEP(5) STEP(6) STEP(7)
#define EXTRA(n) static void extra##n(struct mylib *m) { m->acc ^= n * 11u + 3u; }
EXTRA(0) EXTRA(1) EXTRA(2) EXTRA(3) EXTRA(4) EXTRA(5) EXTRA(6) EXTRA(7)
#define MARK(n) static void mark##n(struct mylib *m) { m->entry.tag += n * 13u + 5u; }
MARK(0) MARK(1) MARK(2) MARK(3) MARK(4) MARK(5) MARK(6) MARK(7)

struct mylib *mylib_new(void) { return (struct mylib *)calloc(1, sizeof(struct mylib)); }

int mylib_open_memory(struct mylib *m, const void *buff, size_t size)
{
    size_t i;
    const unsigned char *bytes = (const unsigned char *)buff;

    if (m == NULL || bytes == NULL || size == 0) { return -1; }
    m->data = bytes;
    m->size = size;
    m->pos = 1;
    for (i = 0; i < size && i < 24; i++) {
        switch (bytes[i] & 7u) {
        case 0: step0(m); break;
        case 1: step1(m); break;
        case 2: step2(m); break;
        case 3: step3(m); break;
        case 4: step4(m); break;
        case 5: step5(m); break;
        case 6: step6(m); break;
        default: step7(m); break;
        }
    }
    return 0;
}

int mylib_scan(struct mylib *m)
{
    size_t i;

    if (m == NULL || m->data == NULL) { return -1; }
    for (i = m->pos; i < m->size && i < 40; i++) {
        switch ((m->data[i] >> 5) & 7u) {
        case 0: extra0(m); break;
        case 1: extra1(m); break;
        case 2: extra2(m); break;
        case 3: extra3(m); break;
        case 4: extra4(m); break;
        case 5: extra5(m); break;
        case 6: extra6(m); break;
        default: extra7(m); break;
        }
    }
    return 0;
}

/* The same four blocks on every input, which is the whole point of the control: oracle 3b has
   to see one constant gain per seed and reject, where `mylib_scan` above varies. */
int mylib_touch(struct mylib *m)
{
    if (m == NULL) { return -1; }
    extra0(m);
    extra1(m);
    extra2(m);
    extra3(m);
    return 0;
}

/* The shape B81 unlocks: the library hands back a pointer to storage it owns. Its coverage has
   to depend on the input or oracle 3b would reject it for the same reason it rejects
   `mylib_touch`, which would make the acceptance below prove nothing about the out-param. */
int mylib_next_entry(struct mylib *m, struct mylib_entry **entry)
{
    size_t i;

    if (m == NULL || entry == NULL || m->data == NULL) { return -1; }
    for (i = m->pos; i < m->size && i < 32; i++) {
        switch ((m->data[i] >> 2) & 7u) {
        case 0: mark0(m); break;
        case 1: mark1(m); break;
        case 2: mark2(m); break;
        case 3: mark3(m); break;
        case 4: mark4(m); break;
        case 5: mark5(m); break;
        case 6: mark6(m); break;
        default: mark7(m); break;
        }
    }
    *entry = &m->entry;
    return 0;
}

void mylib_free(struct mylib *m) { free(m); }
LAB_C
lab_target() {
    cat >"$LAB/$1/fuzz/mylib_fuzzer.c" <<LAB_FUZZ
#include <stdint.h>

#include "mylib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct mylib *m = mylib_new();

    mylib_open_memory(m, data, size);
    mylib_$1(m);
    mylib_free(m);
    return 0;
}
LAB_FUZZ
    cp "$LAB/lib/mylib.h" "$LAB/$1/include/mylib.h"
}
lab_target scan
lab_target touch
mkdir -p "$LAB/entry/include" "$LAB/entry/fuzz"
cat >"$LAB/entry/fuzz/mylib_fuzzer.c" <<'LAB_ENTRY'
#include <stdint.h>

#include "mylib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct mylib *m = mylib_new();
    struct mylib_entry *entry = NULL;

    mylib_open_memory(m, data, size);
    mylib_next_entry(m, &entry);
    mylib_free(m);
    return 0;
}
LAB_ENTRY
cp "$LAB/lib/mylib.h" "$LAB/entry/include/mylib.h"
python3 - "$LAB/seeds" <<'LAB_SEEDS'
import sys, os
target = sys.argv[1]
for index in range(8):
    body = bytes((index * 37 + offset * 11) % 251 for offset in range(1 + index * 5))
    with open(os.path.join(target, f"seed-{index:02d}"), "wb") as handle:
        handle.write(body)
LAB_SEEDS

# The library is instrumented ONCE, by afl-clang-fast, and its edge IDs are baked into the
# object file. This is load-bearing and was measured: with an LTO-BITCODE archive
# `afl-clang-lto` re-instruments the whole program at every link, so appending one call to the
# harness renumbered every library edge - a parent's {13, 15, 32} became the child's
# {12, 14, 31, 35} for the same seed, sharing NOTHING - and the per-seed gains then varied with
# map size rather than with the input, which ACCEPTED a call doing identical work on every seed.
# B82. Kept in its OWN header and its own translation unit, because the trees above take their
# candidate list from `mylib.h` and two more exported functions there would move every ranking
# stages 11-13 depend on. One archive, two objects; the trees see one header each.
cat >"$LAB/lib/mylib_image.h" <<'IMAGE_H'
#include <stddef.h>

typedef struct mylib_image {
    unsigned int version;
    unsigned int width;
    unsigned int height;
    unsigned int acc;
} mylib_image;

/* B84. A record the header defines completely that the library also hands back through a
   GETTER's slot. Before B84 the slot alone marked it produced, so the harness could not declare
   one and every call taking it refused - which is what `png_const_colorp background` is. */
typedef struct mylib_color {
    unsigned char red;
    unsigned char green;
    unsigned char blue;
} mylib_color;

#define MYLIB_IMAGE_VERSION 1
#define MYLIB_IMAGE_SIZE(image) ((size_t)(image).width * (size_t)(image).height)
#define MYLIB_IMAGE_ROW_STRIDE(image) ((size_t)(image).width)
#define MYLIB_IMAGE_BUFFER_SIZE(image, row_stride) \
    ((size_t)(image).height * (size_t)(row_stride))

int mylib_begin_read(mylib_image *image, const void *buff, size_t size);
unsigned mylib_get_palette(mylib_image *image, mylib_color **palette);
int mylib_finish_read(mylib_image *image, const mylib_color *background, void *buffer,
                      int row_stride);
IMAGE_H
cat >"$LAB/lib/mylib_image.c" <<'IMAGE_C'
#include "mylib_image.h"

/* Eight distinct blocks, for the same reason mylib.c has them: the PARENT harness has to clear
   oracle 3a's inter-seed divergence floor of 5 edges before there is an extension to judge. The
   bodies must have a lasting effect - a first version added and subtracted the same constant,
   which the optimizer folded to nothing and identical-code-folding then merged into ONE edge. */
#define TINT(n) static void tint##n(mylib_image *i) { i->acc += n * 7u + 1u; }
TINT(0) TINT(1) TINT(2) TINT(3) TINT(4) TINT(5) TINT(6) TINT(7)

/* The header reads the dimensions and nothing else, exactly as png_image_begin_read_from_memory
   does, so MYLIB_IMAGE_SIZE states nothing until this has run. */
int mylib_begin_read(mylib_image *image, const void *buff, size_t size)
{
    const unsigned char *bytes = (const unsigned char *)buff;
    size_t at;

    if (image == NULL || image->version != MYLIB_IMAGE_VERSION) { return 0; }
    if (bytes == NULL || size < 2) { return 0; }
    for (at = 0; at < size && at < 24; at++) {
        switch (bytes[at] & 7u) {
        case 0: tint0(image); break;
        case 1: tint1(image); break;
        case 2: tint2(image); break;
        case 3: tint3(image); break;
        case 4: tint4(image); break;
        case 5: tint5(image); break;
        case 6: tint6(image); break;
        default: tint7(image); break;
        }
    }
    image->width = (unsigned int)bytes[0] + 1u;
    image->height = (unsigned int)bytes[1] + 1u;
    return 1;
}

/* Writes the WHOLE buffer on purpose. That is what makes this stage a measurement rather than a
   compile check: a harness that allocated anything less than MYLIB_IMAGE_SIZE bytes is a
   heap-buffer-overflow with the library's frames on top, which is the D12 crash B82 is built to
   avoid, and ASAN reports it here instead of in a real target. */
/* The palette belongs to the library and the caller only borrows a pointer to it, which is
   exactly `png_get_PLTE`. It is here so `mylib_color` is a record the library HANDS BACK. */
static mylib_color mylib_palette[4];

unsigned mylib_get_palette(mylib_image *image, mylib_color **palette)
{
    if (image == NULL || palette == NULL) { return 0; }
    *palette = mylib_palette;
    return 4u;
}

int mylib_finish_read(mylib_image *image, const mylib_color *background, void *buffer,
                      int row_stride)
{
    unsigned char *out = (unsigned char *)buffer;
    size_t total;
    size_t at;

    if (image == NULL || out == NULL) { return 0; }
    /* Read, so a harness passing a pointer to memory it never initialised is an ASAN report
       here rather than a quiet pass. NULL stays legal, exactly as libpng documents it. */
    if (background != NULL) { image->acc += background->red; }
    if (row_stride == 0) { row_stride = (int)MYLIB_IMAGE_ROW_STRIDE(*image); }
    total = (size_t)image->height * (size_t)row_stride;
    if (total == 0 || total > MYLIB_IMAGE_SIZE(*image)) { return 0; }
    for (at = 0; at < total; at++) {
        out[at] = (unsigned char)(at ^ (size_t)image->width);
    }
    switch (image->height & 7u) {
    case 0: out[0] ^= 1u; break;
    case 1: out[0] ^= 2u; break;
    case 2: out[0] ^= 4u; break;
    case 3: out[0] ^= 8u; break;
    case 4: out[0] ^= 16u; break;
    case 5: out[0] ^= 32u; break;
    case 6: out[0] ^= 64u; break;
    default: out[0] ^= 128u; break;
    }
    return 1;
}
IMAGE_C
mkdir -p "$LAB/sized/include" "$LAB/sized/fuzz"
cp "$LAB/lib/mylib_image.h" "$LAB/sized/include/mylib_image.h"
cat >"$LAB/sized/fuzz/mylib_image_fuzzer.c" <<'IMAGE_FUZZ'
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mylib_image.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mylib_image image;
    mylib_color background;
    void *buffer;

    memset(&image, 0, sizeof image);
    memset(&background, 0, sizeof background);
    image.version = MYLIB_IMAGE_VERSION;
    if (mylib_begin_read(&image, data, size)) {
        buffer = malloc(MYLIB_IMAGE_SIZE(image));
        if (buffer != NULL) {
            mylib_finish_read(&image, &background, buffer, 0);
            free(buffer);
        }
    }
    return 0;
}
IMAGE_FUZZ

(
    cd "$LAB/lib"
    env AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_QUIET=1 \
        afl-clang-fast -g -O1 -I. -c mylib.c -o mylib.o
    env AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_QUIET=1 \
        afl-clang-fast -g -O1 -I. -c mylib_image.c -o mylib_image.o
    llvm-ar rcs libmylib.a mylib.o mylib_image.o
) >"$LAB/build.log" 2>&1 || die "the synthetic oracle-3b library does not build"

lab_run() {
    "$LISDEX_BIN" harness "$LAB/$1" --out "$LAB/out-$1" --top 6 \
        --seeds "$LAB/seeds" --archive "$LAB/lib/libmylib.a" --driver "$DRIVER" \
        >"$LAB/$1.log" 2>&1
}

if lab_run scan && grep -q 'extended by 1 author call(s): mylib_scan' "$LAB/scan.log"; then
    pass "an appended call whose coverage depends on the input is ACCEPTED by oracle 3b"
else
    tail -6 "$LAB/scan.log" >&2
    fail "oracle 3b rejected an extension that genuinely reads the input"
fi
if grep -q '3b non-linear delta' "$LAB/scan.log"; then
    pass "and the oracle report names 3b as having run, which no other run in this gate can"
else
    fail "the extension was accepted without oracle 3b being reported as run"
fi
# The rejecting direction, and the first one this project has ever measured end to end.
lab_run touch
if grep -q 'every seed gained the same' "$LAB/touch.log"; then
    pass "$(grep -m1 'every seed gained the same' "$LAB/touch.log" | sed 's/^ *//' | cut -c1-108)"
else
    tail -6 "$LAB/touch.log" >&2
    fail "oracle 3b ACCEPTED a call that does identical work on every seed"
fi
# The parent must still stand: an extension is judged, and losing that judgement costs the depth,
# never the harness underneath it.
if grep -qE '^1 harness\(es\) survived' "$LAB/touch.log" \
    && ! grep -q 'extended by' "$LAB/touch.log"; then
    pass "the rejected extension left its parent standing as the survivor"
else
    fail "a rejected extension took the accepted harness underneath it with it"
fi
# The guard on the oracle itself. Same tree, same seeds, an LTO-bitcode archive: the two maps no
# longer share a numbering, and the oracle must REFUSE to give a verdict rather than read the
# renumbering as an input-dependent gain.
(
    cd "$LAB/lib"
    env AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_QUIET=1 \
        afl-clang-lto -g -O1 -I. -c mylib.c -o mylib_lto.o
    llvm-ar rcs libmylib_lto.a mylib_lto.o
) >>"$LAB/build.log" 2>&1 || die "the LTO variant of the synthetic library does not build"
"$LISDEX_BIN" harness "$LAB/touch" --out "$LAB/out-lto" --top 6 \
    --seeds "$LAB/seeds" --archive "$LAB/lib/libmylib_lto.a" --driver "$DRIVER" \
    >"$LAB/lto.log" 2>&1
if grep -q 'do not describe the same numbering' "$LAB/lto.log"; then
    pass "an LTO relink renumbers the map and the oracle refuses the verdict instead of guessing"
else
    tail -6 "$LAB/lto.log" >&2
    fail "the incomparable-map guard did not fire on a relinked LTO archive"
fi

log "stage 13/14: a library-filled out-param compiles and runs against the real header"
# B81. m3 asserts the PLAN says AddressOf and the emitted C declares the slot. Those are claims
# about text. This is the claim text cannot make: the same library, a third tree, and the appended
# `mylib_next_entry(ctx, &lisdex_filled)` has to type-check against the real header, link, and run
# clean on every seed. Reaching oracle 3b at all is the proof, because 3b sits behind compilation,
# execution and inter-seed divergence - a declaration that did not compile never gets here.
#
# The VERDICT is asserted here now, and B80's remaining half is what earns it. This stage used
# to accept either outcome because whether 3b could judge the relink at all depended on the
# numbering, which was a coin flip: the lab archive is PCGUARD but the harness was compiled by
# afl-clang-lto and linked ahead of the library, and either mismatch renumbers everything
# underneath. With the bench matching the archive's scheme AND linking the library first, the
# parent's map is contained in the child's on every seed, so an acceptance is a judgement rather
# than a link-order accident.
lab_run entry
if grep -q 'extended by 1 author call(s): mylib_next_entry' "$LAB/entry.log"; then
    pass "a step whose out-param the library fills is ACCEPTED by oracle 3b, verdict and all"
else
    tail -6 "$LAB/entry.log" >&2
    fail "the library-filled extension was not accepted by the oracle that judges it"
fi
# The isolating control for that verdict, and the reason it is a measurement rather than a
# tautology: the SAME tree, the SAME seeds, the SAME candidate, against the LTO build of the
# SAME library. Nothing about the harness changed, so if this one were also accepted the pass
# above would be telling us nothing about the numbering. Gut either the compiler switch or the
# link order and the two stop disagreeing.
"$LISDEX_BIN" harness "$LAB/entry" --out "$LAB/out-entry-lto" --top 6 \
    --seeds "$LAB/seeds" --archive "$LAB/lib/libmylib_lto.a" --driver "$DRIVER" \
    >"$LAB/entry-lto.log" 2>&1
if grep -q 'do not describe the same numbering' "$LAB/entry-lto.log" \
    && ! grep -q 'extended by 1 author call(s): mylib_next_entry' "$LAB/entry-lto.log"; then
    pass "and the same candidate against the LTO build of that library is refused, not accepted"
else
    tail -6 "$LAB/entry-lto.log" >&2
    fail "the acceptance above did not depend on the archive's numbering, so it proves nothing"
fi
# The declaration is the harness's own, and LSAN is what proves the ownership line is drawn in
# the right place: the entry belongs to the library, so nothing here frees it.
ENTRY_C="$(find "$LAB/out-entry" -maxdepth 2 -name '*.c' | head -1)"
if [ -n "$ENTRY_C" ] && grep -qE 'struct mylib_entry \* ?lisdex_filled = NULL;' "$ENTRY_C" \
    && grep -q 'mylib_next_entry(ctx, &lisdex_filled);' "$ENTRY_C" \
    && ! grep -q 'free(lisdex_filled)' "$ENTRY_C"; then
    pass "the harness declares the slot, passes its address, and frees nothing it does not own"
else
    fail "the emitted extension does not own its slot: \
$(grep -n 'lisdex_filled' "${ENTRY_C:-/dev/null}" | head -3)"
fi
# B80, the ACCEPTING direction of the same rule, and the reason stage 4's assertion is a control
# rather than a tautology. This lab's libmylib.a is an OBJECT archive, whose instrumentation was
# fixed when the library was built, so the total IS a measurement and must be published. Gut the
# archive check either way and exactly one of these two stages goes red.
if grep -q 'harness(es) survived the oracles, covering' "$LAB/entry.log"; then
    pass "and the same total IS published against an archive whose instrumentation is fixed"
else
    fail "a measurable cross-harness total was suppressed against an object archive"
fi

log "stage 14/14: a macro-stated capacity is allocated, is the right size, and is released"
# B82. m3 asserts the PLAN appends the call and the three controls each go red alone. Those are
# claims about text. This is the claim text cannot make: the appended
# `mylib_finish_read(&ctx, (void *)lisdex_sized)` has to type-check against the real header,
# link, and run clean on every seed with ASAN watching - and `mylib_finish_read` writes every
# byte MYLIB_IMAGE_SIZE claims, so a buffer even one byte short is a heap-buffer-overflow here
# rather than in a real target.
#
# The VERDICT is asserted here now, for the same reason stage 13 asserts one: B80's remaining
# half fixed the library's numbering, so 3b can judge this relink instead of refusing it.
#
# This one assertion carries what two used to. Acceptance sits behind compilation, execution
# and inter-seed divergence, so it is also the size claim this stage exists for: `mylib_finish_
# read` writes every byte `MYLIB_IMAGE_SIZE` promises, and a buffer one byte short is a
# heap-buffer-overflow, a missing free is a LeakSanitizer report and a missing NULL guard is a
# memset through NULL - each one an execution-oracle rejection, and none of them reaches an
# acceptance. The separate `crashed on seed` grep that used to make that claim is gone because
# it could no longer go red on its own, which is the inert-rule case doc 02 says to delete.
lab_run sized
if grep -q 'extended by 1 author call(s): mylib_finish_read' "$LAB/sized.log"; then
    pass "a buffer sized by the header's own macro is ACCEPTED, so every byte it claimed was writable"
else
    grep -m2 'mylib_finish_read' "$LAB/sized.log" >&2
    fail "the macro-sized extension was not accepted by the oracle that judges it"
fi
# The EXTENDED candidate by name, never `find | head -1`: the candidates directory also holds
# the two unextended variants, and reading one of those would assert nothing about the climb.
SIZED_C="$(find "$LAB/out-sized" -maxdepth 2 -name '*.up1.c' | head -1)"
if [ -n "$SIZED_C" ] \
    && grep -q 'size_t lisdex_sized_len = (size_t)(MYLIB_IMAGE_SIZE(ctx));' "$SIZED_C" \
    && grep -q 'malloc(lisdex_sized_len) : NULL;' "$SIZED_C" \
    && grep -q 'if (lisdex_sized == NULL) {' "$SIZED_C" \
    && grep -q 'free(lisdex_sized);' "$SIZED_C"; then
    pass "the emitted C states the size from the macro, bails on a failed or empty allocation, frees it"
else
    fail "the emitted C does not own the buffer it sized: \
$(grep -n 'lisdex_sized' "${SIZED_C:-/dev/null}" | head -4)"
fi
# The arity filter, in the SHIPPED pipeline rather than in a synthetic plan. The lab header
# ships `MYLIB_IMAGE_BUFFER_SIZE(image, row_stride)`, which is named for this parameter and
# sorts ahead of the record's own macro - applying it would mean inventing the stride.
if [ -n "$SIZED_C" ] && ! grep -q 'MYLIB_IMAGE_BUFFER_SIZE' "$SIZED_C"; then
    pass "and the two-argument macro named for the parameter was passed over, not given a zero"
else
    fail "a macro needing a number the caller owns reached the emitted harness"
fi
# B84, the step's own context. `mylib_color` is complete in the header AND handed back by
# `mylib_get_palette`'s slot, which is `png_get_PLTE`'s shape - before B84 that slot alone marked
# it produced and this parameter refused. The library READS the background, so a harness passing
# a pointer to memory it never initialised is an ASAN report rather than a quiet pass.
if [ -n "$SIZED_C" ] && grep -qE 'struct mylib_color ctx1;' "$SIZED_C" \
    && grep -q 'memset(&ctx1, 0, sizeof ctx1);' "$SIZED_C" \
    && grep -q 'mylib_finish_read(&ctx, &ctx1,' "$SIZED_C"; then
    pass "a step declares the context the entry point never took, and zeroes it before use"
else
    fail "the step did not declare its own context: \
$(grep -n 'ctx1\|mylib_finish_read' "${SIZED_C:-/dev/null}" | head -3)"
fi
# B84, the stated number. `row_stride` is a Config, and a Config pinned to zero is the invented
# constant an upward step may not copy - which is what stopped this climb after the buffer and
# the background both bound. `MYLIB_IMAGE_ROW_STRIDE(image)` is the header stating it, and it is
# the same stride `MYLIB_IMAGE_SIZE` is defined in terms of, so the two agree by construction.
if [ -n "$SIZED_C" ] && grep -q 'MYLIB_IMAGE_ROW_STRIDE(ctx));' "$SIZED_C" \
    && ! grep -qE 'mylib_finish_read\(.*, 0\);' "$SIZED_C"; then
    pass "and the stride comes from the header that states it, not from a pinned zero"
else
    fail "the step invented its Config rather than reading the macro: \
$(grep -n 'mylib_finish_read' "${SIZED_C:-/dev/null}" | head -2)"
fi

printf '\n'
if [ "$FAILURES" -eq 0 ]; then
    printf '[m4] M4 EXIT GATE PASSED - the none tier synthesized and self-verified a harness with no LLM\n'
    exit 0
fi
printf '[m4] M4 EXIT GATE FAILED: %d assertion(s)\n' "$FAILURES"
exit 1
