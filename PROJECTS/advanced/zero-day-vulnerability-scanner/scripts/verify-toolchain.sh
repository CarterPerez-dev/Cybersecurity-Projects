#!/usr/bin/env bash
# ©AngelaMos | 2026
# verify-toolchain.sh

set -uo pipefail

EXPECTED_MAGMA_COMMIT="75d1ae7b180443a778b8830c79176ca5f93642ac"
EXPECTED_RUST="1.97.0"
EXPECTED_AFL="5.02c"
EXPECTED_LIBPNG_CANARIES=7
MIN_ASAN_SYMBOLS=100
FUZZ_SMOKE_TIMEOUT_SECS=120
CORE_PATTERN_PATH=/proc/sys/kernel/core_pattern
FAILURES=0
WARNINGS=0

ok() {
    printf '  PASS  %s\n' "$1"
}

fail() {
    printf '  FAIL  %s\n' "$1"
    FAILURES=$((FAILURES + 1))
}

warn() {
    printf '  WARN  %s\n' "$1"
    WARNINGS=$((WARNINGS + 1))
}

section() {
    printf '\n== %s ==\n' "$1"
}

require_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        ok "$1 -> $(command -v "$1")"
    else
        fail "$1 not on PATH"
    fi
}

section "Fuzzing engine (AFL++)"
for c in afl-fuzz afl-clang-lto afl-clang-lto++ afl-clang-fast afl-cmin afl-tmin afl-showmap; do
    require_cmd "$c"
done
AFL_BANNER="$(afl-fuzz -h 2>&1 || true)"
AFL_VERSION="$(printf '%s' "$AFL_BANNER" | grep -oE 'afl-fuzz\+\+[0-9][0-9.]*[a-z]*' | head -1)"
if [ "$AFL_VERSION" = "afl-fuzz++$EXPECTED_AFL" ]; then
    ok "afl-fuzz version pinned: $AFL_VERSION"
elif [ -n "$AFL_VERSION" ]; then
    fail "afl-fuzz is $AFL_VERSION, expected afl-fuzz++$EXPECTED_AFL"
else
    fail "afl-fuzz did not report a recognizable version banner"
fi

section "Host crash-reporting environment"
CORE_PATTERN="$(cat "$CORE_PATTERN_PATH" 2>/dev/null || true)"
printf '  INFO  %s = %s\n' "$CORE_PATTERN_PATH" "${CORE_PATTERN:-unreadable}"
case "$CORE_PATTERN" in
    \|*)
        warn "core_pattern pipes cores to a userspace handler; afl-fuzz can mis-classify"
        warn "crashes as hangs and lose them. This container sets"
        warn "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1, so the degradation is SILENT at runtime."
        warn "Remedy (host, needs root): echo core > $CORE_PATTERN_PATH"
        ;;
    *)
        ok "core_pattern is not piped to a userspace handler"
        ;;
esac

section "LLVM toolchain (afl-clang-lto requirements)"
require_cmd clang
require_cmd clang++
for c in llvm-ar llvm-ranlib llvm-as llvm-nm ld.lld; do
    require_cmd "$c"
done
printf '  INFO  %s\n' "$(clang --version | head -1)"

section "AFL++ driver + libclang"
if [ -f "${LISDEX_AFL_DRIVER:-/usr/local/lib/afl/libAFLDriver.a}" ]; then
    ok "libAFLDriver.a present at ${LISDEX_AFL_DRIVER:-/usr/local/lib/afl/libAFLDriver.a}"
else
    fail "libAFLDriver.a missing"
fi
LIBCLANG="$(find /usr/lib -name 'libclang.so*' -o -name 'libclang-*.so*' 2>/dev/null | head -1)"
if [ -n "$LIBCLANG" ]; then
    ok "libclang present at $LIBCLANG"
else
    fail "libclang.so missing (clang-sys will not link in M3)"
fi

section "Rust toolchain"
require_cmd cargo
require_cmd rustc
if rustc --version | grep -q "$EXPECTED_RUST"; then
    ok "rustc pinned: $(rustc --version)"
else
    fail "rustc is $(rustc --version), expected $EXPECTED_RUST"
fi
if cargo clippy --version >/dev/null 2>&1; then
    ok "clippy: $(cargo clippy --version)"
else
    fail "clippy missing"
fi
if cargo fmt --version >/dev/null 2>&1; then
    ok "rustfmt: $(cargo fmt --version)"
else
    fail "rustfmt missing"
fi

section "Magma benchmark source"
MAGMA_ROOT="${MAGMA_ROOT:-/opt/magma}"
if [ -d "$MAGMA_ROOT" ]; then
    ACTUAL="$(git -C "$MAGMA_ROOT" rev-parse HEAD 2>/dev/null)"
    if [ "$ACTUAL" = "$EXPECTED_MAGMA_COMMIT" ]; then
        ok "magma pinned at $ACTUAL"
    else
        fail "magma at $ACTUAL, expected $EXPECTED_MAGMA_COMMIT"
    fi
    PNG_BUGS="$(ls "$MAGMA_ROOT/targets/libpng/patches/bugs/" 2>/dev/null | wc -l)"
    if [ "$PNG_BUGS" -eq 7 ]; then
        ok "libpng canary patches: $PNG_BUGS (PNG001-PNG007)"
    else
        fail "libpng canary patches: $PNG_BUGS, expected 7"
    fi
    for f in magma/src/canary.c magma/src/storage.c magma/build.sh magma/apply_patches.sh \
             targets/libpng/build.sh targets/libpng/fetch.sh; do
        if [ -f "$MAGMA_ROOT/$f" ]; then
            ok "magma file present: $f"
        else
            fail "magma file missing: $f"
        fi
    done
else
    fail "magma source tree missing at $MAGMA_ROOT"
fi

section "End-to-end spine: afl-clang-lto + ASAN + cmplog + afl-fuzz"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/planted.c" <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <string.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char buf[8];
    if (size >= 4 && memcmp(data, "BOOM", 4) == 0) {
        memcpy(buf, data, size);
        return buf[0];
    }
    return 0;
}
EOF

export AR=llvm-ar RANLIB=llvm-ranlib AS=llvm-as NM=llvm-nm
DRIVER="${LISDEX_AFL_DRIVER:-/usr/local/lib/afl/libAFLDriver.a}"

if AFL_USE_ASAN=1 afl-clang-lto -O0 -g "$WORK/planted.c" "$DRIVER" \
        -o "$WORK/harness" >"$WORK/build.log" 2>&1; then
    ok "afl-clang-lto built ASAN harness"
else
    fail "afl-clang-lto ASAN build failed"
    tail -20 "$WORK/build.log"
fi

if AFL_USE_ASAN=1 AFL_LLVM_CMPLOG=1 afl-clang-lto -O0 -g "$WORK/planted.c" "$DRIVER" \
        -o "$WORK/harness_cmplog" >"$WORK/build_cmplog.log" 2>&1; then
    ok "afl-clang-lto built cmplog harness"
else
    fail "afl-clang-lto cmplog build failed"
    tail -20 "$WORK/build_cmplog.log"
fi

if [ -f "$WORK/harness" ]; then
    ASAN_SYMS="$(nm "$WORK/harness" 2>/dev/null | grep -c asan)"
    AFL_SYMS="$(nm "$WORK/harness" 2>/dev/null | grep -cE '__afl_area_ptr|__sanitizer_cov')"
    if [ "$ASAN_SYMS" -gt 100 ]; then
        ok "ASAN instrumentation present in binary ($ASAN_SYMS symbols)"
    else
        fail "ASAN instrumentation absent or thin ($ASAN_SYMS symbols)"
    fi
    if [ "$AFL_SYMS" -gt 0 ]; then
        ok "AFL coverage instrumentation present in binary ($AFL_SYMS symbols)"
    else
        fail "AFL coverage instrumentation absent ($AFL_SYMS symbols)"
    fi
fi

if [ -f "$WORK/harness" ] && [ -f "$WORK/harness_cmplog" ]; then
    mkdir -p "$WORK/in" "$WORK/out"
    printf 'AAAA' > "$WORK/in/seed"
    AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_NO_UI=1 AFL_BENCH_UNTIL_CRASH=1 \
        timeout 120 afl-fuzz -i "$WORK/in" -o "$WORK/out" -m none \
        -c "$WORK/harness_cmplog" -- "$WORK/harness" >"$WORK/fuzz.log" 2>&1
    CRASH="$(find "$WORK/out" -path '*/crashes/id:*' 2>/dev/null | head -1)"
    if [ -n "$CRASH" ]; then
        ok "afl-fuzz found the planted bug: $(basename "$CRASH")"
        REPRO_OUT="$("$WORK/harness" "$CRASH" 2>&1 || true)"
        SANI="$(printf '%s' "$REPRO_OUT" | grep -oE 'AddressSanitizer: [a-z-]+' | head -1)"
        if [ -n "$SANI" ]; then
            ok "crash reproduces under ASAN: $SANI"
        else
            fail "crash did not reproduce with an ASAN report"
            printf '%s\n' "$REPRO_OUT" | head -10
        fi
    else
        fail "afl-fuzz did not find the planted bug within the time budget"
        tail -25 "$WORK/fuzz.log"
    fi
fi

section "Result"
if [ "$FAILURES" -eq 0 ]; then
    printf 'TOOLCHAIN VERIFIED: all checks passed\n'
    exit 0
fi
printf 'TOOLCHAIN BROKEN: %d check(s) failed\n' "$FAILURES"
exit 1
