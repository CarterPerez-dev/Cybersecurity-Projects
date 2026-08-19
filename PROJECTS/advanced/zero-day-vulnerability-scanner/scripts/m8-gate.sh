#!/usr/bin/env bash
# ©AngelaMos | 2026
# m8-gate.sh

set -euo pipefail

# shellcheck source=scripts/magma-guard.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/magma-guard.sh"

WORK="${MAGMA_WORK:-/opt/magma-work}"
REPO="$WORK/libpng/repo"
OUT_ROOT="$WORK/out/libpng"
SEEDS="$WORK/libpng/corpus/libpng_read_fuzzer"
GATE="$WORK/m8"
FIXTURES="/work/crates/lisdex-triage/tests/fixtures"
FINDINGS="$GATE/findings"
DB="$GATE/lisdex.sqlite"
FIXTURE_DB="$GATE/fixtures.sqlite"
MIN_OUT="$GATE/minimized"
BUNDLES="$GATE/bundles"
STANDALONE="$GATE/standalone"
GATE_LOG="$GATE/stage.log"
LISDEX_BIN="${CARGO_TARGET_DIR:-/cargo-target}/debug/lisdex"
TARGET="$OUT_ROOT/afl/lisdex_libpng_read"
CMPLOG="$OUT_ROOT/cmplog/lisdex_libpng_read"
GATE_DURATION="${LISDEX_M8_DURATION:-600}"
PACKAGE="libpng"
FIXTURE_COUNT=19
IDENTITY_FRAMES=4
BUNDLE_FILES=5

FAILURES=0

log() { printf '\n[m8] %s\n' "$1"; }
die() { printf '\n[m8] FAIL: %s\n' "$1" >&2; exit 1; }
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

if [ "${1:-}" = "reset" ]; then
    log "resetting $GATE"
    rm -rf "$GATE"
fi

[ -d "$REPO" ] || die "magma libpng not fetched; run: just magma-libpng"
[ -x "$TARGET" ] || die "magma libpng not built; run: just magma-libpng"
require_harness_current "$OUT_ROOT"
[ -x "$CMPLOG" ] || die "cmplog target missing at $CMPLOG"
[ -d "$SEEDS" ] || die "seed corpus missing at $SEEDS"
[ -d "$FIXTURES" ] || die "captured report fixtures missing at $FIXTURES"

mkdir -p "$GATE"

log "stage 1/8: build lisdex"
cargo build -p lisdex
[ -x "$LISDEX_BIN" ] || die "lisdex binary not found at $LISDEX_BIN"

log "stage 2/8: the report layer answers for itself"
# The end-to-end checks below all read one rendered advisory, so a single corpus-wide
# assertion cannot tell the provenance guard from the refusal rendering from the bundle
# writer. Each owns tests that no other mechanism can satisfy.
if cargo test -p lisdex-report > "$GATE_LOG" 2>&1; then
    pass "lisdex-report unit and integration tests"
else
    fail "lisdex-report tests (see $GATE_LOG)"
fi

log "stage 3/8: a crash that cannot be keyed is never named as a bug"
rm -f "$FIXTURE_DB"
sqlite3 "$FIXTURE_DB" <<'SQL'
CREATE TABLE campaigns (id INTEGER PRIMARY KEY, target TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE crashes (
    id INTEGER PRIMARY KEY,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    input BLOB NOT NULL,
    sanitizer_report TEXT NOT NULL,
    stack_hash TEXT
);
INSERT INTO campaigns (id, target, status) VALUES (1, 'captured-reports', 'completed');
SQL
for fixture in "$FIXTURES"/*.txt; do
    sqlite3 "$FIXTURE_DB" \
        "INSERT INTO crashes (campaign_id, input, sanitizer_report, stack_hash)
         VALUES (1, zeroblob(1), CAST(readfile('$fixture') AS TEXT), NULL);"
done
LOADED="$(sqlite3 "$FIXTURE_DB" 'SELECT COUNT(*) FROM crashes;')"
if [ "$LOADED" -eq "$FIXTURE_COUNT" ]; then
    pass "$LOADED captured reports loaded as a campaign the shipped binary reads"
else
    fail "expected $FIXTURE_COUNT captured reports, loaded $LOADED"
fi

"$LISDEX_BIN" advisory --db "$FIXTURE_DB" --campaign 1 --package "$PACKAGE" \
    --format json > "$GATE/fixture-advisories.json" 2> "$GATE/fixture-advisories.err" || true
# These captures are verbatim ASAN output taken with symbolize=0, so every frame is a bare
# module offset. Keying one would give every crash in that module the same identity, so the
# triage layer refuses, and an advisory that cannot name one bug is not written at all.
if [ "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$GATE/fixture-advisories.json")" -eq 0 ] \
    && grep -q "$FIXTURE_COUNT crashes carry no dedup key" "$GATE/fixture-advisories.err"; then
    pass "$FIXTURE_COUNT unsymbolized captures produce no advisory, and the binary says why"
else
    fail "an advisory was drafted for a crash that could only be keyed on a module offset"
fi

log "stage 4/8: re-find a magma bug (${GATE_DURATION}s)"
rm -rf "$FINDINGS" "$DB"
"$LISDEX_BIN" fuzz --target "$TARGET" --cmplog "$CMPLOG" --seeds "$SEEDS" \
    --findings "$FINDINGS" --db "$DB" --duration "$GATE_DURATION" \
    > "$GATE_LOG" 2>&1 || die "campaign failed (see $GATE_LOG)"

BUGS="$("$LISDEX_BIN" crashes --db "$DB" --campaign 1 2>/dev/null | grep -c 'stack_hash' || true)"
if [ "$BUGS" -gt 0 ]; then
    pass "campaign persisted $BUGS crash(es)"
else
    fail "campaign found no crashes; the gate has nothing to report on"
fi

# The two stage-7 controls hand lisdex a tree provenance in a hand-built database, so they
# check what lisdex DOES with the value, never whether it can MEASURE one. This reads the
# column lisdex wrote for itself, off the real magma binary it just fuzzed. Without it, a
# detector hardwired to 'field' passes the whole gate, because every crash above carries a
# canary frame and the frame arm covers for it.
STORED_TREE="$(sqlite3 "$DB" 'SELECT tree_provenance FROM campaigns WHERE id = 1;' || true)"
if [ "$STORED_TREE" = "benchmark" ]; then
    pass "lisdex measured the target itself and recorded the campaign tree as benchmark"
else
    fail "the campaign against a magma build recorded tree_provenance='$STORED_TREE', not 'benchmark'"
fi

log "stage 5/8: minimize, then bundle"
rm -rf "$MIN_OUT" "$BUNDLES" "$STANDALONE"
"$LISDEX_BIN" minimize --db "$DB" --campaign 1 --target "$TARGET" --out "$MIN_OUT" \
    > "$GATE/minimize.log" 2>&1 || die "minimize failed (see $GATE/minimize.log)"
MINIMIZED="$(find "$MIN_OUT" -name '*.min' | wc -l)"
if [ "$MINIMIZED" -gt 0 ]; then
    pass "$MINIMIZED identity-verified reproducer(s) written"
else
    fail "no .min reproducer survived identity verification"
fi

"$LISDEX_BIN" bundle --db "$DB" --campaign 1 --package "$PACKAGE" \
    --minimized "$MIN_OUT" --out "$BUNDLES" > "$GATE/bundle.log" 2>&1 \
    || die "bundle failed (see $GATE/bundle.log)"
"$LISDEX_BIN" advisory --db "$DB" --campaign 1 --package "$PACKAGE" \
    --out "$STANDALONE" > /dev/null 2>&1 || die "standalone advisory failed"

BUNDLE_DIRS="$(find "$BUNDLES" -mindepth 1 -maxdepth 1 -type d | sort)"
BUNDLE_COUNT="$(printf '%s\n' "$BUNDLE_DIRS" | grep -c . || true)"
if [ "$BUNDLE_COUNT" -gt 0 ]; then
    pass "$BUNDLE_COUNT bundle(s) written"
else
    fail "no bundle written"
fi

log "stage 6/8: every bundle is complete, refuses disclosure, and states what it declined"
for dir in $BUNDLE_DIRS; do
    stem="$(basename "$dir")"
    present="$(find "$dir" -maxdepth 1 -type f -size +0c | wc -l)"
    if [ "$present" -eq "$BUNDLE_FILES" ]; then
        pass "$stem: $BUNDLE_FILES non-empty files"
    else
        fail "$stem: $present non-empty files, expected $BUNDLE_FILES"
    fi

    if cmp -s "$dir/poc" "$MIN_OUT/$stem.min"; then
        pass "$stem: the bundled reproducer is byte-identical to the verified minimized input"
    else
        fail "$stem: the bundled reproducer is NOT the file minimize verified"
    fi

    python3 - "$dir/advisory.json" <<'PY' && pass "$stem: the machine-readable advisory refuses what it cannot establish" || fail "$stem: advisory.json states something lisdex never measured"
import json, sys
d = json.load(open(sys.argv[1]))
ghsa = d["ghsa"]
assert ghsa["ecosystem"] == "other", ghsa["ecosystem"]
for field in ("vulnerable_version_range", "patched_versions", "cvss_vector_string", "cve_id"):
    assert ghsa[field] is None, f"{field} was invented: {ghsa[field]}"
assert len(d["declined"]) == 3, d["declined"]
assert d["disclosable"] is False, "a magma canary finding must never be disclosable"
assert d["provenance"] == "synthetic_benchmark", d["provenance"]
PY

    if grep -q 'DO NOT FILE THIS ADVISORY' "$dir/advisory.md"; then
        pass "$stem: the advisory leads with the refusal, and the bundle did not launder it away"
    else
        fail "$stem: a planted benchmark bug was packaged with no refusal"
    fi

    if grep -q 'Anyone with admin permissions' "$dir/advisory.md"; then
        fail "$stem: an undisclosable finding carries filing instructions"
    else
        pass "$stem: no filing route is offered for a finding that must not be filed"
    fi

    if grep -qE 'CVSS:3\.1/|CVSS:4\.0/' "$dir/advisory.md"; then
        fail "$stem: the advisory states a CVSS vector it cannot derive from a crash"
    else
        pass "$stem: no CVSS vector is asserted"
    fi

    if grep -q 'NOT ESTABLISHED' "$dir/advisory.md"; then
        pass "$stem: declined fields are named in the page, not silently dropped"
    else
        fail "$stem: the advisory declines fields without saying so"
    fi

    if grep -q 'reproduce.sh' "$STANDALONE/$stem.md"; then
        fail "$stem: the standalone advisory points at a script that was never written beside it"
    else
        pass "$stem: the standalone advisory claims no files it did not ship"
    fi
done

log "stage 7/8: the same crash without benchmark frames IS disclosable"
# Everything above asserts NOT DISCLOSABLE, which a guard hardwired to refuse everything
# would also satisfy. This takes one report the campaign really produced and removes only
# the benchmark instrumentation from it - the canary runtime frame, and the MAGMA_ prefix
# the harness patcher adds - leaving the same fault in the same functions as the library
# ships them. If that does not come back disclosable, the mark means nothing.
CONTROL_DB="$GATE/control.sqlite"
rm -f "$CONTROL_DB"
sqlite3 "$CONTROL_DB" <<'SQL'
CREATE TABLE campaigns (id INTEGER PRIMARY KEY, target TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE crashes (
    id INTEGER PRIMARY KEY,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    input BLOB NOT NULL,
    sanitizer_report TEXT NOT NULL,
    stack_hash TEXT
);
INSERT INTO campaigns (id, target, status) VALUES (1, 'libpng', 'completed');
SQL
FIRST_BUNDLE="$(printf '%s\n' "$BUNDLE_DIRS" | head -1)"
grep -v 'in magma_log ' "$FIRST_BUNDLE/report.txt" | sed 's/ in MAGMA_/ in /' > "$GATE/control-report.txt"
if grep -qE 'magma_log|MAGMA_' "$GATE/control-report.txt"; then
    fail "the control still carries benchmark instrumentation, so it controls nothing"
else
    pass "the control report retains the fault and drops only the benchmark frames"
fi
sqlite3 "$CONTROL_DB" \
    "INSERT INTO crashes (campaign_id, input, sanitizer_report, stack_hash)
     VALUES (1, zeroblob(1), CAST(readfile('$GATE/control-report.txt') AS TEXT), NULL);"
"$LISDEX_BIN" advisory --db "$CONTROL_DB" --campaign 1 --package "$PACKAGE" \
    --format json > "$GATE/control-advisories.json" 2>/dev/null || true
python3 - "$GATE/control-advisories.json" <<'PY' && pass "the de-instrumented crash drafts an advisory and it IS disclosable" || fail "the guard refuses a crash with no benchmark frames in it, so NOT DISCLOSABLE is a constant"
import json, sys
documents = json.load(open(sys.argv[1]))
assert documents, "no advisory drafted from the de-instrumented report"
for d in documents:
    assert d["disclosable"] is True, f"{d['dedup_key']} still undisclosable"
    assert d["provenance"] == "field", d["provenance"]
print(f"    {len(documents)} advisory, disclosable, provenance field")
PY
if grep -q 'Anyone with admin permissions' "$GATE/control-advisories.json" \
    || "$LISDEX_BIN" advisory --db "$CONTROL_DB" --campaign 1 --package "$PACKAGE" 2>/dev/null \
        | grep -q 'Anyone with admin permissions'; then
    pass "and it carries the filing route the undisclosable findings withhold"
else
    fail "a disclosable advisory was rendered without a filing route"
fi

# The control above proves the FRAME arm is not hardwired. It says nothing about the TREE
# arm. Magma forward-ports real historical CVEs into current source, so a benchmark tree
# holds genuine already-fixed vulnerabilities a crash can reach without ever touching a
# canary - and that crash carries no benchmark frame to find. This control is the SAME
# report bytes as the one above, attributed to a campaign whose tree lisdex recorded as a
# benchmark. The tree column is the only difference between them, so neither can alibi the
# other.
TREE_DB="$GATE/control-tree.sqlite"
rm -f "$TREE_DB"
sqlite3 "$TREE_DB" <<'SQL'
CREATE TABLE campaigns (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    tree_provenance TEXT
);
CREATE TABLE crashes (
    id INTEGER PRIMARY KEY,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    input BLOB NOT NULL,
    sanitizer_report TEXT NOT NULL,
    stack_hash TEXT
);
INSERT INTO campaigns (id, target, status, tree_provenance)
VALUES (1, 'libpng', 'completed', 'benchmark');
SQL
sqlite3 "$TREE_DB" \
    "INSERT INTO crashes (campaign_id, input, sanitizer_report, stack_hash)
     VALUES (1, zeroblob(1), CAST(readfile('$GATE/control-report.txt') AS TEXT), NULL);"
"$LISDEX_BIN" advisory --db "$TREE_DB" --campaign 1 --package "$PACKAGE" \
    --format json > "$GATE/control-tree-advisories.json" 2>/dev/null || true
python3 - "$GATE/control-tree-advisories.json" <<'PY' && pass "the same de-instrumented report from a BENCHMARK tree is refused on the tree alone" || fail "a benchmark tree did not refuse disclosure, so a forward-ported CVE could be filed as a new bug"
import json, sys
documents = json.load(open(sys.argv[1]))
assert documents, "no advisory drafted from the de-instrumented report"
for d in documents:
    assert d["disclosable"] is False, f"{d['dedup_key']} is disclosable from a benchmark tree"
    assert d["provenance"] == "synthetic_benchmark", d["provenance"]
print(f"    {len(documents)} advisory, NOT disclosable, provenance synthetic_benchmark")
PY

log "stage 8/8: the shipped reproducer still crashes, and the bundles do not all carry the same bug"
SIGNATURES="$GATE/signatures.txt"
: > "$SIGNATURES"
for dir in $BUNDLE_DIRS; do
    stem="$(basename "$dir")"
    output="$GATE/$stem.replay"
    ( cd "$dir" && ./reproduce.sh "$TARGET" ) > "$output" 2>&1 || true
    if grep -qE 'ERROR: (AddressSanitizer|LeakSanitizer)' "$output"; then
        pass "$stem: the emitted reproduce.sh reproduces the fault on the shipped PoC"
    else
        fail "$stem: the emitted reproduce.sh did NOT reproduce (see $output)"
    fi
    grep -oE '\(/[^ ]+\+0x[0-9a-f]+\)' "$output" | head -"$IDENTITY_FRAMES" \
        | tr '\n' ' ' >> "$SIGNATURES"
    printf '\n' >> "$SIGNATURES"
done

DISTINCT="$(sort -u "$SIGNATURES" | grep -c . || true)"
if [ "$DISTINCT" -eq "$BUNDLE_COUNT" ]; then
    pass "all $BUNDLE_COUNT bundle(s) replay to distinct top-$IDENTITY_FRAMES signatures, so no two ship the same bug"
else
    fail "$BUNDLE_COUNT bundle(s) replayed to only $DISTINCT distinct signature(s)"
fi

log "RESULT"
if [ "$FAILURES" -eq 0 ]; then
    printf '\n[m8] M8 EXIT GATE PASSED\n'
    printf '  CHECK 1  a re-found magma bug yields a complete advisory and reproducer bundle\n'
    printf '  CHECK 2  that bundle is stamped NOT DISCLOSABLE, and carries no filing route\n'
    printf '  CHECK 3  real captured errors are still disclosable, so the mark is not a constant\n'
    printf '  CHECK 4  the shipped reproducer replays the fault it names\n'
    printf '  CHECK 5  a benchmark TREE refuses disclosure on its own, with no canary frame to read\n'
    exit 0
fi
printf '\n[m8] M8 EXIT GATE FAILED: %s check(s)\n' "$FAILURES" >&2
exit 1
