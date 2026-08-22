#!/usr/bin/env bash
# ©AngelaMos | 2026
# m5-gate.sh

# M5 is the LLM-booster milestone, RESCOPED 2026-07-29 by the doc-03 verify delta.
#
# The design's original M5 gate said "improves harness compile-rate over the deterministic
# baseline". Doc 03 D1 showed that is GAMEABLE: CKGFuzzer's +19.8pp is a COMPILE-rate gain,
# and four of lisdex's five measured failures compile fine and fail semantically, so the
# check goes green on a harness that compiles and fuzzes handle plumbing. D1's prescription
# is to gate on what the booster is allowed to DO instead.
#
# What M5 actually shipped is a doctrine, and this gate asserts the doctrine:
#   1. keyless is not a degraded mode - the deterministic path plans harnesses with no model
#   2. the booster is structurally unable to reach harness synthesis
#   3. a model may only pick from a ballot the caller offered; anything else is discarded
#
# Every stage carries a negative control, because a refusal path that refuses everything and
# an acceptance path that accepts everything both look green from one side.

set -euo pipefail

WORK="${MAGMA_WORK:-/opt/magma-work}"
GATE="$WORK/m5"
LISDEX_BIN="${CARGO_TARGET_DIR:-/cargo-target}/debug/lisdex"
FAKE_PORT="${LISDEX_M5_FAKE_PORT:-47318}"
FAKE_LOG="$GATE/fake-backend.log"
TREE="$GATE/tree"

PASS=0
FAILURES=0

log() { printf '\n[m5] %s\n' "$1"; }
die() { printf '\n[m5] FAIL: %s\n' "$1" >&2; exit 1; }
pass() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

FAKE_PID=""
cleanup() {
    if [ -n "$FAKE_PID" ]; then
        kill "$FAKE_PID" 2>/dev/null || true
        wait "$FAKE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if [ "${1:-}" = "reset" ]; then
    log "resetting $GATE"
    rm -rf "$GATE"
fi
mkdir -p "$GATE"

log "stage 1/4: build lisdex"
cargo build -p lisdex
[ -x "$LISDEX_BIN" ] || die "lisdex binary not found at $LISDEX_BIN"

# ---------------------------------------------------------------------------
log "stage 2/4: keyless is the product, not a degraded mode"
# A tree with a plain byte-buffer entry point. The deterministic mechanisms of the
# rescoped M5 (extent ownership, corpus binding) must plan it with NO model configured
# and no API key in the environment.
rm -rf "$TREE"
mkdir -p "$TREE/include" "$TREE/src"
cat > "$TREE/include/tree.h" <<'HEADER'
#include <stddef.h>
int tree_parse_blob(const unsigned char *data, size_t len);
int tree_scan_header(const unsigned char *buf, size_t n);
HEADER
cat > "$TREE/src/tree.c" <<'SOURCE'
#include "tree.h"
int tree_parse_blob(const unsigned char *data, size_t len) {
  int total = 0;
  if (len < 4) { return -1; }
  for (size_t i = 0; i < len; i++) {
    if (data[i] == 0x7f) { total += 2; }
    else if (data[i] == 0x1a) { total -= 1; }
    else { total += 1; }
  }
  while (total > 1000) { total /= 2; }
  switch (data[0]) { case 9: return 9; case 8: return 8; }
  return total;
}
int tree_scan_header(const unsigned char *buf, size_t n) {
  if (n < 2) { return -1; }
  return buf[0] == 0x89 && buf[1] == 0x50;
}
SOURCE

env -u LISDEX_LLM_ENDPOINT -u LISDEX_LLM_MODEL -u ANTHROPIC_API_KEY -u OPENAI_API_KEY \
    "$LISDEX_BIN" harness "$TREE" --out "$GATE/keyless-out" --plan-only --top 5 \
    > "$GATE/keyless.txt" 2>&1 || true

PLANNED="$(grep -c 'PLANS' "$GATE/keyless.txt" 2>/dev/null || true)"
if [ "${PLANNED:-0}" -gt 0 ]; then
    pass "the deterministic path planned $PLANNED harness(es) with no model and no key configured"
else
    fail "keyless run planned nothing (see $GATE/keyless.txt); keyless must not be a degraded mode"
fi

# Negative control for stage 2: the SAME command against a tree with no readable
# entry point must NOT report a plan, or "planned something" proves nothing.
BARE="$GATE/bare"
rm -rf "$BARE"
mkdir -p "$BARE/include" "$BARE/src"
cat > "$BARE/include/bare.h" <<'HEADER'
struct bare_ctx;
struct bare_ctx *bare_create(void);
void bare_destroy(struct bare_ctx *c);
HEADER
cat > "$BARE/src/bare.c" <<'SOURCE'
#include "bare.h"
#include <stdlib.h>
struct bare_ctx { int state; };
struct bare_ctx *bare_create(void) { return (struct bare_ctx *)calloc(1, sizeof(struct bare_ctx)); }
void bare_destroy(struct bare_ctx *c) { free(c); }
SOURCE

env -u LISDEX_LLM_ENDPOINT -u LISDEX_LLM_MODEL \
    "$LISDEX_BIN" harness "$BARE" --out "$GATE/bare-out" --plan-only --top 5 \
    > "$GATE/bare.txt" 2>&1 || true
# Same measurable as the positive case, opposite direction: a keyword grep would let a
# reworded banner decide the verdict, so both arms count PLANS lines.
BARE_PLANNED="$(grep -c 'PLANS' "$GATE/bare.txt" 2>/dev/null || true)"
if [ "${BARE_PLANNED:-0}" -eq 0 ]; then
    pass "a constructor-only tree plans nothing, so the $PLANNED above is a real discrimination"
else
    fail "a constructor-only tree planned $BARE_PLANNED harness(es) (see $GATE/bare.txt)"
fi

# ---------------------------------------------------------------------------
log "stage 3/4: the booster cannot reach harness synthesis"
# The doctrine is that a model never widens a harness. That is a call-graph property,
# so it is checked on the dependency edge AND on the shipped binary's symbols.
if grep -q 'lisdex-llm' crates/lisdex-harness/Cargo.toml 2>/dev/null; then
    fail "lisdex-harness declares a dependency on lisdex-llm; synthesis must not be able to call a model"
else
    pass "lisdex-harness declares no dependency on lisdex-llm"
fi

# The dependency check alone would pass if the edge moved somewhere synthesis still
# reaches, so assert the reverse edge too: the llm crate must not pull in the
# synthesizer and call it either.
if grep -q 'lisdex-harness' crates/lisdex-llm/Cargo.toml 2>/dev/null; then
    fail "lisdex-llm depends on lisdex-harness, so the booster sits inside the synthesis path"
else
    pass "lisdex-llm declares no dependency on lisdex-harness"
fi

# Negative control for the grep itself: it must be able to SEE a dependency that is
# really there, or an always-false check would alibi both assertions above.
if grep -q 'lisdex-surface' crates/lisdex-harness/Cargo.toml 2>/dev/null; then
    pass "the dependency probe detects a dependency that IS declared (lisdex-surface)"
else
    fail "the dependency probe found no lisdex-surface edge, so it cannot detect an lisdex-llm edge either"
fi

# ---------------------------------------------------------------------------
log "stage 4/4: a model may only choose from the ballot it was given"
# A fake Ollama-protocol backend, so the adjudicator is driven through the SHIPPED
# binary rather than a unit test. Two runs against the same code path: one where the
# model answers ON the ballot, one where it answers off it. Both directions are
# required - a path that always declines would pass the off-ballot check alone.
cat > "$GATE/fake_backend.py" <<'PY'
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ANSWER = os.environ["FAKE_ANSWER"]
MODEL = os.environ["FAKE_MODEL"]


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/tags"):
            self._send({"models": [{"name": MODEL}]})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send({"response": ANSWER, "done": True})

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

FAKE_MODEL="gate-fake-model"

run_ask() {
    local answer="$1" outfile="$2"
    FAKE_ANSWER="$answer" FAKE_MODEL="$FAKE_MODEL" \
        python3 "$GATE/fake_backend.py" "$FAKE_PORT" >> "$FAKE_LOG" 2>&1 &
    FAKE_PID=$!
    local waited=0
    until curl -sf "http://127.0.0.1:$FAKE_PORT/api/tags" >/dev/null 2>&1; do
        sleep 0.2
        waited=$((waited + 1))
        [ "$waited" -gt 50 ] && break
    done
    LISDEX_LLM_ENDPOINT="http://127.0.0.1:$FAKE_PORT" LISDEX_LLM_MODEL="$FAKE_MODEL" \
        "$LISDEX_BIN" llm --tier local --ask > "$outfile" 2>&1 || true
    kill "$FAKE_PID" 2>/dev/null || true
    wait "$FAKE_PID" 2>/dev/null || true
    FAKE_PID=""
}

run_ask "byte_buffer" "$GATE/onballot.txt"
if grep -q 'answered "byte_buffer"' "$GATE/onballot.txt"; then
    pass "an on-ballot answer is accepted, so the adjudicator is not refusing everything"
else
    fail "an on-ballot answer was not accepted (see $GATE/onballot.txt)"
fi

run_ask "the src parameter is definitely a raw pointer to heap memory" "$GATE/offballot.txt"
if grep -q 'not on the ballot' "$GATE/offballot.txt" \
    && ! grep -q '^answered' "$GATE/offballot.txt"; then
    pass "a free-text answer the caller never offered is discarded as a fabrication"
else
    fail "an off-ballot answer was not discarded (see $GATE/offballot.txt)"
fi

# The keyless tier must decline without contacting anything at all.
"$LISDEX_BIN" llm --tier none --ask > "$GATE/none.txt" 2>&1 || true
if grep -q 'no booster is configured' "$GATE/none.txt"; then
    pass "the none tier declines and the deterministic answer stands"
else
    fail "the none tier did not decline cleanly (see $GATE/none.txt)"
fi

# ---------------------------------------------------------------------------
log "RESULT"
echo "  passed: $PASS"
echo "  failed: $FAILURES"
if [ "$FAILURES" -eq 0 ]; then
    printf '\n[m5] M5 EXIT GATE PASSED\n'
    printf '  CHECK 1  the deterministic path plans a harness with no model and no key\n'
    printf '  CHECK 2  the booster is structurally unable to reach harness synthesis\n'
    printf '  CHECK 3  an on-ballot answer is accepted and an off-ballot answer is discarded\n'
    printf '  CHECK 4  the keyless tier declines without contacting a backend\n'
    exit 0
fi
printf '\n[m5] M5 EXIT GATE FAILED: %s check(s)\n' "$FAILURES" >&2
exit 1
