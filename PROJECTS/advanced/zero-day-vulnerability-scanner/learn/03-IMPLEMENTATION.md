# Implementation

This walks the pipeline in the order a campaign actually runs it. Code is quoted
by function and file, never by line number, because line numbers rot.

## File Structure

```
crates/lisdex-surface/
  headers.rs      which files are headers worth parsing
  extract.rs      libclang: declarations out of a translation unit
  signature.rs    does this parameter list look like (bytes, length)?
  complexity.rs   how much work is behind this entry point
  rank.rs         the scoring function
  ladder.rs       ordering entry points into a call sequence
  surface.rs      analyze(), the thing the CLI calls

crates/lisdex-harness/
  search.rs       try candidates, keep survivors
  synth.rs        build a harness body from a signature
  emit.rs         write the .c file
  compile.rs      build and link it against the instrumented archive
  oracle.rs       the four judgements
  verify.rs       Verdict, Corpus, Toolchain, Bench

crates/lisdex-fuzz/
  runner.rs       afl-fuzz invocation, instances, harvest, reproduce
  dictionary.rs   pick dictionaries from seed magic bytes
  plot.rs         parse plot_data
  stats.rs        parse fuzzer_stats
  corpus.rs       afl-cmin
  minimize.rs     afl-tmin
```

## Stage 1: Finding the Entry Points

### Why libclang and not tree-sitter

The original design called for a tree-sitter pre-filter with libclang behind it.
That was measured and abandoned. On real `png.h`, tree-sitter-c returns **719
ERROR nodes and 0 functions**, where libclang returns **256 functions with 0
diagnostics**. The pre-filter deleted 24.3% of all true entry points across the
corpus, and 100% of libpng's.

libclang was also 1.9 to 3.4 times *faster* on real parser headers, and used
75 MB rather than 380 MB. The two-phase design was slower, heavier, and wrong.

### The trap that halves your results silently

Parsing a translation unit without a compilation database still returns `Ok`. It
just resolves fewer types, so fewer parameters look like buffers. Buffer
detection drops by about half and nothing tells you.

`SurfaceOptions::parse_options` builds the arguments, and `analyze` gates on
diagnostics severity rather than on the absence of an error:

```rust
// a translation unit that produced Error or Fatal diagnostics is not
// trustworthy, even though libclang happily returned a cursor for it
```

Another libclang trap: `is_in_main_file()` returns **0 of 256** functions on
macro-heavy headers, because the declarations arrive through includes. Never
filter on it.

### What counts as an entry point

`signature.rs` looks for the shapes that eat untrusted bytes:

```c
int decode(const unsigned char *data, size_t len);   /* DirectBuffer */
int decode(const char *buf, int n);                  /* DirectBuffer */
```

The buffer-and-length pair is the easy case. The hard case is the one that
matters for real libraries:

```c
void png_set_read_fn(png_structp png_ptr, png_voidp io_ptr,
                     png_rw_ptr read_data_fn);       /* callback-driven */
```

`png_read_info`, `TIFFClientOpen`, and `opj_read_header` all rank #1 for their
libraries and **none of them is visible to buffer-and-length matching**. They
take a context and a callback. A detector without a callback-registration rule
misses the most important entry point in three of the five reference libraries,
which is why `signature.rs` has one.

### Ranking

`rank::rank` scores each candidate. The signals:

- **Signature shape.** A direct buffer outranks a callback, which outranks
  anything needing an opaque context.
- **Complexity behind it.** `complexity::complexity_score` estimates how much
  code the entry point reaches. A deep parser is a better target than a getter.
- **Argument simplicity.** `complexity::arg_simplicity` penalizes every extra
  context argument the harness would have to construct.
- **Novelty.** A static signal standing in for "has this been fuzzed before",
  because runtime coverage is not available at cold start.

The output is what `lisdex surface` prints:

```
  1. png_read                0.4350  DirectBuffer  undiscovered=0 accumulated=0
  2. png_decode              0.4090  DirectBuffer  undiscovered=0 accumulated=0
```

## Stage 2: Synthesizing a Harness

`synth.rs` builds a harness body from the signature; `emit.rs` writes it. The
generated file is a libFuzzer-style entry point so it can link against
`libAFLDriver.a`:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    png_read(data, size);
    return 0;
}
```

That is the easy case. The interesting part is what happens when the harness is
wrong, which is most of the time.

### The four oracles

A harness that compiles is not a harness that works. `oracle.rs` runs four
independent judgements, and a candidate has to survive all of them.

**1. Execution.** `judge_execution` rejects a harness that crashes on valid
input, hangs, or exits non-zero. If your harness segfaults on a good PNG, every
crash the campaign finds is your bug, not libpng's.

**2. Stderr.** `judge_stderr` rejects a harness whose output shows it rejected
the input outright. A harness that prints "unsupported format" for every seed is
reading the bytes and throwing them away.

**3. Inter-seed divergence.** `judge_inter_seed_divergence` requires different
seeds to produce *different* coverage. This is the one that catches the most
common failure: a harness that reads none of its input.

```
seed A -> 1,204 edges
seed B -> 1,204 edges     identical coverage across different inputs
seed C -> 1,204 edges     => the harness is not reading the bytes
```

**4. Novelty.** The candidate has to reach edges an empty harness does not, so a
harness that only exercises setup and teardown is culled.

### Why refusal is the right default

A harness that constructs a half-initialized `png_struct` and fuzzes it will find
bugs in lisdex's initialization, not in libpng. So when lisdex cannot establish
an argument, it refuses the candidate and says which rule refused it.

Refusal is also how the project measures itself. An early census put "entry point
needs an opaque context built by another call" at 58% of all refusals, and that
number set the build order for the whole producer-chain effort. After that effort
shipped, the same census over 14 trees and 244 refusals put the class at **0%**.
The dominant refusal today is `CorpusNeverBound` at 35.5%, which is a different
kind of statement: the harness assembled, compiled and ran, and never read the
fuzzer's bytes.

Notice what that progression requires. A refusal has to be a *named category* you
can count, not a generic failure, or you cannot tell a fixed problem from a
renamed one.

`Rejection` names the reason, and `lisdex harness` prints it, so a refusal is
actionable rather than a shrug.

## Stage 3: Building Under Sanitizers

This is the hard wall. Published measurements put automated builds of arbitrary
C/C++ projects under sanitizers well below 50% success, and the honest baseline
without an LLM scores about the same as Google's LLM agent.

`lisdex-build/ladder.rs` tries build systems in order and injects flags into
each. The injection points are not obvious, and getting them wrong fails
silently.

### The flag injection that survives

The documented "most reliable method", `CMAKE_<LANG>_FLAGS_INIT` in a toolchain
file, **does not survive a project's own `set(CMAKE_C_FLAGS ...)`**. Reproduced
on CMake 4.4.0. The injection that does survive:

```
-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=<file with add_compile_options()>
```

### Two-pass builds need a clean between them

GNU Make decides what to rebuild by mtime alone. A two-pass
uninstrumented-then-instrumented build in the same directory silently reuses the
uninstrumented objects, and you get an archive with no coverage instrumentation
that builds and links perfectly.

`make clean` between passes is mandatory. It is also safe: only
`maintainer-clean` erases bison and flex output.

### AFL_NOOPT

`AFL_NOOPT=1` must be set for the *configure* step and unset for the *build*
step. Configure scripts compile tiny probe programs, and AFL++'s instrumentation
makes some of them fail, so configure concludes the feature is missing.

## Stage 4: Fuzzing

`runner::AflOptions::invocation` builds the command line. The pieces that matter:

```
afl-fuzz -i <seeds> -o <findings> -m none
         -V <duration>
         -c <cmplog binary>       # solves magic bytes and checksums
         -x <dict> ... (max 4)    # format-aware tokens
         -M main | -S secondary1 -p fast
         -- <target>
```

### Dictionaries, capped at four

`dictionary::select` reads the magic bytes of the seed corpus, matches them to
AFL++'s shipped dictionaries, and passes up to `MAX_DICTIONARIES` of them.

The cap is four because **`afl-fuzz` fatals on a fifth `-x`**. It is a property
of the binary, so lisdex caps and warns rather than letting the campaign die at
startup.

A related gotcha for anyone reading AFL++'s docs: `-P` is the mutation strategy
and `-p` is the power schedule. They share value names and the upstream docs use
both within four lines of each other.

### Parallel instances

`runner::instance_plan` builds one main and N-1 secondaries, each secondary on a
different power schedule (`fast`, `coe`, `lin`, `quad`, `exploit`, `rare`).
Secondaries sync through the main instance, which is why coverage combines with
`max` and not `+`.

### Harvesting crashes

`runner::discover_crash_inputs` walks **every** instance directory, not just
`default/`. `runner::harvest` re-runs each crashing input under the sanitizer to
get a fresh report:

```rust
pub fn reproduce(target: &Path, input: &Path, timeout: Duration)
    -> Result<Reproduction, RunnerError>
```

It captures stderr with a timeout and a byte cap. Both matter: a target that
hangs would block the harvest forever, and a target in a report loop can emit
hundreds of megabytes.

## Stage 5: Deduplication

`SanitizerReport::stack_hash` is the whole thing:

```rust
pub fn significant_frames(&self) -> Vec<&str>   // noise dropped
pub fn stack_hash(&self) -> Option<String>      // None if nothing survives
```

Two filters run:

```rust
const NOISE_FRAME_PREFIXES: [&str; 7] =
    ["__asan", "__ubsan", "__msan", "__sanitizer", "__interceptor", "__libc", "_start"];

const NOISE_FRAME_EXACT: [&str; 7] =
    ["kill", "abort", "raise", "main", "LLVMFuzzerRunDriver",
     "ExecuteFilesOnyByOne", "magma_log"];
```

Then the top frames are hashed. If **no symbolized frame survives**, the function
returns `None` and the crash is never bucketed.

`dedup::group_crashes` does the grouping, and its contract is worth stating
plainly:

```rust
match crash.stack_hash() {
    Some(key) => by_key.entry(key).or_default().push(crash),
    None      => unkeyed.push(crash),   // never merged with each other
}
```

Groups are sorted by size, then by key, so the output is deterministic.

## Stage 6: Classification

`classify::classify` runs CASR first and applies lisdex's own rules where CASR is
silent:

```rust
pub fn classify(text: &str) -> Option<Classification> {
    let parsed = SanitizerReport::parse(text)?;
    let fault_address = FaultAddress::of(parsed.fault_address());
    if parsed.is_undefined_behavior() { /* UBSan: lisdex decides */ }
    let anchored = report::anchored_lines(text)?;
    let context = AsanContext(...);
    let class = context.severity().ok()?;   // CASR
    ...
}
```

Two things are worth knowing.

**CASR does not triage UBSan.** UndefinedBehaviorSanitizer reports get lisdex's
own verdict, `Severity::Undefined`, because feeding them to an ASAN classifier
produces nonsense.

**Double free is upgraded.** CASR's own verdict for `double-free` is lower than
the exploitation literature supports, so `DOUBLE_FREE_SEVERITY` overrides it to
`ProbablyExploitable` and the classification records `DecidedBy::Lisdex` so the
override is visible rather than hidden.

`FaultAddress::of` handles the null-versus-wild distinction, and
`is_security_relevant` is what makes a null dereference render as
"(non-security)" in the panels.

That verdict is not decided per report. Chromium's rule is "consistent, small,
fixed offset", and consistency is a property of a bug group rather than of one
crash: the same bug landing at `0x10` on one input and `0x4000` on another has an
offset that moves with the input, which makes it attacker-influenced even though
both addresses are small. `group_is_security_relevant` folds every fault address
in the group and only keeps the non-security verdict when they agree. A crash
whose report will not parse contributes `Absent`, which disqualifies the whole
group from the rule - deferring is the safe direction, and concluding "all
near-null" from the subset that happened to parse is not.

## Stage 7: The Advisory

`Advisory::draft` takes the whole bug group, because an advisory describes a bug
rather than a single crash, and the group-level checks above need every crash in
it:

```rust
pub fn draft(
    target: &str,
    group: &CrashGroup<'_>,
    tree: TreeProvenance,
) -> Option<Advisory>
```

It returns `None` when the group cannot support an advisory, which is the same
refusal discipline as everywhere else. Note there is no `crash_count` parameter:
it was always `group.len()` at every call site, and a count passed separately
from the thing it counts is a parameter that can disagree with reality.

`tree` is required rather than optional on purpose. Disclosability depends on
what kind of tree the campaign ran against, so making it a parameter means the
compiler will not let a caller draft an advisory while leaving that question
unanswered.

`weakness.rs` maps the bug class to a CWE. `markdown.rs` and `json.rs` render the
OpenSSF template. `bundle.rs` writes a directory per bug:

```
bundles/2167ce84a15d/
  advisory.md          human form
  advisory.json        machine form
  poc.bin              the exact crashing bytes
  report.txt           the sanitizer output
  reproduce.sh         executable, takes the target as $1
```

The exit gate for this stage **executes the emitted `reproduce.sh`** and requires
the same fault to come back. A reproducer that does not reproduce is worse than
no reproducer.

### The provenance guard

`provenance_of` inspects the frames for Magma's canary functions. A crash from an
instrumented benchmark is stamped `NOT DISCLOSABLE` and carries no filing route,
because reporting a planted bug to a maintainer wastes their time.

That is only half the guard, and it is the weaker half. A stack heuristic answers
"did this crash route through a canary?" when the question that matters is "is
this target a benchmark?" So `campaign_tree` scans the target binary's symbols
once, at campaign start, and stores the answer on the campaign;
`resolve_provenance` refuses disclosure if *either* the tree or the frames say
benchmark. The two arms are independent, and the exit gate proves it with a pair
of controls that are the same report bytes differing only in the stored tree
value.

Watch what the split did to the rendered advisory. The original refusal banner
told the reader the crash "carries benchmark instrumentation in its call stack."
For a tree-arm refusal that sentence is false, and a reader who checks the stack
and finds it clean would reasonably conclude lisdex was broken. A refusal has to
state the reason it actually used, so there are two banners.

## Stage 8: The Read-Model

`Snapshot::read` collapses everything into one immutable value:

```rust
pub fn read(source: &Source) -> Result<Snapshot, MonitorError>
```

The design rule is that a missing artifact is a *notice*, not an error. A
campaign that has not written its first `plot_data` sample yet still renders:

```rust
let Ok(curve) = runner::read_curve(findings) else {
    notices.push(Notice::NoCurveRecorded);
    return (Vec::new(), None);
};
```

Only an unusable source is a hard error, and there is exactly one:
`CampaignNotFound`, raised when you name a campaign id the store does not hold.
Silently falling back to a different campaign would show you numbers from a run
you did not ask about.

## Error Handling

Every crate has one `thiserror` enum and no `unwrap` in library code. The pattern
that recurs:

```rust
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{AFL_FUZZ_BIN} failed before writing stats ({status}); \
             check the {AFL_FUZZ_BIN} output above")]
    AflFailed { status: String },
    #[error("asked to resume but {findings} holds no previous instance; \
             drop --resume to start a new campaign there")]
    NothingToResume { findings: String },
}
```

Error text says what to do next, not just what went wrong.

## Testing Strategy

The suite is about a thousand tests, and the ones that earn their keep share a
shape: they assert a property against a **real captured artifact**, and their
failure message says what breaks in the product.

```rust
assert_eq!(
    totals.edges_found, 13_647,
    "instances share one coverage map and sync; summing edges_found would \
     report 26647 edges the campaign never had"
);
```

Fixtures are real: a 600-second libpng `plot_data` with 107 rows, and 19
sanitizer captures taken from actual crashes. The unsymbolized ones are kept
deliberately, because they are the corpus that proves the refusal works.

Above the unit tests are exit gates, one per milestone, each running a real
campaign against a Magma-instrumented libpng and checking the result against
canary ground truth. The gates are shell scripts so they can assert on the
shipped binary rather than on library internals.

A gate is only trusted after it has been **gutted**: break the thing it checks
and confirm it goes red. Three consecutive gates in this project went red on
their first run because the *check* was wrong, not the product, and one control
passed while gutted because the only tell was that it ran in 5.01 seconds
instead of 0.10.
