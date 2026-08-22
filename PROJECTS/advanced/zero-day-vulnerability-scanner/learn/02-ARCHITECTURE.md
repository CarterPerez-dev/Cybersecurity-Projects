# Architecture

## High Level

lisdex is a pipeline. Each stage produces an artifact the next stage consumes,
and every stage can be run on its own from the CLI.

```
  git URL or path
        |
        v
  +-------------+   source tree
  |   ingest    |------------------+
  +-------------+                  |
                                   v
                          +-----------------+  ranked entry points
                          |    surface      |--------------------+
                          | (libclang)      |                    |
                          +-----------------+                    v
                                                        +-----------------+
  +-------------+   instrumented archive                 |    harness      |
  |    build    |<---------------------------------------|  + 4 oracles    |
  | (the ladder)|                                        +-----------------+
  +-------------+                                                 |
        |                                                         |
        |            harness binary (ASAN + AFL + cmplog)         |
        +------------------------+--------------------------------+
                                 v
                        +-----------------+
                        |      fuzz       |  afl-fuzz, N instances
                        +-----------------+
                            |         |
                  plot_data |         | crashes/
                fuzzer_stats|         |
                            v         v
                        +-----------------------+
                        |        store          |  sqlite: campaigns, crashes
                        +-----------------------+
                                 |
                                 v
                        +-----------------------+
                        |  dedup + triage       |  stack hash, CASR
                        +-----------------------+
                                 |
              +------------------+------------------+
              v                                     v
     +-----------------+                   +-----------------+
     |    monitor      |  Snapshot         |     report      |  advisory,
     |  (read-model)   |                   |                 |  bundle
     +-----------------+                   +-----------------+
        |           |
        v           v
      tui        dashboard
```

## Component Breakdown

| Crate | Responsibility |
|---|---|
| `lisdex-ingest` | Acquire a source tree from a git URL or a local path. Detect the build system. |
| `lisdex-surface` | Parse headers with libclang, find functions that take attacker bytes, rank them. |
| `lisdex-harness` | Synthesize a harness for a ranked entry point and judge it with four oracles. |
| `lisdex-build` | The auto-build ladder. Inject sanitizer and coverage flags into cmake, autotools, meson, or plain make. |
| `lisdex-fuzz` | Build the `afl-fuzz` invocation, choose dictionaries, run instances, harvest crashes, parse `plot_data` and `fuzzer_stats`. |
| `lisdex-core` | The domain: `Campaign`, `Crash`, the sqlite store, sanitizer-report parsing, stack hashing, dedup. |
| `lisdex-triage` | Exploitability classification via CASR plus lisdex's own fault-address rules. |
| `lisdex-report` | Advisory drafting, the OpenSSF template, JSON and markdown renderers, reproducer bundles. |
| `lisdex-monitor` | The read-model. Collapses store + curve + stats + dedup + classification into one immutable `Snapshot`. |
| `lisdex-tui` | Terminal dashboard. Renders `Snapshot`. Nothing else. |
| `lisdex-dashboard` | Local web console. Renders `Snapshot` over HTTP. Nothing else. |

## The Layering Decision That Cost the Most

The milestone plan called for one crate, `lisdex-tui`, described as "a pure view
over core with zero analysis logic". The exit condition was that two auditors
agree it is a pure view.

That is an opinion for exactly as long as the view *can* call analysis. So the
read-model was split into its own crate:

```
   lisdex-core   lisdex-fuzz   lisdex-triage      <- analysis lives here
        \             |             /
         \            |            /
          +-----------+-----------+
                      |
              lisdex-monitor                      <- one Snapshot of owned data
                      |
          +-----------+-----------+
          |                       |
     lisdex-tui            lisdex-dashboard       <- views, and nothing else
```

`lisdex-tui`'s dependency list is `lisdex-monitor`, `ratatui`, `thiserror`.
`lisdex-dashboard`'s is `lisdex-monitor`, `axum`, `tokio`, `serde`, `thiserror`.
Neither can call `classify()` or `group_crashes()` or `plot::parse()` because
those crates are not linked. Purity stops being a judgement call and becomes a
manifest fact plus a grep, which is what the exit gate checks.

`Snapshot` also carries no analysis types. `lisdex_triage::Severity`,
`lisdex_triage::classify::DecidedBy`, and `lisdex_core::CampaignStatus` are each
*projected* onto a monitor-owned enum, so the views cannot reach the analysis
crates transitively either.

### The property this actually buys

A view that computes anything drifts from the tool it claims to be a view over.
The exit gate asserts they agree:

```
lisdex crashes  --db X --campaign 1   ->  83 crashes, 2 distinct bugs
lisdex coverage --findings Y          ->  curve_peak_edges 13504

panel shows: crashes 83, bugs 2, peak edges 13,504
```

If the TUI computed its own bug count, that check would fail. It is a
differential oracle, and it is stronger than any amount of reading the code.

## Data Flow: One Crash, End to End

1. **afl-fuzz saves a file** under `findings/<instance>/crashes/id:000001,...`.

2. **`runner::harvest` re-runs it** against the target with
   `ASAN_OPTIONS`/`UBSAN_OPTIONS` set, captures stderr, and caps it at
   `MAX_REPORT_BYTES` so a pathological report cannot exhaust memory.

3. **`SanitizerReport::parse` reads that text.** It finds the header line, pulls
   the sanitizer name, the bug kind, and the fault address, then parses the
   frames.

4. **`SanitizerReport::stack_hash` keys it.** Noise frames are dropped
   (`NOISE_FRAME_PREFIXES`, `NOISE_FRAME_EXACT`), unsymbolized frames disqualify
   the stack entirely, and the surviving top frames are hashed.

5. **`Store::insert_crash` persists** the input bytes, the raw report, and the
   key.

6. **`dedup::group_crashes` buckets** by key at read time. Crashes with no key
   are never merged with each other.

7. **`classify::classify` judges severity** from the report text: CASR for the
   main verdict, `FaultAddress` for the null-versus-wild distinction.

8. **`Advisory::draft` builds the disclosure** from the whole bug group and the
   campaign's tree provenance, refusing the fields it cannot know and refusing
   disclosure entirely for anything from a benchmark tree. It takes the group
   rather than one crash because two of its judgements are group-level: how many
   crashes the bug has, and whether a near-null fault offset holds still across
   them.

## Design Decisions

### The stored stack hash is a cache, not the truth

A crash row stores its key, but `Store::crashes_for_campaign` recomputes the key
from the retained report rather than trusting the stored one.

This looks redundant until you change the frame filter. Measured on two real
libpng campaigns: adding a single entry to `NOISE_FRAME_EXACT` invalidated all
127 stored keys. If the store had trusted them, rows written before and after the
change would have counted as different bugs, and the campaign would have reported
4 bugs where the Magma canaries prove there are 2.

The report is the durable artifact. The key is derived from it, every time.

### Coverage is a maximum, never a sum

When N instances fuzz in parallel they share one coverage map and sync through
the main instance. `runner::combine_stats` therefore adds the work and takes the
maximum of the coverage:

```rust
combined.execs_done   += stats.execs_done;      // work is additive
combined.edges_found   = max(a.edges_found, b.edges_found);  // coverage is not
```

Summing `edges_found` across four instances would report coverage the campaign
never had.

### The coverage curve comes from one authoritative instance

`plot_data` is per-instance. `runner::primary_instance` picks main, then default,
then the first, and the curve is read from that one. Choosing which instance is
authoritative is a policy decision, so it lives in `lisdex-fuzz` and not in
either view.

### Falling coverage means the campaign was resumed

`plot_data` is appended to on resume, so a resumed campaign's curve is two
campaigns concatenated and its coverage appears to fall at the seam. lisdex
detects this and raises a notice rather than silently reporting a first-to-last
delta that understates the run. It is a true positive, not a bug to fix.

### The dictionary cap of four is structural

`afl-fuzz` fatals on a fifth `-x`. lisdex caps the dictionaries it selects at
four and warns when a corpus has more recognized formats than fit. This is a
property of the binary, not a style choice.

### The model owns every sentence on screen

Notices, severity labels, the reason a crash could not be keyed: all of these
are strings the model produces. A view that composes its own sentence about, say,
how dedup treats unkeyed crashes can contradict dedup while every test stays
green. The rule is that a view places words, it does not choose them.

The same rule caught a subtler bug. The instances panel said "N running", but
`afl-fuzz` leaves `fuzzer_stats` on disk after it exits, so instance count can
never be a liveness signal. Only the campaign's own phase is.

## Data Models

```rust
struct Campaign { target: String, status: CampaignStatus }

struct Crash {
    campaign_id: CampaignId,
    input: Vec<u8>,            // the exact bytes that crashed it
    sanitizer_report: String,  // the durable artifact
    stack_hash: Option<String> // None means "refused to key", not "no bug"
}
```

`stack_hash` being `Option` is the whole refusal doctrine in one field.

The sqlite schema is deliberately small:

```sql
CREATE TABLE campaigns (
    id INTEGER PRIMARY KEY,
    target TEXT,
    status TEXT,
    tree_provenance TEXT
);
CREATE TABLE crashes (
    id INTEGER PRIMARY KEY,
    campaign_id INTEGER REFERENCES campaigns(id),
    input BLOB NOT NULL,
    sanitizer_report TEXT NOT NULL,
    stack_hash TEXT
);
```

`tree_provenance` is `field`, `benchmark`, or `unknown`, and a database written
before that column existed reads back as `unknown` rather than `field`. That
distinction is load-bearing: an unmeasured tree must not be able to assert
something nobody checked.

There is no version column, no severity column, no bug table. Severity and
bucketing are computed from the report on read, so improving the classifier
improves every campaign already in the store.

## Security Architecture

lisdex handles unfixed vulnerabilities in other people's software. The threat
model is mostly about not leaking them.

| Asset | Exposure | Control |
|---|---|---|
| Crash inputs | Files under `findings/` | Local filesystem only |
| Sanitizer reports | The sqlite store | Local file |
| The web console | HTTP | Binds `127.0.0.1` by default; a non-loopback bind prints a warning naming what it exposes |
| Advisory drafts | Files you choose to write | Marked NOT DISCLOSABLE when the finding came from a synthetic benchmark |

The console page loads nothing from the network. No CDN, no font service, no
analytics. This is enforced by a test that asserts the only absolute URL in the
page is the SVG namespace string, which browsers never fetch.

### The synthetic-benchmark guard

lisdex validates itself against Magma, which works by injecting known bugs into
real libraries. A Magma crash is a *planted* bug, and reporting one to libpng
would be embarrassing at best. Worse, Magma also forward-ports real historical
CVEs into current source, so a benchmark tree holds genuine vulnerabilities that
were fixed years ago.

The guard has two independent arms, and either one alone refuses disclosure:

- **The stack arm.** `provenance_of` detects Magma's canary frames in the report.
- **The tree arm.** At campaign start lisdex scans the target binary's symbols. A
  build carrying the canary runtime is a benchmark build, and `tree_provenance`
  records that on the campaign. Every finding from it is refused *whatever the
  stack looks like*.

The tree arm exists because the stack arm asks the wrong question. Whether a
crash routed through a canary is an accident of which bug fired; whether the tree
is a benchmark is a fact about the target. `Advisory::draft` takes the campaign's
tree provenance as a required argument, so no caller can draft an advisory
without stating what kind of tree it came from.

## Performance Considerations

The bottleneck is never lisdex. It is `afl-fuzz` exec rate, and the two things
that wreck it:

- **A harness that shadows the driver's `main`.** Silently drops from ~240,000
  execs/sec to ~1,600. lisdex checks `target_mode` in `fuzzer_stats` and warns.
- **Not using persistent mode.** Forking per input costs more than the parse.

Everything lisdex does per-crash (re-run, parse, hash, classify) is cheap
relative to a campaign, and the read-model rebuilds the whole snapshot on each
1 Hz refresh without noticeable cost.

## Deployment

lisdex is a single binary. It shells out to `afl-fuzz`, `afl-cmin`, `afl-tmin`
and the AFL++ compilers; it does not link them. That matters legally as well as
technically: AFL++ is AGPL-3.0-or-later, lisdex is AGPL-3.0, and lisdex installs
AFL++ upstream and unmodified rather than vendoring a fork.

The Docker setup is for development and for the Magma validation rig. Users get
the binary.

## Limitations

- **C and C++ only.** The entry-point discovery is libclang.
- **File-format and codec parsers.** The ranking heuristics look for
  `(bytes, length)` shapes and callback-registration patterns. A network
  protocol parser with a socket-shaped entry point ranks poorly.
- **Auto-build is the hard wall.** Building arbitrary C projects under sanitizers
  succeeds well under half the time in the published measurements, and lisdex is
  not magic. When the ladder fails it says so rather than producing a broken
  archive.
- **Harness synthesis will not invent a producer.** Where an entry point needs an
  opaque context built by another call, lisdex resolves it through the producer
  chain or refuses; it never emits a harness that fuzzes handle plumbing. That
  class was 58% of all refusals before the chain was built and is **0%** across
  14 trees after it. The dominant refusal now is `CorpusNeverBound` at 35.5% --
  a harness that compiled and ran without reading the fuzzer's bytes.

## Comparison

| | lisdex | OSS-Fuzz | OSS-Fuzz-Gen | OGHarn |
|---|---|---|---|---|
| Needs an existing harness | no | yes | no | no |
| Needs an API key / account | no | n/a | yes (LLM) | no |
| Runs locally | yes | no | partly | yes |
| Struct-based entry points | yes | n/a | varies | authors declare unsupported |
| Ships triage + advisory | yes | separate | no | no |

The honest framing: OGHarn's authors name libPNG, libVPX and libAOM as
unsupported because of their struct-based entry points. That is the niche lisdex
is built for, and it is a checkable claim rather than a marketing one.
