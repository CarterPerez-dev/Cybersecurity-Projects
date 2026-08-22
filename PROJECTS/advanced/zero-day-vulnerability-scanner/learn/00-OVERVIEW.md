# lisdex

## What This Is

lisdex is a point-and-run zero-day scanner for C and C++ parsers. You give it a
source tree; it ranks the parser entry points, synthesizes a fuzz harness for
the best one, builds the library under AddressSanitizer, runs an AFL++ campaign,
buckets the crashes into distinct bugs, classifies how bad each one is, and
drafts a coordinated-disclosure advisory with a reproducer you can attach to a
report.

It needs no API key, no account, and no cloud service. Everything runs on your
machine.

## Why This Matters

Memory-corruption bugs in file-format parsers are still the way people get owned
in 2026, and the reason is boring: parsers are written in C, they run on
attacker-controlled bytes, and most of them are nobody's full-time job.

Three real ones, all from 2025:

- **CVE-2025-53367**, an out-of-bounds write in DjVuLibre's `MMRDecoder::scanruns`.
  Antonio Morales at GitHub Security Lab found it while looking at Evince. The
  proof of concept achieved working code execution and bypassed ASLR on a fully
  updated Ubuntu 25.04. DjVuLibre is a transitive dependency most people did not
  know they shipped, and it has never been enrolled in OSS-Fuzz, so there was no
  continuous fuzzing pressure on it at all.
- **CVE-2025-54874**, CVSS 9.8, an out-of-bounds heap write in openjpeg's
  `opj_jp2_read_header` when the input stream is shorter than the header claims.
- **CVE-2025-5914**, CVSS 7.8, an integer overflow in libarchive's
  `archive_read_format_rar_seek_data` that leads to a double free.

None of these are exotic. They are the same three shapes that have been showing
up since the 1990s: a length field nobody checked, a buffer walked past its end,
and a pointer freed twice.

**Real world scenarios where this applies:**

- You maintain a product that links an image, archive, or document library you
  did not write, and you want to know what its parser does on malformed input
  before someone else finds out.
- You are a security researcher who wants to hunt in a library that OSS-Fuzz
  does not cover, and you do not want to spend the first two days hand-writing a
  harness and a build script.
- You are triaging a crash pile from an existing fuzzer and you need to know how
  many *distinct* bugs are in it, which ones are exploitable, and what to put in
  the report.

## What You'll Learn

**Security concepts:**

- How memory-safety bugs actually present at runtime: what a heap overflow looks
  like in an AddressSanitizer report, why the read/write distinction dominates
  severity, and why a null dereference is usually a denial of service rather
  than a foothold.
- Why crash counts lie. A campaign that reports 182 crashes may have found two
  bugs. Getting from one number to the other is the whole discipline of triage.
- What coordinated disclosure actually requires, which fields a CVE record needs,
  and why refusing to guess at a field is more useful than filling it in.

**Technical skills:**

- Reading a C header with libclang and deciding which functions take
  attacker-controlled bytes.
- Building an arbitrary C project under sanitizers and coverage instrumentation
  without hand-writing a build script for it.
- Driving AFL++: persistent mode, cmplog, dictionaries, parallel campaigns, and
  reading the coverage curve it writes.
- Stack hashing for crash deduplication, and how to tell when your hash is
  merging bugs that are actually distinct.

**Tools and techniques:**

- AFL++ 5.02c (`afl-clang-lto`, `afl-fuzz`, `afl-cmin`, `afl-tmin`)
- AddressSanitizer and UndefinedBehaviorSanitizer
- libclang for entry-point discovery
- CASR for exploitability classification
- Magma, the bug-injection benchmark, as ground truth for whether the triage
  layer is telling the truth

## Prerequisites

**You should already know:**

- C well enough to read a header and know what `const unsigned char *data,
  size_t len` implies.
- What a stack trace is and roughly how heap allocation works.
- Enough shell to run a long-lived process and read its output.

**You do not need to know:**

- Rust. lisdex is written in it, but you can use the tool without reading it.
- Anything about fuzzing. That is what this project teaches.

**Tools:** Linux, a C compiler, and about 4 GB of disk for a build tree. The
installer handles the rest.

## Quick Start

```sh
curl -fsSL https://angelamos.com/lisdex/install.sh | bash
```

That ends with `lisdex` on your PATH. Then:

```sh
# 1. What in this source tree parses untrusted bytes?
lisdex surface ./libpng

# 2. Build it under AddressSanitizer, with no hand-written build script
lisdex build https://github.com/glennrp/libpng --work /tmp/lisdex

# 3. Fuzz the harness
lisdex fuzz --target /tmp/lisdex/builds/libpng/afl/harness \
            --seeds ./corpus --findings /tmp/out --db /tmp/lisdex.sqlite

# 4. Watch it, in the terminal or in a browser
lisdex tui   --db /tmp/lisdex.sqlite --findings /tmp/out
lisdex serve --db /tmp/lisdex.sqlite --findings /tmp/out

# 5. How many distinct bugs, and how bad?
lisdex crashes --db /tmp/lisdex.sqlite --campaign 1

# 6. Draft the disclosure
lisdex advisory --db /tmp/lisdex.sqlite --campaign 1
lisdex bundle   --db /tmp/lisdex.sqlite --campaign 1 --out /tmp/bundles
```

Step 6 writes a directory per distinct bug containing the advisory in both
human and machine form, the reproducer input, the sanitizer report, and an
executable `reproduce.sh`.

## Project Structure

```
crates/
  lisdex/            the CLI, one subcommand per verb above
  lisdex-ingest/     acquiring a source tree (git URL or local path)
  lisdex-surface/    libclang entry-point discovery and ranking
  lisdex-harness/    harness synthesis and the four oracles that judge it
  lisdex-build/      the auto-build ladder: cmake, autotools, make, meson
  lisdex-fuzz/       AFL++ invocation, dictionaries, corpus, coverage curve
  lisdex-triage/     exploitability classification (CASR + lisdex's own rules)
  lisdex-core/       the store, the crash model, dedup, sanitizer parsing
  lisdex-report/     advisories, reproducer bundles, the disclosure template
  lisdex-monitor/    the read-model: one immutable snapshot of a campaign
  lisdex-tui/        the terminal dashboard (a pure view over the model)
  lisdex-dashboard/  the local web console (the same view, over HTTP)
```

The split between `lisdex-monitor` and the two view crates is deliberate and
is explained in `02-ARCHITECTURE.md`.

## Next Steps

- `01-CONCEPTS.md` - what memory corruption is, how sanitizers catch it, why
  crash counts lie, and what disclosure requires.
- `02-ARCHITECTURE.md` - the pipeline, the layering, and the design decisions
  that cost the most to get right.
- `03-IMPLEMENTATION.md` - how each stage works, with the code.
- `04-CHALLENGES.md` - extensions, from a weekend to a research project.

## Common Issues

**`lisdex surface` finds nothing, or half of what you expected.**
Parsing a C project without a compilation database silently halves buffer
detection while still returning success. Point lisdex at a tree that has a
`compile_commands.json`, or let `lisdex build` produce one first.

**`lisdex fuzz` runs at 1,500 execs/sec instead of 200,000.**
Your harness defines its own `main`, which links against the driver's weak
`main` and shadows it, so nothing is actually being fuzzed. lisdex warns about
this: look for the line about persistent mode in the campaign output.

**A campaign was killed and its crashes are not in the database.**
Ctrl-C is handled: lisdex stops the fuzzers, harvests what they already wrote,
and exits 0, so the crashes are persisted. A campaign killed outright, by
`SIGKILL` or a lost session, cannot run that path. The crash files are still on
disk under the findings directory, and `lisdex import --findings <dir> --target
<harness> --db <db>` re-runs each one and persists it exactly as a live campaign
would.

**A campaign reports crashes but `lisdex crashes` shows no distinct bugs.**
The crashes were captured unsymbolized, so every one of them would hash to the
same module offset. lisdex refuses to key them rather than invent a bucket. Build
the target with symbols and re-run.

## Related Projects

- `PROJECTS/advanced/binary-analysis-tool` - static analysis of the compiled
  artifact rather than the source.
- `PROJECTS/intermediate/sbom-generator-vulnerability-matcher` - finding out
  which of these libraries you actually ship.
