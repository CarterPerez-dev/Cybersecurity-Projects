# Core Security Concepts

This document covers what you need to understand to use lisdex and to trust what
it tells you. The running example is a PNG parser, because libpng is small
enough to read and old enough to have had every kind of bug.

## Memory Corruption in Parsers

### What It Is

A parser reads bytes it did not write. Somewhere in it, a length from the input
gets used to index or copy into a buffer whose size came from somewhere else.
When those two disagree, memory outside the buffer gets read or written.

The canonical shape, in a chunk-based format like PNG:

```c
/* the file says how long the chunk is */
png_uint_32 length = png_get_uint_31(png_ptr, chunk_length);

/* the parser allocated a buffer at some earlier, unrelated moment */
png_bytep buffer = png_ptr->chunk_buffer;   /* say, 8192 bytes */

/* and then trusts the file */
memcpy(buffer, input + offset, length);     /* length can be 0x7fffffff */
```

Nothing here is exotic. The bug is that `length` is attacker data and `buffer`
is a fixed size, and no line compares them.

### Why It Matters

C has no bounds checking, so this does not fail loudly. It corrupts whatever is
adjacent and the program keeps going. What is adjacent decides what an attacker
gets:

- Another heap buffer: information disclosure, or a controlled write into data
  the program trusts.
- Heap metadata: control of a later `malloc` or `free`, which is a classic route
  to arbitrary write.
- A function pointer or a C++ vtable pointer: direct control of the instruction
  pointer.

CVE-2025-53367 in DjVuLibre is the full chain. An out-of-bounds write in
`MMRDecoder::scanruns` produced working code execution with an ASLR bypass on a
fully patched Ubuntu 25.04.

### How It Works

There are four shapes worth being able to name on sight.

**Heap buffer overflow.** Read or write past the end of a `malloc`'d region.
AddressSanitizer catches this because it places poisoned redzones around every
allocation.

```
==53767==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7bd6bfde0020
WRITE of size 32 at 0x7bd6bfde0020 thread T0
    #0 0x558474e40fd8 in png_handle_PLTE /src/libpng/pngrutil.c:992:4
```

**Use after free.** A pointer is kept past the `free` that invalidated it. ASAN
catches it by quarantining freed memory rather than returning it immediately.
The shadow byte for freed heap is `0xfd`.

**Double free.** `free` called twice on the same pointer. Depending on the
allocator this corrupts the free list, which is a well-trodden route to an
arbitrary write.

**Stack buffer overflow.** The same thing on a stack array, which is more
directly dangerous because return addresses live there.

### Common Attacks

**Malformed length field.** Set a declared length larger than the data actually
present, or larger than any buffer the parser has. This is the single most
productive mutation against a chunked format and it is why format-aware
dictionaries matter.

**Integer overflow into an allocation.** Make `count * sizeof(item)` wrap, so a
small allocation is followed by a large loop.

```c
/* wrong: count is attacker controlled */
items = malloc(count * sizeof(struct item));
for (i = 0; i < count; i++) items[i] = read_item(input);
```

CVE-2025-5914 in libarchive is this bug, in
`archive_read_format_rar_seek_data`, ending in a double free.

**Truncation.** Declare a header, then end the file early. The parser reads
fields that were never written. CVE-2025-54874 in openjpeg is exactly this: an
out-of-bounds heap write in `opj_jp2_read_header` when the stream is too short.

### Defense Strategies

- **Validate before allocating, and validate against the real remaining input**,
  not against the value the file supplied.
- **Use checked arithmetic** for any size computation involving input.
- **Fuzz continuously**, because the space of malformed inputs is far too large
  to enumerate by hand.
- **Compile with sanitizers in CI**, not only when investigating. A bug that
  only corrupts memory silently in a release build is a bug you will not notice
  until someone else does.

## Sanitizers: Turning Corruption Into a Crash

### What It Is

A sanitizer is compiler instrumentation that makes undefined behavior loud.
AddressSanitizer maintains a shadow map: one byte of metadata per eight bytes of
application memory, recording whether each is addressable. Every load and store
gets a check against that map.

### Why It Matters

Without a sanitizer, a fuzzer only finds bugs that happen to segfault. Most
overflows do not. They land in memory the process owns, the program continues,
and the fuzzer records nothing. Instrumentation is the difference between
finding the bug and walking straight past it.

### How It Works

```
application memory   [ alloc'd 32 bytes ][ redzone ]
shadow map            00 00 00 00          fa fa fa
                       ^ addressable        ^ poisoned
```

Reading the redzone hits a poisoned shadow byte, and ASAN reports rather than
continuing. The legend appears in every report:

```
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Heap left redzone:     fa
  Freed heap region:     fd
```

Note `fd` for freed heap. A common mistake, which lisdex's own research
originally made, is to key a use-after-free detector on `0xfb`. That value does
not exist in the legend, and a detector written against it fails closed and
never fires.

### Common Pitfalls

**Assuming ASAN aborts.** On Linux it does not abort by default. If your harness
keeps running after a report, you get one crash file with several stacked
reports in it. Set `abort_on_error=1` when you want one crash per report.

**Assuming symbolization.** ASAN only symbolizes if it can find a symbolizer and
the binary has symbols. An unsymbolized report looks like this:

```
    #0 0x7fc82135353b  (/lib/x86_64-linux-gnu/libc.so.6+0x4553b)
```

That frame is a module plus an offset. Every crash of that kind in that module
produces the same frame, so any bucketing built on it merges unrelated bugs.
lisdex refuses to key such a report at all, which is covered below.

## Why Crash Counts Lie

### What It Is

A fuzzer saves one file per input that produced a new crash *signature by its own
coverage metric*, which is not the same as one file per bug. A single bug reached
by twenty different paths produces twenty files.

### Why It Matters

This is the difference between a useful report and noise. Real numbers from a
lisdex campaign against a Magma-instrumented libpng:

```
182 crash files  ->  2 distinct bugs
```

If you reported 182 issues, you would be ignored. If you reported 2, with a
reproducer each, you would be taken seriously.

The academic version of this: a triage layer takes crash-report precision from
about 2.7% to about 89.7%. Most of what a fuzzer saves is the same bug again.

### How It Works: Stack Hashing

Take the crash stack, drop the frames that are noise, keep the top N, hash them.
Two crashes with the same hash are the same bug.

```
raw stack                          after filtering            key
-----------------------------      --------------------      ------
#0 __asan_memcpy                   png_handle_PLTE           sha256(
#1 png_handle_PLTE                 png_read_info               "png_handle_PLTE
#2 png_read_info                   LLVMFuzzerTestOneInput       png_read_info
#3 LLVMFuzzerTestOneInput                                       ...")
#4 main                            (dropped: noise)
#5 __libc_start_main               (dropped: noise)
```

Two decisions here carry all the weight.

**Which frames are noise.** `__asan_*`, `__interceptor_*`, `main`,
`_start`, and the fuzzer driver's own frames appear in every crash and carry no
information. Including them makes every crash look similar.

**How many frames, N.** Too few and you merge distinct bugs that share a leaf
function. Too many and you split one bug across the different paths that reach
it. lisdex uses N=5, validated against Magma's canary ground truth across two
real campaigns: N=1 and N=2 both merged bugs that the canaries prove are
distinct.

### The Refusal

If the stack has no symbolized frames, lisdex does not key it. It reports the
crash, classifies its severity, and marks it unkeyed, rather than putting it in a
bucket.

This matters because the alternative is worse than useless. Keying on
`libc.so.6+0x4553b` would merge every SEGV in libc into one "bug", and you would
report one issue that is actually thirty, or thirty that are actually one.

## Exploitability Classification

### What It Is

Given a crash, how bad is it? The industry vocabulary comes from `!exploitable`
and its descendants: EXPLOITABLE, PROBABLY_EXPLOITABLE, NOT_EXPLOITABLE,
UNDEFINED.

### How It Works

lisdex uses CASR for the main classification and applies its own rules where CASR
is silent. The dominant factor is one most severity tables omit entirely: whether
the faulting access was a **read** or a **write**.

```
heap-buffer-overflow WRITE  ->  EXPLOITABLE
heap-buffer-overflow READ   ->  NOT_EXPLOITABLE
```

Both are the same CWE. Both are the same function. The write is a foothold; the
read is an information leak at best and usually a crash. A severity table that
keys on the bug class alone will publish "High" for the read, and it will be
wrong.

The second factor is the fault address. A dereference near zero is a null
pointer bug, which is a denial of service. A dereference at a wild address is a
corrupted pointer, which is not.

```
fault address    interpretation
0x0000000000     null dereference        -> not security relevant
0x0000000018     null + small offset     -> still a null dereference
0x00007f2c9bb0   wild pointer            -> security relevant
```

### Industry Standards

| Standard | What it maps to here |
|---|---|
| CWE-787 | Out-of-bounds write |
| CWE-125 | Out-of-bounds read |
| CWE-416 | Use after free |
| CWE-415 | Double free |
| CWE-190 | Integer overflow leading to one of the above |
| CVSS 3.1/4.0 | The score a CNA may assign. lisdex does not guess one. |

## Coordinated Disclosure

### What It Is

You found a bug in someone else's software. Disclosure is the process of telling
them, giving them time to fix it, and then telling everyone else.

### What a Report Needs

The OpenSSF publishes a disclosure template, and lisdex renders it. The parts
that matter:

- What the bug is, in one sentence, with the CWE.
- Where it is: the function, the file, the version you tested.
- How to reproduce it: the exact input, and a script that runs it.
- What an attacker gets.
- Who found it.

### The Fields lisdex Refuses To Fill

An advisory drafted from a fuzzing campaign genuinely does not know some things,
and lisdex leaves them empty rather than guessing:

- **Affected version ranges.** The campaign fuzzed one build. It does not know
  when the bug was introduced or whether older releases have it.
- **CVSS score.** That is the CNA's to assign, and a guessed vector is worse
  than none.
- **Attacker reachability.** Whether this parser is reachable from the network
  in your product is a question about your product.

This is a deliberate design decision and it is defensible on the record: these
are required *keys* in the schemas, typed string-or-null. A CVE record accepts
`defaultStatus: unknown`, and the CNA Rules allow a permanently unknown value.
Leaving them null makes a record incomplete. Inventing them makes it wrong.

### Real World Examples

**CVE-2025-53367, DjVuLibre.** Found by targeted fuzzing of a library that was
not in OSS-Fuzz. Reported through GitHub Security Lab, fixed in 3.5.29. The
research writeup demonstrated ASLR-bypassing code execution, which is what moved
it from "a crash" to "an emergency".

**Project Zero's disclosure trial, announced 2025-07-29.** Google now announces
that a report *exists* within a week of filing, before any technical detail.
The point is to let downstream consumers start asking their vendors, without
handing attackers the bug.

One rule that follows from all of this: **a CVE record must not be the first
public disclosure.** Tell the maintainer, agree a timeline, then publish.

## How the Concepts Relate

```
   source tree
        |
        v
  entry point discovery ......... which functions eat untrusted bytes
        |
        v
  harness + instrumented build .. sanitizers make corruption loud
        |
        v
  fuzzing campaign .............. coverage-guided mutation finds inputs
        |
        v
  crash pile (182 files)
        |
        +--> stack hashing ...... 182 files -> 2 distinct bugs
        |
        +--> classification ..... read vs write -> severity
        |
        v
  advisory + reproducer ......... what a maintainer can act on
```

Each stage is only as good as the one before it. A harness that reads none of
its input produces a campaign with no crashes. A campaign with no symbols
produces crashes that cannot be bucketed. Bucketing that merges two bugs
produces an advisory that describes neither.

## Testing Your Understanding

1. A campaign reports 300 crash files and your triage says 1 distinct bug. What
   are the two most likely explanations, and how would you tell them apart?
2. You get a `heap-buffer-overflow READ of size 1`. The maintainer asks whether
   they should treat it as urgent. What do you tell them, and what would change
   your answer?
3. Why is keying a crash bucket on `libc.so.6+0x4553b` worse than refusing to
   key it at all?
4. Your fuzzer is running at 1,200 execs/sec on a small PNG parser. What is the
   first thing you check?

## Further Reading

**Essential:**

- AddressSanitizer algorithm and shadow mapping: `github.com/google/sanitizers/wiki/AddressSanitizer`
- AFL++ documentation: `aflplus.plus/docs/`
- The OpenSSF vulnerability disclosure template

**Deep dive:**

- Klees et al., *Evaluating Fuzz Testing* (CCS 2018), on why single-trial fuzzing
  comparisons are meaningless.
- Hazimeh, Herrera, Payer, *Magma: A Ground-Truth Fuzzing Benchmark* (2021), the
  canary approach lisdex uses to check its own triage.
- GitHub Security Lab's CVE-2025-53367 writeup, for a complete modern chain from
  fuzz crash to ASLR bypass.
