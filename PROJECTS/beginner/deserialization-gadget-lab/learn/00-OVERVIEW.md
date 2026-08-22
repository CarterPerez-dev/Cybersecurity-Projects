<!-- ©AngelaMos | 2026 -->
<!-- 00-OVERVIEW.md -->

# marshalsea: Overview

## What This Is

A Ruby object-deserialization security lab, shipped as a gem plus a container. You hand it `Marshal` bytes or a YAML document and it tells you which classes are in there and which methods those bytes would fire, **without ever reviving anything**. It hunts your loaded class graph for the classes that make usable gadgets. It builds a working payload for a real 2026 CVE. And then it stands up a deliberately vulnerable Sinatra app so you can watch that payload land over HTTP and watch the defense stop it.

The whole project is organized around one question that almost every write-up skips: *why does the obvious fix not work?* Everyone says "do not deserialize untrusted input." Fewer people can tell you why handing `Marshal.load` an allowlist proc fails, why the same allowlist idea in Psych succeeds, and why the difference is four lines apart in `marshal.c`. That question is the spine of this lab, and every defense it ships comes with a written statement of what it cannot do.

Nothing here is a stub. 268 tests across seven suites, plus a six-stage gate that drives real containers with 79 assertions that must all pass.

## Why This Matters

Serializing an object freezes it into bytes. Deserializing thaws it back. The trap is that thawing is not a passive copy: rebuilding an object calls methods on it, and if an attacker chooses the bytes, the attacker chooses which methods run. String enough unrelated standard-library methods together and code execution falls out the far end. Nowhere in those bytes is there an instruction that says "run a command." That is what makes it a **gadget chain**, and it is why the name of this class of bug is so often mis-taught.

This is not a Ruby quirk. Java, PHP, Python, and .NET all shipped a convenient serializer and all inherited the same bug. The honest numbers, all reproducible:

- **69 of 1,653 CISA KEV entries are CWE-502** (catalog version 2026.07.24), making it the **seventh most common weakness** in the catalog of vulnerabilities confirmed exploited in the wild.
- **34.8% of those carry known ransomware use, against a 20.1% baseline** for the catalog as a whole. Deserialization bugs are roughly 1.7x more likely than average to end up in a ransomware crew's toolkit.
- **The rate is not declining.** 2025 was the highest single year on record for CWE-502 KEV additions, and Microsoft SharePoint alone picked up five of them inside twelve months.

What you will *not* find in this repo is a dollar figure. There is no credible, citable number for the total financial cost of this bug class, and [01-CONCEPTS.md](./01-CONCEPTS.md) says so instead of laundering a vendor statistic into an academic-looking citation.

**Real-world scenarios where this applies:**
- **Reviewing a session or cache layer.** Rails cookies were Marshal-serialized before 4.1, and Active Support cache stores still deserialize what they read back. The signature is the only control, and CVE-2019-5420 is the case where the signature worked and the *key* was guessable.
- **Auditing a second-order sink.** CVE-2022-32224 is the modern shape: untrusted data arrives from your own database, not over HTTP, and defeats any threat model that draws the trust boundary at the request edge.
- **Building a detector.** If you are writing a scanner for serialized payloads, the most useful thing in this repo is the evidence that denylist scanning of a serialization format loses on architecture, not on effort. `picklescan`, the scanner the Python ML ecosystem relies on, has accumulated **26+ CVEs of its own**, and Trail of Bits' `fickling` has the same failure. Both have been assigned CWE-184, "Incomplete List of Disallowed Inputs."

## What You'll Learn

**Security concepts:**
- **Gated versus ungated dispatch.** The axis this whole lab is built on, and one that is not written down in the published Ruby literature. `marshal_load` and `_load` are gated: `Marshal` calls `respond_to?` first and raises `TypeError` on a false answer. `hash`, `eql?`, `<=>`, `[]=`, and Psych's `init_with` are dispatched blind. A method-erased proxy class is therefore a *valid* YAML entry point and an *invalid* Marshal one. Same class, opposite outcome.
- **Why one allowlist is a bouncer and the other is an autopsy.** `Marshal.load`'s proc runs in `r_post_proc`, after `load_funcall` has already fired your gadget. Psych checks the tag *before* revival. Identical intent, opposite outcome, decided entirely by where the check sits.
- **Entry points versus links.** `to_s` is a real link in the published universal chain, but `Marshal` never calls it. Conflating "a method a gadget calls" with "a method the deserializer dispatches" is a false-positive factory, and the scanner models them as two different kinds of node.
- **What a partial guard costs you.** CVE-2026-41316 is the worked example: Ruby 2.7.0 added a guard to stop `Marshal.load` code execution on ERB objects, and it covered two of the five entry points. Six years of a correct defense with three doors left open. NVD files it CWE-502 **and CWE-693, Protection Mechanism Failure**, and the dual mapping is the story.
- **How to tell this bug class apart from the ones it gets confused with.** The chapter opens by debunking the most-cited example of it.

**Technical skills:**
- **Reading a binary format without executing it.** The Marshal wire format tag by tag: version bytes, fixnum packing, symbol tables, object back-references, instance variables, the three sink tags.
- **Reflection over a live class graph.** `ObjectSpace.each_object(Module)`, `instance_method`, `source_location`, and Prism to decide whether a method body actually touches object state, with every swallowed error counted and named.
- **Building a payload without detonating it.** Constructing `{proxy => 1}` in Ruby calls `#hash` on the key and fires the chain *in your own process*. The builder splices a key-position stream out of a standalone dump instead.
- **Vetoing at a point the language does not offer you.** A `TracePoint` on `:call` fires before a method body runs, which is exactly the veto point the allowlist proc denies you.

**Tools and techniques:**
- **`just`** as the command runner, with every stage running in a pinned Docker container and `--network none` everywhere except the target.
- **Minitest** for seven suites, and a **differential** discipline: execute real `Marshal.load` and real `Psych`, observe what actually dispatched, assert the model agrees, with liveness guards on both directions so a dead oracle cannot pass quietly.
- **Prism** for source analysis, and **Sinatra on Rack 3** for the vulnerable target.

## Prerequisites

You do not need prior deserialization or Ruby-security experience. This is a beginner-tier project in the sense that it starts from first principles, not in the sense that the material is shallow.

**Required knowledge:**
- **Ruby basics.** Classes, modules, instance variables, blocks. If you can read `def foo(x)` and know what `@bar` means, you can read this code.
- **Bytes.** What a byte is, that `"\x04\b"` is two bytes and not six characters, and roughly what a hex dump looks like.
- **What "the standard library is loaded into your process" means.** The scanner's entire premise is that a class nobody has required yet cannot be a gadget.

**Tools you'll need:**
- **Docker**, and that is genuinely it. Every recipe in the justfile runs in a container against a pinned Ruby. You never need a Ruby on your host.
- **`just`.** Install with `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`.
- **The gem, if you only want the reader.** `gem install marshalsea` needs Ruby 3.4 or newer and no container at all.

**Helpful but not required:**
- A skim of [CWE-502](https://cwe.mitre.org/data/definitions/502.html), so the vocabulary in the concepts chapter lands faster.
- Familiarity with any *other* language's version of this bug (Java `readObject`, PHP `unserialize`, Python `pickle`). The concepts chapter maps all four onto each other deliberately.

## Quick Start

Install the reader:

```bash
gem install marshalsea
```

Look at a payload without running it:

```ruby
require "marshalsea"

payload = Marshal.dump(Gem::Requirement.new(">= 0"))
result  = Marshalsea::Marshal::Parser.new(payload).parse

result.class_names
# => ["Gem::Requirement", "Gem::Version"]

result.sinks.map { |s| "#{s.class_name}##{s.sink_method}" }
# => ["Gem::Requirement#marshal_load", "Gem::Version#marshal_load"]
```

Make a decision instead of an observation:

```ruby
detector = Marshalsea::Marshal::BoundaryDetector.new(allowed_class_names: %w[Hash String])
decision = detector.inspect_stream(untrusted_bytes)

decision.blocked?   # => true
decision.reason
# => "stream reaches \"Gem::Requirement\"#marshal_load during load, before any allowlist can run"

Marshal.load(decision.snapshot) if decision.proceed?
```

Nothing above instantiates a class, calls a constructor, or invokes `Marshal.load`. Read `Marshalsea::Marshal::BoundaryDetector::LIMITATION_NOTICE` before you rely on `proceed?`; it is a constant in the library precisely so it cannot be skipped.

Then run the lab itself from a checkout:

```bash
just scan        # hunt the loaded class graph for usable gadget entry points
just corpus      # every adversarial payload, and what the detector decides about each
just target      # stand up the vulnerable app and attack it over HTTP
just gate        # everything: suites, version matrix, exploit, detector, target, packaging
```

`just scan` on a stock `ruby:4.0-slim` prints a header and then every entry point it judged reachable:

```
modules=691 candidates=193 gated=11 reachable=43 suppressed=3 candidates_lost=false
analysed=43 unanalysable=142 unreadable=8

  gated      Date._load
  ungated    Gem::Requirement#hash                /usr/local/lib/ruby/4.0.0/rubygems/requirement.rb:195
  ungated    Gem::Specification#method_missing    /usr/local/lib/ruby/4.0.0/rubygems/specification.rb:2055
  ...
  gated      Time._load

suppressed errors (this scan under-reports):
  source_parse     3

142 candidates have no Ruby source and were never analysed; the reachability filter does not cover them
```

Read the last two blocks first. The scanner reports what it *could not* see with the same prominence as what it found, and that is deliberate: a gadget-discovery tool that quietly under-reports is worse than no tool at all.

> [!TIP]
> Those numbers are image-dependent and load-dependent, not facts about Ruby. `ObjectSpace` cannot report a class nobody has required yet, so requiring more code produces more candidates. Re-run `just scan` in your own environment rather than trusting the figures printed here.

## Project Structure

```
deserialization-gadget-lab/
├── lib/marshalsea/
│   ├── marshal/
│   │   ├── parser.rb            # the Marshal format reader that never calls Marshal.load
│   │   ├── node.rb              # the parse graph, sealed and frozen before it is returned
│   │   ├── boundary_detector.rb # policy, three decision states, limitation notice
│   │   ├── load_guard.rb        # TracePoint veto that fires before the hook body
│   │   ├── limits.rb            # fourteen resource ceilings, all on by default
│   │   ├── float_body.rb        # float decoding that labels what it cannot decode
│   │   └── constants.rb errors.rb
│   ├── psych/inspector.rb       # YAML AST reader, revives nothing
│   ├── chains/                  # the directory is the chain identity, no registry to rot
│   │   ├── base.rb erb_def_method.rb erb_def_module.rb psych_init_with.rb
│   ├── scanner.rb               # reflection over the loaded class graph
│   └── chains.rb version.rb
├── target/                      # the deliberately vulnerable Sinatra app + containers
├── scripts/                     # the six gate stages and the gem auditor
├── test/                        # seven suites, the adversarial corpus, standalone controls
├── learn/                       # this teaching track
└── justfile
```

The single most important seam to understand first is the split between `parser.rb` and `boundary_detector.rb`. The parser is deliberately **forensic**: it keeps parsing a stream that CRuby itself would refuse, so a sink hidden in a slot where a symbol belongs stays visible in the report instead of vanishing behind a parse error. The detector is the **strict** half, and it rejects on the anomaly the parser recorded. That split is why a hostile stream can be both fully described and firmly refused, and it is the design decision the rest of the library hangs off.

## Next Steps

1. **Understand the ideas.** Read [01-CONCEPTS.md](./01-CONCEPTS.md). It opens by debunking the most-cited example of this bug class, then builds the gated-versus-ungated axis, the two-allowlists argument, and the verified incident record behind all of it.
2. **See the design.** Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) for the two readers, the three decision states, the scanner's taxonomy table, and why the parser and the detector disagree on purpose.
3. **Walk the code.** Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) to trace bytes into a node graph, a node graph into a decision, and a live object into a payload, with the ActiveSupport proxy chain as the showpiece.
4. **Extend it.** Read [04-CHALLENGES.md](./04-CHALLENGES.md) for projects from writing a new chain to closing the guard's deferred-execution bypass.

## Common Issues

**`just scan` reports far fewer candidates than you expected**
```
modules=691 candidates=193 gated=11 reachable=43
```
This is correct, not a bug. `ObjectSpace.each_object(Module)` sees only what the current process has loaded, and a bare `ruby -Ilib` process has loaded very little. Require `active_support`, or scan inside your own application's boot, and the numbers climb. A gadget scanner tells you what chains exist in *this* process, which is a statement about your dependency graph, not about Ruby.

**The detector accepted a stream and something still went wrong**
```
decision.proceed?  # => true
```
Read `Marshalsea::Marshal::BoundaryDetector::LIMITATION_NOTICE`. `proceed?` means *these bytes matched the policy you configured*. It does not mean the payload is safe. The published CVE-2026-41316 chain produces **zero sink tags**, so a sink-only policy never catches it; only class allowlisting does, and an application that allowlists `ERB` will accept it anyway.

**The runtime guard made things slower than the documentation implied**
```
LoadGuard, 45-byte session cookie: 40x
```
Also correct. The guard's cost is not a multiplier, it is a near-constant **~46 microseconds per load** spent enabling the `TracePoint`. That is 1.0x on a 488 KB document and 40x on a session cookie, and a session cookie is exactly what this lab deserializes. The number is published with the payload size attached because publishing it without one reads as an endorsement it has not earned.

**The gem refuses to install on Ruby 3.3**
```
marshalsea requires Ruby version >= 3.4
```
Measured, not chosen. `Marshal.load` did not validate the bignum sign byte until 3.4. The parser accepts `+` and `-` only, so it models 3.4 and newer; run it on 3.3 and it disagrees with the interpreter it exists to model. `just package` re-proves that boundary in both directions on every run.

## Related Projects

If you found this interesting, look at:
- **binary-analysis-tool**: the same "read a file format precisely and never execute it" muscle, applied to executables instead of object graphs.
- **api-security-scanner**: the other half of the sink question, finding where untrusted bytes enter an application in the first place.
- **lisdex** (zero-day-vulnerability-scanner): what happens when the parser you are auditing is written in C and the failure mode is memory corruption rather than object injection.
