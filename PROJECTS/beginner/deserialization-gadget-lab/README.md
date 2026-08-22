<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

```ruby
███╗   ███╗ █████╗ ██████╗ ███████╗██╗  ██╗ █████╗ ██╗     ███████╗███████╗ █████╗
████╗ ████║██╔══██╗██╔══██╗██╔════╝██║  ██║██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗
██╔████╔██║███████║██████╔╝███████╗███████║███████║██║     ███████╗█████╗  ███████║
██║╚██╔╝██║██╔══██║██╔══██╗╚════██║██╔══██║██╔══██║██║     ╚════██║██╔══╝  ██╔══██║
██║ ╚═╝ ██║██║  ██║██║  ██║███████║██║  ██║██║  ██║███████╗███████║███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2341-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/deserialization-gadget-lab)
[![Ruby](https://img.shields.io/badge/Ruby-4.0-CC342D?style=flat&logo=ruby&logoColor=white)](https://www.ruby-lang.org)
[![Gem](https://img.shields.io/badge/gem-marshalsea-E9573F?style=flat&logo=rubygems&logoColor=white)](https://rubygems.org/gems/marshalsea)
[![Formats](https://img.shields.io/badge/formats-Marshal%20%2B%20YAML-6D4AFF?style=flat)](#the-two-allowlists)
[![CVE](https://img.shields.io/badge/CVE--2026--41316-CVSS%208.1-4457E8?style=flat)](https://www.ruby-lang.org/en/news/2026/04/21/erb-cve-2026-41316/)
[![Tests](https://img.shields.io/badge/tests-268-8B5CF6?style=flat)](#build-and-test)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> A Ruby object-deserialization security lab. It reads `Marshal` and YAML bytes without ever reviving them, tells you which classes are in there and which methods those bytes would fire, hunts your loaded code for the classes that make usable gadgets, builds a working payload for a real 2026 CVE, and then stands up a deliberately vulnerable Sinatra target so you can watch the exploit land over HTTP and watch the defense stop it. It ships as a gem plus a container, and every defense in it comes with a written statement of what it cannot do.

## Why deserialization is its own bug class

Serializing an object freezes it into bytes. Deserializing thaws it back. The trap is that thawing is not a passive copy: rebuilding an object calls methods on it, and if an attacker chooses the bytes then the attacker chooses which methods run. String enough unrelated standard-library methods together and code execution falls out the far end. A gadget chain is a Rube Goldberg machine, and nowhere in those bytes is there an instruction that says "run a command."

This is not a Ruby quirk. It is the same shape as Java deserialization, PHP POP chains, and Python pickle. CWE-502 is the seventh most common weakness in the CISA Known Exploited Vulnerabilities catalog, at 69 of 1,653 entries, and **34.8% of those carry known ransomware use against a 20.1% baseline** for the catalog as a whole. Ruby itself has shipped two advisories in this class recently: CVE-2024-27281 in RDoc and CVE-2026-41316 in ERB, the one this lab reproduces.

It is also the bug class the industry most consistently gets wrong in retellings. Equifax is cited as an insecure-deserialization breach in an enormous number of write-ups. It was OGNL injection, CWE-755. The Apache Software Foundation published that correction on 2017-09-14 and the correction lost. `learn/01-CONCEPTS.md` opens with that debunk on purpose, because a repository that teaches this class should be able to show its work.

## What it is

Not a stub. Every capability below is exercised by 268 tests across seven suites and a six-stage gate that runs real containers, with 79 assertions that must all pass.

**A reader that never loads (Marshal)**
- Parses the Marshal binary format without calling `Marshal.load`: version bytes, type tags, instance variables, object links, symbols, floats
- Extracts referenced class names and sink tags without instantiating anything at all
- Rejects truncated streams, unsupported versions, unknown tags, out-of-bounds object links and symlinks, trailing bytes, and excessive nesting, and bounds fourteen separate resource axes by default rather than on request
- Labels what it cannot decode instead of guessing: a legacy float mantissa becomes an `undecoded_tail`, and a role slot holding the wrong node type becomes a named anomaly rather than a silent pass

**A reader that never loads (YAML)**
- Reads a document through `Psych.parse_stream`, which builds an AST and revives nothing
- Reports every `!ruby/*` tag with the method that tag would dispatch: `init_with`, `[]=`, or `marshal_load`
- Counts aliases instead of expanding them, so an alias bomb costs nothing to inspect

**A boundary detector with three states and no comforting lies**
- One `state` per decision, `proceed` / `blocked` / `observed`, mutually exclusive by construction. There is no `accepted?`, because "did the policy permit this" and "is this stream clean" have different answers under monitoring mode and one predicate cannot answer both
- Rejects on sink tags, on hash keys whose `#hash` or `#eql?` would dispatch during load, on `Range` endpoints whose `#<=>` would dispatch, and on unapproved class names, each with a reason that is a true statement about that specific stream
- Bounds how much attacker-controlled text reaches your logs, and escapes control bytes so a class name cannot forge a log line

**A runtime guard that vetoes instead of reporting**
- A `TracePoint` on `:call` fires *before* a method body runs, which is exactly the veto point a `Marshal.load` allowlist proc denies you
- Refuses an unpermitted `marshal_load`, `_load`, `_load_data`, `method_missing`, or `respond_to_missing?` before the body executes, thread-scoped so one request does not tax the process
- Ships its own bypasses, including the one it deliberately leaves open by default

**A reflection scanner over the loaded class graph**
- Sorts auto-invoked methods into entry points a deserializer dispatches directly and links a gadget calls once a chain is already moving, because `to_s` is a link and never an entry point and conflating them is a false positive
- Each entry point carries the format that reaches it, the gate that guards it, and the argument count the deserializer supplies, so a `marshal_load` whose arity cannot accept the call is not reported as reachable
- Counts every error it swallows, names the site, and treats a method it could not analyse as reachable rather than inert, so under-reporting is visible instead of silent

**Payloads, labelled by what they actually are**
- `erb-def-module` is a **chain**: it reaches `ERB#def_module` through an `ActiveSupport` proxy in hash-key position, so it executes inside `Marshal.load` with no cooperation from the application
- `erb-def-method` is a **primitive**: it forges an ERB object past the `@_init` guard and stays inert until the application calls a `def_*` method on it
- The builder never runs its own payload. A key-position stream is spliced from a standalone dump instead of assembled by building the hash locally, and it refuses any object graph whose link indices would shift

**A vulnerable target you can attack over HTTP**
- Sinatra on Rack 3 in a container with no route off the host, read-only root, dropped capabilities, and pinned dependencies
- Four endpoints: load a Marshal cookie, inspect it first, then the same pair again over YAML

## Quick Start

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
decision.reason     # => "stream reaches Gem::Requirement#marshal_load during load, ..."

Marshal.load(decision.snapshot) if decision.proceed?
```

Nothing above instantiates a class, calls a constructor, or invokes `Marshal.load`. Read `Marshalsea::Marshal::BoundaryDetector::LIMITATION_NOTICE` before you rely on `proceed?`.

Then run the lab itself from a checkout:

```bash
just gate        # everything: suites, matrix, exploit, detector, target, packaging
just target      # stand up the vulnerable app and attack it over HTTP
just scan        # run the gadget scanner over loaded modules
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see every recipe.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## The two allowlists

This is the spine of the project and the reason it exists. Everyone teaches "do not deserialize untrusted input." Almost nobody explains why the obvious fix fails.

The obvious fix is handing `Marshal.load` an allowlist proc. It does not work, and the reason is one line of `marshal.c`: the proc runs in `r_post_proc`, which is invoked *after* `load_funcall(... s_mload ...)`. Psych's allowlist genuinely is a veto, for exactly one reason: it checks the tag *before* revival.

```
Marshal   bytes ──> build the object ──> RUN its hook ──> your allowlist runs
                                         ^^^^^^^^^^^^     too late, an autopsy

Psych     bytes ──> CHECK the tag ──> refuse
                    ^^^^^^^^^^^^^^   in time, a bouncer
```

Same intent, opposite outcome, decided entirely by where the check sits. The target exposes both so you can `curl` the difference: `/render` and `/yaml/unsafe` both reach code execution with the same ERB object, and `/yaml/safe` refuses it by tag while `/render/safe` can only inspect the bytes and hope.

## The two payloads

| Payload | Kind | Enters through | Fires when | Needs |
|---------|------|----------------|------------|-------|
| `erb-def-module` | **chain** | ungated `#hash` on a hash key | inside `Marshal.load`, no application call | activesupport loaded in the target |
| `erb-def-method` | **primitive** | the `@_init` guard bypass | only when the application calls `def_method` | nothing |

Both target CVE-2026-41316 (published 2026-04-23, CVSS 8.1, CWE-502 plus CWE-693). Ruby 2.7.0 added an `@_init` guard to stop `Marshal.load` code execution on ERB objects, and `def_method`, `def_module`, and `def_class` never checked it. Six years of a correct defense with three doors left open. The exploit gate proves both halves: the chain fires on erb 6.0.1 and is blocked on 6.0.1.1, one `docker pull` apart.

## Limits

Every defense here is a trade, and the code says so out loud rather than in a footnote.

- **A stream that passes inspection is not a safe stream.** `proceed?` means the bytes matched a policy. It does not mean the payload is harmless, and `LIMITATION_NOTICE` says exactly that. The published CVE chain produces **zero sink tags**, so sink detection alone never catches it; only class allowlisting does.
- **The runtime guard is defense in depth, not a boundary.** Its cost is not a multiplier. Enabling a `TracePoint` costs a near-constant ~46 microseconds per load, so it is 1.0x on a 488 KB document and **40x on a 45-byte session cookie**, and a cookie is what this lab deserializes. It also covers the load window only: a class carrying no hook at all is built freely and fires whenever the application next touches it.
- **The scanner sees only what is loaded.** `ObjectSpace` cannot report a class nobody has required yet. On a stock `ruby:4.0-slim` it narrows 124 ungated candidates to 28 reachable, and 142 of its candidates are C-defined with no Ruby source at all, which it reports as `unanalysable` rather than scoring as inert. Those figures are a statement about what one process had loaded, not about Ruby; re-run `just scan` rather than quoting them.
- **The gem floor is `>= 3.4` and it was measured, not chosen.** `Marshal.load` did not validate the bignum sign byte until 3.4. The parser accepts `+` and `-` only, so it models 3.4 and newer; run it on 3.3 and it disagrees with the interpreter it exists to model. `just package` re-proves that in both directions on every run.

## Architecture

Two readers, one vocabulary. Nothing in the inspection path ever revives an object.

```
   Marshal bytes ──> Parser ──> Node graph ──┐
                                             ├──>  BoundaryDetector  ──>  Decision
   YAML document ──> Inspector ──> Document ─┘         (proceed / blocked / observed)

   loaded classes ──> Scanner ──> entry points + links      (offense: what is usable)
   chain registry ──> generate ──> serialize                (offense: build the payload)
   Marshal.load   ──> LoadGuard (TracePoint :call)          (defense: veto before the body)
```

The parser is deliberately forensic: it keeps parsing a stream that CRuby would refuse, so a sink hidden in a slot where a symbol belongs stays visible in the report instead of vanishing behind a parse error. The detector is the strict half, and it rejects on the anomaly the parser recorded. That split is why a hostile stream can be both fully described and firmly refused.

## Build and Test

```bash
just check       # the seven suites plus the standalone controls
just gate        # check + matrix + exploit + detector + target + package
just lint        # rubocop, 37 files
just build       # build the gem into tmp/build
```

Everything runs in Docker against a pinned Ruby, and every gate container runs with `--network none` except the target, which gets its own internal network with no route off the host.

The discipline here is that a green suite proves nothing until the thing under test has been mutated. Every rule added to this project ships with the mutant that kills it, every gate carries an input it must reject, and the tests that matter most are differential: they execute real `Marshal.load` and real `Psych`, observe what actually dispatched, and assert the model agrees, with liveness guards on both directions so a dead oracle cannot pass quietly.

## Project Structure

```
deserialization-gadget-lab/
├── lib/marshalsea/
│   ├── marshal/
│   │   ├── parser.rb            # the Marshal format reader that never calls Marshal.load
│   │   ├── node.rb              # the parse graph, sealed and frozen before it is returned
│   │   ├── boundary_detector.rb # policy, three decision states, limitation notice
│   │   ├── load_guard.rb        # TracePoint veto that fires before the hook body
│   │   ├── limits.rb            # fourteen resource ceilings, all opt-out
│   │   ├── float_body.rb        # float decoding that labels what it cannot decode
│   │   └── constants.rb errors.rb
│   ├── psych/inspector.rb       # YAML AST reader, revives nothing
│   ├── chains/                  # directory is the chain identity, no registry to rot
│   │   ├── base.rb erb_def_method.rb erb_def_module.rb psych_init_with.rb
│   ├── scanner.rb               # reflection over the loaded class graph
│   └── chains.rb version.rb
├── target/                      # the deliberately vulnerable Sinatra app + containers
├── scripts/                     # the six gate stages and the gem auditor
├── test/                        # seven suites, the adversarial corpus, standalone controls
├── learn/                       # the teaching track (public)
└── justfile
```

## Learn

This project ships a full teaching track. Read it in order, or jump to what you need.

| Doc | What it covers |
|-----|----------------|
| [`learn/00-OVERVIEW.md`](learn/00-OVERVIEW.md) | What the lab is, prerequisites, the project layout, and a quick tour |
| [`learn/01-CONCEPTS.md`](learn/01-CONCEPTS.md) | The deserialization bug class, opening with the Equifax debunk, grounded in verified incidents |
| [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) | The two readers, the gated versus ungated dispatch axis, and why the detector and parser disagree on purpose |
| [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) | A code walkthrough from Marshal tags to a working chain, with the ActiveSupport proxy as the showpiece |
| [`learn/04-CHALLENGES.md`](learn/04-CHALLENGES.md) | Extension ideas, from a new chain to closing the guard's deferred-execution bypass |

## License

[AGPL 3.0](LICENSE).
