<!-- ©AngelaMos | 2026 -->
<!-- 04-CHALLENGES.md -->

# marshalsea: Challenges

The best way to understand a gadget chain is to build one. The best way to understand a detector is to get a payload past it. This chapter is a graded set of projects, each naming the files you would touch and the test that would prove you finished. They are ordered roughly by effort.

None of these is a hint at incomplete work. The lab is complete: 268 tests across seven suites, six gate stages, 79 assertions, all green. These are the doors it deliberately leaves open, and two of them are documented deferrals with real tradeoffs that are named honestly below rather than dressed up as exercises.

Before you start:

```bash
just check       # seven suites plus the standalone controls
just gate        # everything, about ten minutes, runs real containers
just corpus      # every adversarial payload and what the detector decided
just scan        # the gadget scanner over whatever this process has loaded
just lint        # rubocop across 37 files
```

**Every challenge below should end two ways: a green suite, and a test that would have failed before your change.** That second half is the part that matters. This project shipped two detector bypasses under 110 passing tests, so a green suite on its own is evidence of nothing. If you add a rule claiming the code does X, go break X and watch a test go red before you believe it.

## Warm-ups

**Add a sink tag the parser does not know about.** The three sink tags are `u`, `U`, and `d`, mapped to `_load`, `marshal_load`, and `_load_data` in `Constants::SINK_METHODS`. Pick any other tag from the format, decide what it would dispatch, and add it. The point of the exercise is discovering how little you have to touch: the table is a frozen constant, `Node#sink?` and `Node#sink_method` are lookups into it, and the detector's ladder never names a tag directly. Prove it with a corpus entry that must be rejected, and then go the other way and confirm your new tag does *not* fire on a stream that merely mentions the class in value position.

**Make the reason-string budget configurable.** `REASON_MAX_NAME_BYTES` is 96 and `REASON_MAX_NAMES` is 8, both hard-coded. Move them onto `Limits` so an application logging to a system with a smaller line budget can shrink them. The test that matters is the adversarial one: a class name of 10,000 bytes containing newlines must still produce a single-line, truncated, `inspect`-escaped reason at whatever ceiling you set. A reason string is attacker-controlled output, and this is a log-injection surface before it is a formatting preference.

**Teach the scanner one more link method.** `to_s` and `coerce` are the two methods currently classified `GATE_LINK`: reachable by a gadget mid-chain, never dispatched by a deserializer. Find another one in the published chain literature, add it to `ENTRY_POINTS` with `gate: GATE_LINK` and `formats: []`, and confirm the link count moves while the reachable count does not. If reachable moves, you classified it wrong, and that is the lesson.

**Add a `--namespace` filter to a scan you care about.** `Scanner.new(namespace: "Gem")` already exists and the justfile already passes it through (`just scan Gem`). Use it to scan only your own application's namespace, then compare against a full scan. The interesting result is usually how few of your own classes are candidates and how many of your dependencies' are.

## Intermediate

**Write a third chain against a different CVE.** The registry is directory-based: drop a file in `lib/marshalsea/chains/`, subclass `Base`, and `inherited` registers it. You need `metadata` (name, vector, cve, gem, affected constraints, kind), a `generate` that returns a live object or document, and a `serialize` if the default `Marshal.dump` is wrong for your entry point. RDoc's CVE-2024-27281 is a reasonable target because the mechanism is documented and the affected ranges are precise; the trap is that four of the "fixed" versions contain an incorrect fix, so your `affected` constraints have to encode `6.3.4.1` and not `6.3.4`. Prove it with a version-boundary test in both directions, the way `erb-def-module` asserts `6.0.1` affected and `6.0.1.1` not.

**Make the scanner follow links into actual chains.** Right now the scanner reports entry points and links as two separate lists and never connects them. That is honest but it stops one step short of the interesting question: *given this entry point, what can it reach?* Build a second pass that, for each reachable entry point, walks the method body with Prism looking for calls to methods on ivar-held receivers, and emits candidate two-step chains. The honest deliverable is not a chain finder, it is a *ranked* list plus a written statement of its false-positive rate, because a static walk cannot know what those ivars will hold at load time. Measure that rate against the one chain in this repo that is known to be real.

**Close the guard's `#hash` hole without the strict-mode cost.** `LoadGuard` deliberately does not watch `#hash` and `#eql?` by default, because they are among the hottest methods in Ruby. `strict: true` watches them and pays for it. Find a third option: watch `#hash` but filter the `TracePoint` to receivers whose class is outside a permitted set before doing any other work, or use `TracePoint#enable(target:)` to scope the trace rather than filtering inside the handler. Then **measure it**, on the payload sizes that matter, and publish the number with the payload size attached. If your version is not meaningfully cheaper than `strict: true`, that is a real result and should be written down as one.

**Build the authenticated session envelope.** The target deserializes a base64 cookie with no signature at all, which is realistic for a teaching target and is *not* what a real application should do. Add an HMAC or AEAD envelope in front of `Marshal.load`, verify it before the bytes reach any deserializer, and then write the test that makes the lesson land: **a valid signature does not make the payload safe.** Sign a real gadget payload with the correct key and confirm it still executes. That is CVE-2019-5420 and CVE-2018-15133 reproduced in your own code, and it is the cleanest possible demonstration that signing addresses tampering, not untrusted origin. This is a deliberate scope decision in the current lab, not an oversight; the reason it was left out is that the two-allowlists lesson is clearer without a crypto layer in the way.

**Extend the Psych inspector to Oj.** Ruby's `oj` gem supports object instantiation from JSON in its `:object` mode, which is its **default**. A JSON parser that is object-injection-capable out of the box is the most surprising fact in this whole area and it has no representation in this lab. Write a third reader that reads Oj-mode JSON without loading it, reports which classes it would instantiate, and produces a `Decision` in the same vocabulary as the other two. The design constraint is the interesting part: the two existing readers share a `Decision` class deliberately, so a third one that needed a different shape would be telling you something about the abstraction.

## Advanced

**Build the eager-load stage the design contract asks for.** The scanner can only see classes that have been required, so a scan of a bare process sees 691 modules and a scan inside a booted Rails app sees several thousand. The obvious fix is a stage that requires every file in every installed gem before scanning. It is also **arbitrary code execution by design**: requiring a gem runs its top-level code, so an eager-load stage run against untrusted gems is a supply-chain footgun pointed at the operator. Build it, and build the isolation that makes it defensible: a separate container with no network, a read-only mount, a timeout, and an explicit opt-in flag whose help text says what it does. The deliverable that matters is the written threat model, not the loop. This is the single largest open item in the project and it was deferred for exactly this reason.

**Model a second interpreter version.** The parser models Ruby 3.4 and newer, and the gem floor is `>= 3.4` because `Marshal.load` did not validate the bignum sign byte until 3.4. That means the parser and the interpreter *disagree* on 3.3, and `just package` proves that boundary in both directions on every run. Make the parser version-aware: accept a target version, relax the bignum sign check below 3.4, and lower the floor. Then write the differential test that keeps you honest, running the same stream through the real `Marshal.load` on both a 3.3 and a 3.4 container and asserting the parser agrees with **each** of them. You will discover quickly that "which Ruby is this stream for" is not a question the stream can answer, which is the real lesson.

**Attack the parser's forensic tolerance.** The parser deliberately keeps going where CRuby stops, and the detector rejects on the anomalies it records. That split is the design, but it is also an attack surface: any place the parser's model of the format diverges from CRuby's is a potential differential. Go find one. Build a fuzzer that generates streams, feeds each to both the parser and a sandboxed real `Marshal.load`, and flags every case where the parser reports a class or sink set that the interpreter's actual behaviour contradicts. This is the highest-value security work available in the repo, and a single confirmed differential would be a real finding.

**Write the detector that beats a denylist.** [01-CONCEPTS.md](./01-CONCEPTS.md) argues that denylist scanning of a serialization stream loses on architecture, with 26+ picklescan CVEs and CWE-184 as the evidence. Take that seriously and design the alternative. What would a *structural* policy look like, one that decides on the shape of the graph rather than on a list of names? A stream containing only primitives, arrays, hashes with primitive keys, and strings is safe by construction, regardless of which classes exist. Implement that as a fourth policy, measure how many real-world payloads it rejects (that number will be high, and that is the honest cost), and write down where the boundary between "safe by construction" and "useful" actually sits.

**Make the target a real vulnerable-app corpus.** The target has four endpoints across two deserializers. Add the second-order sink from CVE-2022-32224: a route that writes attacker-influenced data to a store and a *different* route that reads it back and deserializes it, so the payload never appears in the request that triggers execution. That is the shape that defeats a trust boundary drawn at the HTTP edge, and it is much harder to reason about than the direct case. The gate stage that proves it has to span two requests, which is itself a useful thing to have built.

## A capstone: get a payload past the detector

If you want one project that ties the whole lab together, do this one.

The detector's `LIMITATION_NOTICE` says out loud that an accept decision means only "these bytes matched this policy." Your job is to make that concrete: **find a stream the strict-allowlist detector accepts that still does something an operator would not sanction.**

You have three angles and they are all legitimate:

1. **Find a class worth allowlisting that is dangerous anyway.** The notice concedes this directly: "Class allowlisting compares serialized names. It does not prove that the corresponding Ruby code is harmless." An application that allowlists `ERB` accepts the published CVE chain, because that payload carries zero sink tags. Find a second class with the same property.
2. **Find a dispatch the parser does not model.** The ladder covers sink tags, `#hash` and `#eql?` in key position, and `#<=>` in `Range` endpoints. Three of those five rules were added because a bypass shipped first. There is no reason to believe the list is complete. Go read `marshal.c` and find the sixth.
3. **Find a parser-versus-interpreter differential.** If the parser and CRuby disagree about what a stream contains, the detector is deciding about a graph that is not the one that will be loaded.

The rules of the exercise, which are the same rules the project holds itself to:

- Your bypass must be **reproducible from a byte string**, not from a hand-built object graph. If you cannot write it down as bytes, it is not a payload.
- It must be accepted under `strict_allowlist`, not just under `deny_sinks_only`. Beating the weaker policy proves nothing.
- Ship the fix **and the mutant**: add the rule that catches it, then gut the rule and watch the corpus entry go red. A rule you cannot kill is a rule you have not tested.
- Add a **negative control** alongside it: a payload of the same shape that must still be accepted. Otherwise you cannot tell your new rule from a detector that rejects everything.

When you have done that once, you will understand this bug class better than any write-up teaches, because you will have been on both sides of the same file.

## Where to go next

Re-read [01-CONCEPTS.md](./01-CONCEPTS.md) with the code from [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) fresh in your head. The two-allowlists argument reads differently once you have seen `in_hash_key_position` splice a payload together byte by byte, and the Equifax debunk reads differently once you know how much work it takes to be sure about one claim.

Then run `just corpus`, pick any line in that table, and go find the test that put it there.
