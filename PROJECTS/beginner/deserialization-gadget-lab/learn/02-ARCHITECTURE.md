<!-- ©AngelaMos | 2026 -->
<!-- 02-ARCHITECTURE.md -->

# marshalsea: Architecture

This chapter is the design. It explains the pieces, the seams between them, and the handful of decisions that look strange until you know what they are protecting against. The code walkthrough is in [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md); this is the map you want open while you read it.

## The shape

Two readers, one vocabulary. Nothing in the inspection path ever revives an object.

```
   Marshal bytes ──> Parser ──> Node graph ──┐
                                             ├──>  BoundaryDetector  ──>  Decision
   YAML document ──> Inspector ──> Document ─┘         (proceed / blocked / observed)

   loaded classes ──> Scanner ──> entry points + links      (offense: what is usable)
   chain registry ──> generate ──> serialize                (offense: build the payload)
   Marshal.load   ──> LoadGuard (TracePoint :call)          (defense: veto before the body)
```

The two halves of the library never call each other. The offensive half builds payloads and hunts for gadgets; the defensive half reads bytes and makes decisions. They meet only in the test suite and the gate, where each one's output is the other one's input. That is deliberate: a detector whose author also wrote the payloads will only catch the payloads its author imagined, so the adversarial corpus exists as a third artifact that both halves are measured against.

## Reader one: the Marshal parser

`Marshal` is a binary format. Two header bytes for the version, then a tree of tagged values. The parser reads it byte by byte and builds a node graph. It never calls `Marshal.load`, never resolves a class name to a real class, and never allocates anything from the stream except strings and integers.

The tags it understands, with the ones that matter marked:

```
   0 nil        T true       F false      i fixnum      l bignum      f float
   " string     : symbol     ; symlink    @ object link  / regexp
   [ array      { hash       } hash+default          S struct
   I ivar       o object     e extended   C userclass
   c class      m module     M module (old)
   u userdef     <- SINK, dispatches Klass._load
   U usermarshal <- SINK, dispatches obj.marshal_load
   d data        <- SINK, dispatches Klass._load_data
```

Three tags are **sinks**: `u`, `U`, and `d`. Seeing one in a stream is a true statement that loading the stream will dispatch a specific method on a specific class name, before any allowlist proc can run. That is the highest-confidence signal the parser produces, and it is also, importantly, not sufficient. The published CVE chain produces **zero sink tags**, because ERB defines no `marshal_load`. Sink detection alone never catches it.

### The parser is forensic on purpose

Here is the design decision that looks wrong at first.

CRuby refuses a stream where the instance-variable name slot holds something that is not a symbol. It raises and stops. This parser **keeps going**, records the problem as a named anomaly, and returns a complete graph anyway.

Watch the difference on the same 17 bytes:

```
Marshal.load: ArgumentError: dump format error for symbol(0x69)
parser:       class_names=["Object"] anomalies=["instance variable name slot holds fixnum, not a symbol"]
detector:     blocked: stream is not canonical Marshal: instance variable name slot holds fixnum, not a
              symbol, so Marshal.load refuses it and there is nothing here to permit
```

Why bother, if `Marshal.load` would refuse it anyway? Because **the goal of the parser is description, not admission control.** If a hostile stream hides a sink in a slot where a symbol belongs, a parser that raises on the first structural surprise reports "malformed" and tells you nothing about what was in there. A parser that keeps going reports the class name, the sink, *and* the anomaly. You get a forensic record instead of an error message.

The strictness lives one layer up. The detector treats any recorded anomaly as an immediate rejection, and its reason string says precisely why: not "this is dangerous" but "`Marshal.load` refuses this and there is nothing here to permit." Those are different claims and only the second one is true.

That split is the single most important structural idea in the library. **The parser labels, the detector decides.** It also means the two components are allowed to disagree about the same stream, and that disagreement is a feature. There is a test named `test_sink_in_an_instance_variable_name_position_is_still_reported` that exists to lock it in place, and a proposal to make the parser strict on role slots was rejected specifically because it would delete that test.

The same instinct shows up in float decoding. A legacy Marshal float carries a mantissa extension after a NUL byte that modern Ruby still reads:

```
canonical 1.5:   "\x04\bf\b1.5"
legacy stream:   value=1.5  undecoded_tail="\x00abcde"  fully_decoded=false
Marshal.load:    1.5000000000055356
```

The parser does not guess and it does not pretend. It decodes what it can, labels the rest as an `undecoded_tail`, and answers `fully_decoded?` honestly. A reader that silently returned `1.5` would be claiming agreement with the interpreter that it has not earned.

### Sealing

Once parsing finishes, the whole graph is frozen depth-first and the `Result` wrapping it is frozen too. A parse result is an immutable description of bytes that already happened. Nothing downstream, including a caller who gets it back from `Decision#result`, can mutate the record that a policy decision was made from.

## Reader two: the Psych inspector

YAML needs no hand-written parser, because Psych already ships one that revives nothing. `Psych.parse_stream` builds an AST of `Psych::Nodes::*` objects and stops. The inspector walks that AST.

What it extracts is one `Reference` per `!ruby/*` tag, carrying three things:

```
   !ruby/object:Gem::Version    ->  class_name: "Gem::Version"
                                    kind:       "object"
                                    revival:    "init_with"     <- what Psych WOULD call
                                    key_position: false
```

The mapping from tag kind to revival method is the whole value of the inspector, because it turns "this document mentions a class" into "this document would dispatch `init_with` on that class":

| Tag kind | Method Psych dispatches |
|---|---|
| `!ruby/object` | `init_with` |
| `!ruby/array`, `!ruby/string`, `!ruby/struct`, `!ruby/exception` | `init_with` |
| `!ruby/hash` | `[]=` |
| `!ruby/marshalable` | `marshal_load` |

**Aliases are counted, never expanded.** An alias bomb costs nothing to inspect, which is the point: an inspector that expanded aliases in order to report on them would have imported the exact denial-of-service it exists to warn about. The count is bounded and reported instead of ignored, because it still costs whatever the eventual loader spends.

The inspector's own limitation notice is blunt about where it sits, and it is worth internalizing:

> "Unlike Marshal, Psych's own allowlist is a real veto: Psych checks the tag before it revives the object, where Marshal runs its proc after the callback has already fired. Same intent, opposite outcome, decided entirely by where the check sits. That means `YAML.safe_load` with `permitted_classes` **is** a boundary and this inspector is only detection and reporting on top of it."

A detector that positioned itself as a *replacement* for `safe_load` would be selling a downgrade. This one says so in a constant.

## The decision object

Three states, mutually exclusive by construction:

```
   proceed    the bytes matched the configured policy
   blocked    the bytes violated it, and `reason` says which rule and why
   observed   the bytes violated it, the reporter was called, and the caller
              was handed the snapshot anyway  (monitoring mode)
```

There is no `accepted?` predicate, and its absence is deliberate. Under `observe_and_log`, "did the policy permit this" and "is this stream clean" have **different answers**, and a single predicate named `accepted?` cannot answer both. Callers who write `Marshal.load(d.snapshot) if d.accepted?` would be silently loading everything the monitoring mode reported on. Forcing the caller to name the state they actually mean is worth the extra six characters.

The state is validated in the constructor against a frozen list, so an invalid state is an `ArgumentError` at construction rather than a predicate that quietly returns false everywhere.

### The violation ladder

The detector checks rules in a fixed order and returns the first violation it finds. The order is not arbitrary; it goes from "this is not even loadable" through "this dispatches during load" to "this mentions a class you did not approve":

```
   1. role anomaly        the parser recorded a malformed slot -> Marshal.load refuses it anyway
   2. sink tag            u / U / d  -> _load, marshal_load, or _load_data dispatches
   3. hash-dispatching key    #hash runs when the Hash is rebuilt
   4. eql?-dispatching key    #eql? runs as soon as two keys collide
   5. Range endpoint      #<=> runs when Range#marshal_load validates its ends
   ────────── deny_sinks_only stops here ──────────
   6. non-canonical version   declares a Marshal version no real Ruby emits
   7. unapproved class name   strict_allowlist only
```

Rules 1 through 5 are statements about **dispatch**: they are true regardless of which classes you trust, which is why they run under every policy including `deny_sinks_only`. Rules 6 and 7 are policy, and only `strict_allowlist` enforces them.

Rules 3, 4, and 5 exist because of three bypasses that shipped and were found later. All three were accepted under `deny_sinks_only` **and** under strict allowlisting with the class allowlisted, because neither rule was looking at dispatch through key position:

- A `String`-subclass hash key reaching `#eql?` on bucket collision.
- A gadget nested inside a bare `Array` used as a key. Nineteen bytes: `"\x04\b{\x06[\x06o:\fUngated\x00i\x06"`.
- A `Range` whose endpoints dispatch `#<=>`.

That is the argument for the ladder being data rather than a chain of ad-hoc conditionals: each rule is a separate, individually testable claim about what the interpreter will do, and the corpus carries a payload for each one.

### Reason strings are attacker-controlled output

A reason string quotes a class name, and a class name comes from the stream. That makes every reason string a log-injection surface, so three things happen to it before it is emitted:

- Names are truncated at 96 bytes with an explicit `[truncated, +N bytes]` marker rather than silently.
- Lists show at most 8 names with an explicit `, and N more`.
- Everything goes through `String#inspect` on binary-forced bytes, so a class name containing a newline cannot forge a log line.

A detector that pasted an unbounded attacker-controlled string into your logs would have turned a defense into a delivery mechanism.

## The scanner

The scanner answers a different question from the detector: not "is this stream dangerous" but "**which classes currently loaded in this process could be used as gadgets.**"

It walks `ObjectSpace.each_object(Module)`, and for every named module it collects the auto-invoked methods the module defines *itself* (not inherited), then scores each one.

### The taxonomy is a table, not a list of method names

This is where the concepts chapter's gated-versus-ungated axis becomes code. Every candidate method carries three facts:

| Method | Gate | Arity the deserializer supplies | Formats |
|---|---|---|---|
| `marshal_load` | gated | 1 | Marshal, Psych |
| `_load_data` | gated | 1 | Marshal |
| `_load` | gated (singleton) | 1 | Marshal |
| `init_with` | soft | 1 | Psych |
| `hash` | ungated | 0 | Marshal, Psych |
| `eql?` | ungated | 1 | Marshal, Psych |
| `<=>` | ungated | 1 | Marshal |
| `==` | ungated | 1 | Psych |
| `[]=` | ungated | 2 | Psych |
| `method_missing` | ungated | variadic | Marshal, Psych |
| `respond_to_missing?` | ungated | 2 | Marshal, Psych |
| `respond_to?` | ungated | variadic | Psych |
| `to_s` | **link** | 0 | none |
| `coerce` | **link** | 1 | none |

Three columns and each one earns its place.

**The gate column** is the axis from [01-CONCEPTS.md](./01-CONCEPTS.md). A gated method needs a truthful `respond_to?`; an ungated one is dispatched blind.

**The format column** is why entry points are scored per format rather than globally. A method-erased proxy is a valid Psych entry point and an invalid Marshal one, so a single global "is this reachable" answer would be wrong for one of the two. Today's scan finds 29 entry points reachable through Marshal and 33 through Psych, and neither set contains the other.

**The arity column** is the subtle one. A method named `init_with` that takes three arguments cannot be called by a deserializer that supplies one. Reporting it is a false positive. On a stock image the arity check rejects exactly one candidate, and it is a good one:

```
entry points whose arity cannot accept the deserializer's call: 1
  Psych::Visitors::ToRuby#init_with               arity=3    needs=1
```

That is Psych's own visitor method, which happens to share a name with the hook it dispatches. Without the arity column it would sit at the top of every scan as a permanent, confusing false positive.

**The link rows** are the ones with no formats at all. `to_s` is a real step in the published universal chain, but `Marshal` never calls it. It is a method a *gadget* calls once a chain is already moving, not a method a *deserializer* dispatches to start one. Conflating the two is the single largest source of false positives in gadget scanning, so links are collected, counted, and excluded from reachability. Today's scan finds 53 of them alongside 140 entry points.

### Reachability, and what it deliberately refuses to conclude

Adding the taxonomy up:

```
reachable?  =  is an entry point (not a link)
            AND its arity can accept the deserializer's call
            AND ( it is gated or soft-gated                     <- the tag alone reaches it
                  OR its body references object state
                  OR its source could not be read )             <- read that last one twice
```

The last clause is the interesting one. To decide whether an ungated method like `#hash` is *interesting*, the scanner parses the method's source with Prism and asks whether the body references an instance variable or makes a receiverless call. A `#hash` that returns a literal is inert; a `#hash` that reads `@name` is a potential pivot.

But if the source cannot be read, the scanner scores the method **reachable**, not inert. That is the correct direction for a security tool to be wrong in. On a stock image 8 candidates are in that state, and the scan says so.

### Under-reporting is reported, loudly

A gadget scanner that silently swallows errors is worse than no scanner, because it produces a short clean list that reads as "nothing to see here." So every swallowed error is counted and attributed to a named site:

```
suppressed errors (this scan under-reports):
  source_parse     3

142 candidates have no Ruby source and were never analysed; the reachability filter does not cover them
```

There are five suppression sites and three of them are marked **lossy**, meaning a failure there means a candidate was never even created. `Report#candidates_lost?` is the predicate that distinguishes "this scan is slightly less precise" from "this scan is missing entries entirely," and `complete?` and `fully_analysed?` answer two separate questions rather than one blurred one.

The headline number from a stock `ruby:4.0-slim` (Ruby 4.0.6), re-measured on 2026-07-31:

```
modules=691  candidates=193  entry_points=140  links=53
gated=11  soft=5  ungated=124
reachable=43  (28 of them ungated)   marshal=29  psych=33
unanalysable=142  unreadable=8  suppressed=3
```

**Those numbers are not facts about Ruby.** `ObjectSpace` cannot report a class nobody has required yet, so they are a statement about what this specific process had loaded. Requiring `active_support` moves all of them. Re-run it yourself rather than quoting these.

And the honest framing, stated in the project rather than implied: a gadget-discovery tool tells you what chains exist **today**, in **this** process. It is not a control.

## The chains

Three payloads, and the directory is the identity. Each file under `lib/marshalsea/chains/` subclasses `Base`, and `Base.inherited` registers it. There is no central registry file listing chain names, because a registry file is a thing that rots when someone adds a chain and forgets to update it.

```
  erb-def-method   primitive  CVE-2026-41316   def_method
  erb-def-module   chain      CVE-2026-41316   hash
  psych-init-with  chain      none             init_with
```

**Primitive and chain are different labels and the difference is load-bearing.** A *chain* fires inside the deserializer with no cooperation from the application. A *primitive* forges an object past a guard and stays inert until the application does something with it. Labelling `erb-def-method` a chain would overstate it; deleting it would delete the lesson that the dangerous call site can live in your own code.

Each chain declares the versions it affects as real `Gem::Requirement` constraints, so the boundary is queryable rather than prose:

```
  erb 4.0.3   affected? true
  erb 4.0.3.1 affected? false
  erb 6.0.1   affected? true
  erb 6.0.1.1 affected? false
  erb 6.0.4   affected? false
```

### The builder must never run its own payload

This is the constraint that shapes the offensive half, and it is not obvious until it bites you.

The `erb-def-module` chain enters through hash-key position. So the natural way to build it is `Marshal.dump({ proxy => 1 })`. That calls `#hash` on the proxy **while your builder is constructing the literal**, which fires the chain locally, in the process that was supposed to be generating a payload for somewhere else.

The fix is to never put the object in a hash at all. `Base#in_hash_key_position` dumps the object standalone, slices off its two header bytes, and splices the body into a hand-written one-entry hash frame:

```
   Marshal.dump(nil)      "\x04\b" "0"
                           ^^^^^^ take the header

   Marshal.dump(proxy)    "\x04\b" <body>
                                   ^^^^^^ take the body

   result                 "\x04\b" "{\x06" <body> "0"
                                    ^^^^^^         ^^^ nil value
                                    one-entry hash frame
```

There is one way that splice can go wrong, and the code refuses rather than risking it. Marshal object links are **positional**: `@6` means "the sixth registered object." Splicing a body behind a hash node shifts every index by one, so a payload graph containing a back-reference would silently decode into a different graph than the one you built. So after splicing, the builder parses its own output and raises `ObjectLinkRefusedError` if any object link survived. A payload generator that can produce a graph it did not intend is worse than one that refuses.

## The runtime guard

`LoadGuard` does the thing the allowlist proc cannot: it vetoes **before** the method body runs. A `TracePoint` on `:call` fires at method entry, so raising from the handler means the body never executes.

```
   Marshal.load
        │
        ├─ allocate Klass
        ├─ dispatch marshal_load  ──> TracePoint :call fires HERE
        │                             owner not permitted -> raise
        │                             (body never runs)
        └─ r_post_proc ──> your allowlist proc would have run HERE, too late
```

The hook list is derived by enumeration, not guessed. Tracing every `:call` and `:c_call` during a load of a payload containing a plain object, a `marshal_load` class, a `_load` class, a `Struct`, an extended object, subclassed `Hash`/`Array`/`String`, a custom-`#hash` key, a `Range`, `Time`, `Rational`, `Regexp`, and an `Exception` produces this complete dispatch surface:

```
ALL distinct method_ids seen: [:_load, :hash, :initialize, :load, :marshal_load]
```

Small, which is why the guard is tractable at all.

One structural rule holds the whole thing up: **the guard never dispatches a method on the receiver it is inspecting.** It resolves the owner's name through `Object.instance_method(:class)`, `Object.instance_method(:is_a?)`, and `Module.instance_method(:name)`, bound to the receiver rather than called on it. The receiver is a gadget, a method-erased proxy answers `.class` and `.is_a?` through `method_missing`, and `method_missing` is exactly what the shipped chain enters through. A guard that asks the object what it is fires the chain it was about to veto, inside a `TracePoint` handler that does not trace its own nested calls. [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) has the transcript of that failure and the test that pins it.

### It ships its own bypasses, including one left open by default

The default hook set watches `marshal_load`, `_load`, `_load_data`, `method_missing`, and `respond_to_missing?`. It does **not** watch `#hash` and `#eql?`. That is a deliberate, documented hole, and here is the three-way comparison on the same 19-byte payload:

```
default guard  -> LOADED, #hash fired, watches?(:hash)=false
strict guard   -> blocked: deserialization hook OKey#hash is not permitted, #hash never fired
detector       -> blocked, nothing loaded at all
```

The default guard lets the ungated key shape through. Why leave it open? Because `#hash` and `#eql?` are among the hottest methods in Ruby, and watching them changes both the cost and the false-positive profile completely. `strict: true` closes it and accepts that cost. The **detector** catches the same shape before any bytes are loaded, which is the cheaper place to catch it, and the guard's limitation notice points at it explicitly.

The other limits, stated in the same notice rather than in a footnote:

- **It covers the load window only.** A class carrying no hook at all is instantiated freely and fires whenever the application later touches it. That is outside any window this guard can see, and it is exactly how the `erb-def-method` primitive works.
- **It is thread-scoped.** A load on another thread is not covered.
- **Its cost is not a multiplier.** Enabling a `TracePoint` costs roughly 46 microseconds per load, near enough constant, so the ratio is decided by how much work the load itself does: 1.0x on a 488 KB document, 1.1x on 46 KB, 20.7x on a 142-byte session, **40.4x on a 45-byte session cookie**. A session cookie is exactly what this lab deserializes, so the number is published with the payload size attached. An earlier version of this project's research recorded "1.4x" from a single large-payload measurement, and that figure is now marked with a dated correction, because a ratio quoted without its payload size reads as an endorsement it has not earned.

## The target

A Sinatra app on Rack 3, in a container with no route off the host, read-only root filesystem, dropped capabilities, `no-new-privileges`, a pids limit, and one writable `tmpfs` for the canary file.

Four endpoints, arranged as two matched pairs so the difference is one `curl` apart:

```
   POST /session       issue a benign session cookie

   GET  /render        Marshal.load, then compile the template      VULNERABLE
   GET  /render/safe   inspect the stream first, then load          DEFENDED

   GET  /yaml/unsafe   YAML.unsafe_load the same session            VULNERABLE
   GET  /yaml/safe     inspect, then YAML.safe_load                 DEFENDED

   GET  /canary        report whether the canary file exists
```

The pairing is the lesson from [01-CONCEPTS.md](./01-CONCEPTS.md) made executable. `/render` and `/yaml/unsafe` both reach code execution with the same ERB object. `/yaml/safe` refuses it **by tag**, before revival, because Psych's allowlist is a real veto. `/render/safe` can only inspect the bytes and hope, because Marshal's is not.

Note what `/render/safe` does after the detector accepts: it still calls `Marshal.load` inside a `rescue`, still checks the result is actually a session hash, and only then compiles. Three layers, because the first one is explicitly not a boundary.

The target gate drives all of this from a **second container on the same internal network** rather than from a host port. `--internal` Docker networks block published ports, so a gate that tried to `curl` from the host would either fail or force the network to be non-isolated. Attacking the target from inside the network keeps the egress isolation real.

## Limits: fourteen axes, all on by default

The parser bounds fourteen separate resources, and every one of them is enforced unless you opt out:

```
   stream bytes        nodes               registered objects    symbol definitions
   collection entries  scalar bytes        total scalar bytes    object links
   symbol references   symbol name bytes   class name bytes      instance variables
   struct members      nesting depth
```

Two design notes. The limits are **on by default and opt-out**, not off by default and opt-in, because the caller who most needs them is the one who never read this page. And `Limits.permissive` still pins `max_depth`, because unbounded recursion in a recursive-descent parser is a stack overflow rather than a slow parse, and "permissive" should not mean "crashes the process."

They fail before they allocate:

```
DepthLimitError:      exceeded depth 4
LimitExceededError:   stream bytes 110 exceeds 8
```

## The gate

Six stages, run by `just gate`, 79 assertions, all of which must pass:

| Stage | What it proves |
|---|---|
| `check` | the seven test suites plus standalone control scripts |
| `matrix` | which Ruby versions the chain fires on, by running it in each |
| `exploit` | the CVE boundary in both directions: fires on the vulnerable image, blocked on the patched one, one `docker pull` apart |
| `detector` | the adversarial corpus, every payload and what the detector decided |
| `target` | end-to-end exploitation over real HTTP, plus isolation, error-leak, and the sink-tag check |
| `package` | the built artifact, the manifest audit, the install path, release identity, negative controls |

**Every stage carries an input it must reject.** A gate with only positive cases cannot detect a checker that always says yes. The detector corpus is the clearest example, because the accepts and the rejects sit in the same table:

```
  object_in_value_position_control       accept Foo
  hash_key_object                        reject Foo        stream puts "Foo" in a hash key, so its #hash runs d
  hash_key_object_link                   reject Foo        stream puts "Foo" in a hash key, so its #hash runs d
  hash_key_struct                        reject Foo        stream puts "Foo" in a hash key, so its #hash runs d
  hash_key_extended                      reject Foo,Comparable stream puts "Comparable" in a hash key, so its #hash
  hash_key_user_class_over_array         reject Foo        stream puts "Foo" in a hash key, so its #hash runs d
  hash_key_bare_array                    reject Foo        stream puts "Foo" in a hash key, so its #hash runs d
  hash_key_nested_bare_array             reject Foo        stream puts "Foo" in a hash key, so its #hash runs d
  hash_key_user_class_over_string        reject Foo        stream puts "Foo" in a hash key, so its #eql? runs d
  hash_key_extended_over_string          reject Comparable stream puts "Comparable" in a hash key, so its #eql?
  hash_key_regexp                        accept
  hash_key_array_of_primitives           accept
  hash_key_empty_array                   accept
  range_with_object_endpoints            reject Foo,Range  stream puts "Foo" in a Range endpoint, so its #<=> r
  range_with_primitive_endpoints         accept Range
```

Read the accepts as carefully as the rejects. `hash_key_regexp`, `hash_key_array_of_primitives`, and `hash_key_empty_array` are all key-position payloads that must **not** be rejected, and they are what stop the key-position rules from degenerating into "reject anything in a key."

`object_in_value_position_control` is the sharpest of them. The same class, in the same stream, in **value** position instead of key position, must be accepted. Without it, a detector that simply rejected every stream mentioning `Foo` would pass every rejection case in the table.

There is a further refinement worth naming, because it took a real bug to learn: **two checks that both reject the same input alibi each other.** If a control is refused by the tag check *and* by the class check, gutting either one leaves the gate green. So the target gate carries a YAML document that the inspector approves and Psych still refuses, specifically to isolate the two layers from each other.

## Where to go next

[03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) walks the code: bytes into a node graph, a node graph into a decision, a live object into a payload, and the ActiveSupport proxy chain end to end as the showpiece.
