<!-- ©AngelaMos | 2026 -->
<!-- 01-CONCEPTS.md -->

# marshalsea: Concepts

This chapter is the theory the lab is built on. Every claim in it is either traced to a primary source with a URL, or verified by running Ruby in a pinned container, and it says which. Where a widely repeated claim turned out to be wrong, the correction is here rather than a quiet omission.

## Start with the one everybody gets wrong

**The most-cited example of insecure deserialization was not insecure deserialization.**

Search for "insecure deserialization breach" and Equifax comes back at the top. The 2017 breach, 147 million people, the largest data-breach settlement on record. It is in slide decks, in course material, in interview answers, and in the introductory paragraph of an enormous number of write-ups about this exact bug class.

It was **OGNL expression injection**, and NVD classifies it **CWE-755, Improper Handling of Exceptional Conditions**. Not CWE-502.

Here is [the NVD record for CVE-2017-5638](https://nvd.nist.gov/vuln/detail/CVE-2017-5638), verbatim:

> "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string."

The mechanism: a malformed `Content-Type` header raises an exception, the exception message is built by a routine that evaluates OGNL, and the attacker's OGNL expression executes. **No object graph is reconstructed at any point. There is no serialized payload anywhere in it.** It is closer to template injection than to deserialization.

CISA agrees, and it is worth seeing how precisely. In the KEV catalog, CVE-2017-5638 is titled "Apache Struts *Remote Code Execution* Vulnerability" and mapped to CWE-20, while its sibling CVE-2017-9805 is titled "Apache Struts *Deserialization of Untrusted Data* Vulnerability" and mapped to CWE-502. Same product, same year, different bug class. Somebody named them differently on purpose.

### How to tell them apart

Struts had two famous RCEs in 2017, six months apart, and only the second one is deserialization:

| | CVE-2017-5638 | CVE-2017-9805 |
|---|---|---|
| NVD published | 2017-03-10 | 2017-09-15 |
| Component | Jakarta Multipart parser | REST plugin |
| Mechanism | OGNL injection during error-message generation | XStream deserialization with no type filtering |
| NVD CWE | **CWE-755** | **CWE-502** |
| CVSS v3.1 | 9.8 | 8.1 |
| Used against Equifax | **Yes** | **No** |

### Why the myth is so durable

The timeline explains it completely, and the Apache Software Foundation documented the correction itself. CVE-2017-9805, the one that *is* deserialization, was disclosed 2017-09-04. Equifax announced the breach 2017-09-07. Three days apart. Early reporting reasonably guessed the fresh CVE. Equifax corrected the record on 2017-09-13. The ASF [published a media alert](https://news.apache.org/foundation/entry/media-alert-the-apache-software) on 2017-09-14 that exists specifically to fix this:

> "Following this announcement, additional claims stated that the breach was caused by **CVE-2017-9805**, an exploit in Apache Struts that was disclosed on 4 September 2017."
>
> "On 13 September 2017, Equifax issued a statement confirming that 'The vulnerability was Apache Struts **CVE-2017-5638**'."

The correction lost. The originating Quartz article still carries its own retraction notice and its URL slug still says "nine-year-old security flaw" while the headline has been rewritten.

Four primary sources were opened and text-searched for this chapter, and none of them uses the word:

1. **GAO-18-559** (2018-08-30, 40 pages): "deserialization," "serialization," and "OGNL" appear **zero times**, as does any CVE number.
2. **US House Committee on Oversight majority staff report** (December 2018, 96 pages): names CVE-2017-5638 explicitly and cites NVD directly. "Deserialization" appears **zero times**.
3. **Equifax's own press release** (2017-09-15): "The attack vector used in this incident occurred through a vulnerability in Apache Struts (CVE-2017-5638)."
4. **DOJ indictment press release** (2020-02-10): "the defendants exploited a vulnerability in the Apache Struts Web Framework." "Deserialization": zero occurrences.

That is a better story than the myth was: **a plausible inference, made under time pressure, that outran its own retraction by nine years.** And it teaches something the myth cannot, which is how to look at a CVE and tell expression injection from deserialization.

If you want the correct one-sentence version: *the largest data-breach settlement on record came from an unpatched Struts OGNL injection, a different bug class that is frequently mislabelled as deserialization.*

## So what is deserialization, actually

Serializing an object writes its state to bytes. Deserializing reads those bytes back into a live object. The trap is that the second step is not a copy. To rebuild an object, the runtime has to run code:

```
   Marshal.dump           bytes on the wire            Marshal.load
   ────────────           ─────────────────            ────────────
   object state    ──>    "\x04\bU:\x15Gem::..."  ──>  allocate the class
                                                       CALL its marshal_load
                                                       CALL #hash on hash keys
                                                       CALL #<=> on Range ends
                                                       return the object
```

Every one of those `CALL`s is a method the attacker chose by choosing the bytes. That is the entire vulnerability. `Marshal.load` is not "parsing"; it is a small, attacker-steerable interpreter over your loaded class graph.

Ruby's own documentation for `Marshal` says this plainly, and has for years:

> "By design, `Marshal.load` can deserialize almost any class loaded into the Ruby process. In many cases this can lead to remote code execution if the `Marshal` data is loaded from an untrusted source. As a result, `Marshal.load` is not suitable as a general purpose serialization format and you should never unmarshal user supplied input or other untrusted data."

Python says the same thing about `pickle`:

> "The `pickle` module **is not secure**. Only unpickle data you trust. It is possible to construct malicious pickle data which will **execute arbitrary code during unpickling**. Never unpickle data that could have come from an untrusted source, **or that could have been tampered with**."

PHP says it about `unserialize()`:

> "**Do not pass untrusted user input to unserialize() regardless of the `options` value of `allowed_classes`.** Unserialization can result in code being loaded and executed due to object instantiation and autoloading."

Three languages, three official docs, all saying the same thing for a decade. All three still generating CVEs. **The failure is not missing documentation.** That framing is more useful than any severity score, and it is the reason this lab spends its effort on *why the obvious fixes fail* rather than on repeating the warning.

Note the clause most write-ups drop from the Python quote: "or that could have been tampered with." It is the half that motivates the `hmac` sentence that follows it in the real docs. The teaching point is precise: **hmac addresses tampering, not untrusted origin.** Signing a payload produced by an attacker who holds the key buys you exactly nothing.

## The gadget chain

Here is the part that makes this bug class feel like magic, and the part that stops feeling like magic once you see the shape.

A payload does not contain code. It contains a description of an object graph. What the attacker does is pick a set of classes that are *already loaded in your process*, arrange them so that reviving one calls a method on the next, and keep going until the last one does something useful. Each class in that sequence is a **gadget**. The sequence is a **chain**.

```
   attacker controls only the SHAPE of the graph
   ┌───────────────────────────────────────────────────────────┐
   │  Hash                                                     │
   │   └─ key: DeprecatedInstanceVariableProxy                 │
   │        @instance = ERB (with attacker-controlled @src)    │
   │        @method   = :def_module                            │
   └───────────────────────────────────────────────────────────┘
                             │
        Marshal.load rebuilds the Hash, which rehashes its keys
                             │
                             v
        proxy#hash  ->  method_missing  ->  @instance.def_module
                             │
                             v
        ERB#def_module -> ERB#def_method -> module_eval(@src)
                             │
                             v
                     attacker's Ruby runs
```

Nowhere in that payload is there an instruction saying "run a command." Every step is a normal method doing exactly what it was written to do. `#hash` is supposed to be called when you rebuild a hash. `method_missing` is supposed to forward. `def_module` is supposed to compile a template. The attacker supplied only the arrangement.

This is why the Apache Software Foundation refused to treat Commons Collections as vulnerable in 2015, and their statement is the clearest articulation of the idea anyone has published:

> "this is not the only known and especially not unknown useable gadget. So replacing your installations with a hardened version of Apache Commons Collections will not make your application resist this vulnerability."

All three of the famous 2015 Java CVEs (CVE-2015-4852 for Oracle WebLogic, CVE-2015-7501 for Red Hat JBoss, CVE-2015-6420 for Cisco) are scoped to *downstream vendors*. **Apache Commons Collections itself never received a CVE**, because `InvokerTransformer` was doing exactly what it was documented to do. The vulnerability was `readObject()` on untrusted bytes. The library was ammunition.

Before the upstream fix shipped, the remediation of last resort was to physically delete `InvokerTransformer`, `InstantiateFactory`, and `InstantiateTransformer` class files out of deployed jars. That tells you how well the "just allowlist it" strategy was going.

## The axis that matters: gated versus ungated

This is the organizing idea of the whole lab, it is not written down in the published Ruby literature, and it was established here by execution on Ruby 3.0.7, 3.1.7, 3.3.8, 3.3.12, 3.4.10, and 4.0.6, with negative controls.

Ruby's deserializers reach attacker-controlled objects two different ways, and the difference decides whether a class is usable at all:

```
GATED      the deserializer calls respond_to?(m, true) FIRST
           false -> TypeError, chain dead
           reachable through method_missing ONLY if respond_to_missing? also answers true

UNGATED    the deserializer calls the method directly
           no gate, no check
           method_missing catches it for free
```

The verified table for `Marshal.load`, identical on Ruby 3.0.7 through 4.0.6:

| Method | Gated? | When `Marshal.load` invokes it |
|---|---|---|
| `marshal_load(data)` | **GATED** on `respond_to?(:marshal_load, true)` | Object was dumped via `marshal_dump` (the `U` tag) |
| `self._load(str)` | **GATED**, on the class | Object was dumped via `_dump` (the `u` tag). The gate is on the singleton class |
| `respond_to_missing?(m, true)` | it *is* the gate | Called before the two above whenever the method is not concretely defined. Itself a reachable sink |
| `method_missing(m)` | inherits the gate | Fires for the two above only if `respond_to_missing?` returned true |
| `hash` | **UNGATED** | Object is a Hash key, or nested in an Array or Set used as a key |
| `eql?(other)` | **UNGATED** | Only on hash-bucket collision between two keys |
| `<=>(other)` | **UNGATED** | `Range#marshal_load` validates its endpoints, so it fires on both ends of a bounded Range |

And the verified negatives, which matter just as much. `Marshal.load` **never** invokes any of these directly: `to_s`, `to_str`, `to_ary`, `to_hash`, `to_proc`, `to_int`, `inspect`, `==`, `coerce`, `each`, `call`, `<<`, `+`, `length`, `size`, `freeze`.

That negative list is easy to get wrong and expensive to get wrong. `Gem::RequestSet::Lockfile#to_s` is a real step in the published universal chain, so it is tempting to file `to_s` as a sink. But it is called *by another gadget*, not by `Marshal`. **`to_s` is a link, never an entry point.** A scanner that conflates the two produces a flood of false positives, which is why this project models them as two different kinds of node and reports 53 links separately from 140 entry points.

### The payoff: the same class, opposite outcomes

Take a proxy class that undefines every public method, the shape Rails uses for its deprecation proxies. Reached through a **gated** sink:

```
1) marshal_load via method_missing (respond_to_missing? => true)  -> fires
2) NEGATIVE: respond_to_missing? => false                         -> TypeError, chain dead
3) NEGATIVE: no marshal_load, no method_missing                   -> TypeError, chain dead
4) fully-wiped proxy                                              -> TypeError, chain dead
```

Row 4 is the payoff. A class that undefines everything **cannot** be a `marshal_load` entry point, because it undefined `respond_to?` without supplying `respond_to_missing?`.

Now the same wiped class through an **ungated** sink:

```
A) wiped proxy as a Hash key      [UNGATED #hash]  -> method_missing(hash) | ok
B) wiped proxy inside an Array key [UNGATED #hash]  -> method_missing(hash) | ok
C) wiped proxy inside a Set        [UNGATED #hash]  -> method_missing(hash) | ok
D) two colliding wiped keys                         -> MM(hash) | MM(hash) | MM(eql?) | ok
```

Same class. Gated path dies, ungated path fires. Everything the scanner does is built on that distinction.

Row D is worth pausing on, because it is the one that bit this project. `#eql?` only fires on a **bucket collision**, which means a test fixture with a single key can never observe it. An earlier version of this lab's differential oracle dumped `{ key => nil }`, one key, no collision, and `#eql?` was unobservable by construction. Three detector bypasses shipped under a green suite because of it. The oracle now uses two-key colliding hashes.

### Psych is not Marshal, and the difference is sharper than it looks

The same exercise for `YAML.unsafe_load`, verified identical on Psych 3.3.2, 4.0.4, 5.1.2, 5.2.2, and 5.3.1:

| Method | Gated? | Trigger |
|---|---|---|
| `init_with(coder)` | **soft gate**: `o.respond_to?(:init_with)` as an ordinary Ruby call, so `method_missing` intercepts it | any `!ruby/object:X` mapping |
| `marshal_load(data)` | gated on `respond_to?(:marshal_load)` | the `!ruby/marshalable:X` tag |
| `hash` | **UNGATED** | object used as a YAML mapping key |
| `==` | **UNGATED** | mapping key insertion |
| `[]=(k, v)` | **UNGATED** | `!ruby/hash:Subclass`, where Psych calls `[]=` on the allocated subclass |

The sharpest difference, and one this research run found nowhere in the literature: Psych calls `instance.respond_to?(:init_with)` as an **ordinary Ruby method call**, not through the C-level `rb_obj_respond_to` that Marshal uses. On a method-erased proxy, `respond_to?` itself falls into `method_missing`, which returns something truthy, so Psych then calls `init_with`, which also falls into `method_missing`.

**A fully method-erased proxy class is a valid YAML entry point and an invalid Marshal entry point.** Identical class, opposite outcome. The lab has a test that asserts exactly that in both directions, and it is the reason the scanner scores entry points **per format** rather than globally: today's scan finds 29 entry points reachable through Marshal and 33 through Psych, and those two sets are not nested.

### One blind spot worth knowing about

A `String` subclass that overrides `#hash` and is used as a Marshal hash key **never has its `#hash` called.** Ruby's internal `rb_any_hash` special-cases `T_STRING` and hashes the bytes directly. Verified by execution on Ruby 4.0.6:

```
loading a String-subclass key dispatched: []
loading an Object-subclass key dispatched: [:"Object subclass"]
```

Consequence for anyone writing a scanner: **String subclasses are dead as `#hash` entry points.** Report them and you produce false positives. Array, Hash, Object, and Struct subclasses all dispatch normally. (The same C fast path plausibly covers `Symbol`, `Integer`, `Float`, `nil`, `true`, and `false`, but those cannot be subclassed, so it could not be tested and is not claimed here.)

## The two allowlists

This is the spine of the project. Everyone teaches "do not deserialize untrusted input." Almost nobody explains why the obvious fix fails, and the answer is a specific, checkable fact about where one function call sits.

`Marshal.load` accepts a proc. It is tempting to use it as an allowlist:

```ruby
Marshal.load(bytes, ->(obj) { raise SecurityError unless ALLOWED.include?(obj.class); obj })
```

**That does not work.** Here is the `TYPE_USRMARSHAL` case from `marshal.c` on ruby/ruby master, with the ordering annotated:

```c
case TYPE_USRMARSHAL:
    VALUE name = r_unique(arg);
    VALUE klass = path2class(name);
    ...
    v = obj_alloc_by_klass(klass, arg, &oldclass);   /* 1. allocate */
    ...
    v = r_entry(v, arg);
    data = r_object(arg);
    load_funcall(arg, v, s_mload, 1, &data);         /* 2. YOUR GADGET RUNS */
    ...
    v = r_post_proc(v, arg);                         /* 3. proc finally sees it */
    break;
```

`r_post_proc` is where your proc is invoked. It is two statements after `load_funcall(... s_mload ...)`, which is the call that runs `marshal_load`. By the time your proc is handed the object and raises, the gadget has already fired. Executed confirmation on Ruby 4.0.6:

```
EXP-B: allowlist proc that permits everything EXCEPT Inner
  proc raised: blocked Inner
  side effects fired BEFORE the proc could veto: ["Inner#marshal_load RAN"]
  => allowlist proc FAILED TO PREVENT the callback
```

There is also no allowlist keyword to fall back on. `Marshal.load` accepts exactly `proc` and `freeze:`:

```
Marshal.load(data, permitted_classes: [String])
  ArgumentError: unknown keyword: :permitted_classes
```

Psych's allowlist genuinely is a veto, for exactly one reason: it checks the tag **before** revival. Same intent, opposite outcome, decided entirely by where the check sits.

```
Marshal   bytes ──> build the object ──> RUN its hook ──> your allowlist runs
                                         ^^^^^^^^^^^^     too late, an autopsy

Psych     bytes ──> CHECK the tag ──> refuse
                    ^^^^^^^^^^^^^^   in time, a bouncer
```

The lab makes that executable rather than asserting it. One test loads the same conceptual payload through both deserializers and asserts on which callbacks fired:

- `Psych.safe_load(document, permitted_classes: [])` raises `Psych::DisallowedClass` and `init_with` **never ran**.
- `Marshal.load(blob, ->(o) { o })` returns, and `marshal_load` **already ran**.

The target application exposes both so you can `curl` the difference. `/render` and `/yaml/unsafe` both reach code execution with the same ERB object. `/yaml/safe` refuses it by tag. `/render/safe` can only inspect the bytes first and hope.

That asymmetry is Ruby's position in the wider ecosystem, and it is not flattering: **`Marshal` has no JEP 290, no `weights_only`, no `allowed_classes`, and no `.NET 9` moment.** Psych got a safe default in Ruby 3.1. `Marshal` got a documentation warning. That is the reason this lab exists and the reason it targets Marshal specifically.

## The worked example: CVE-2026-41316

Four months old at the time of writing, and the cleanest teaching case available because the patch is three lines and you can read all of it.

- **Advisory**: [ruby-lang.org, 2026-04-21](https://www.ruby-lang.org/en/news/2026/04/21/erb-cve-2026-41316/). GHSA-q339-8rmv-2mhv. NVD published 2026-04-23.
- **CVSS v3.1 8.1.** **CWE-502 and CWE-693 (Protection Mechanism Failure).** The dual mapping is the story.
- **Affected**: erb `< 4.0.3.1`, `= 4.0.4`, `>= 5.0.0 < 6.0.1.1`, `>= 6.0.2 < 6.0.4`. **Patched**: 4.0.3.1, 4.0.4.1, 6.0.1.1, 6.0.4.
- **Credit**: TristanInSec.
- **Precondition, quoted from the advisory:**
  > "Any Ruby application that calls `Marshal.load` on untrusted data AND has both `erb` and `activesupport` loaded is vulnerable to arbitrary code execution."

Three databases give three different dates for it (rubysec 2026-04-13, ruby-lang 2026-04-21, NVD 2026-04-23), and NVD assigns CWE-502 plus CWE-693 while the GHSA page lists only CWE-693. Cite the one you actually pulled.

**The mechanism.** Ruby 2.7.0 added an `@_init` instance-variable guard so that an ERB object reconstructed through `Marshal.load` would refuse to evaluate its template. `ERB#result` and `ERB#run` check it. `ERB#def_method`, `ERB#def_module`, and `ERB#def_class` evaluated the template source **without** checking it.

Reading the shipped source in a pinned container makes it concrete. In erb 4.0.4.1, a patched version, the assignment and the checks look like this:

```
in def initialize(...)    | @_init = self.class.singleton_class
in def result(b=...)      | unless @_init.equal?(self.class.singleton_class)
in def def_method(mod,..) | unless @_init.equal?(self.class.singleton_class)
```

And the reason one added check fixes all three methods, read from the patched source:

```ruby
def def_module(methodname='erb')
  mod = Module.new
  def_method(mod, methodname, @filename || '(ERB)')
  mod
end

def def_class(superklass=Object, methodname='result')
  cls = Class.new(superklass)
  def_method(cls, methodname, @filename || '(ERB)')
  cls
end
```

`def_module` and `def_class` both delegate to `def_method`, so guarding `def_method` closes the whole family. That is what "fix the guard, not the symptom" looks like as a diff.

**The exploit primitive**, which explains why these three methods were *exploitable* rather than merely unguarded. `def_method` wraps the template source in a generated `def <methodname> ... end`. An attacker who controls `@src` prefixes it with `end\n`, closing the generated wrapper early, so the injected code runs at `module_eval` time, during definition, rather than waiting for anyone to call the method. This lab builds exactly that, and you can print it:

```ruby
Marshalsea::Chains::ErbDefMethod.canary("/tmp/canary", "pwned").src
# => "#\nend\nFile.write(\"/tmp/canary\", \"pwned\")\ndef _marshalsea_unused\n"
```

`ERB#def_method` does not simply prepend the wrapper. Its actual line, read from the shipped source, is:

```ruby
src = self.src.sub(/^(?!#|$)/) { "def #{methodname}\n" } << "\nend\n"
```

It inserts `def <name>` before the **first line that is neither a comment nor blank**. That regex exists because a genuinely compiled ERB template starts with a magic encoding comment, which has to stay on line one:

```ruby
ERB.new("hello <%= 1 %>").src
# => "#coding:UTF-8\n_erbout = +''; _erbout.<< \"hello \".freeze; ..."
```

So the payload's leading `#` is impersonating that magic comment, which pushes the insertion point down onto the `end`. Running the same substitution on the payload produces exactly this:

```ruby
#                                     # the fake magic comment, so the `sub` skips line 1
def render_it                         # the wrapper lands HERE, on the `end` line
end                                   # and closes immediately: an empty method
File.write("/tmp/canary", "pwned")    # now at module_eval top level, runs during eval
def _marshalsea_unused                # a second empty method, which eats the
                                      # wrapper's own appended "\nend\n"
end
```

Verified by executing it: the payload fires during `eval`, and both `render_it` and `_marshalsea_unused` are defined as empty methods afterward.

```
fired during eval: [:RAN_AT_EVAL_TIME]
methods defined:   [:_marshalsea_unused, :render_it]
```

That is the entire trick. Nothing waits for anyone to call `render_it`.

**`def_module` takes no arguments**, which is what makes it reachable from a gadget chain rather than only from cooperating application code, and it is why this lab ships two payloads with different labels:

| Payload | Kind | Enters through | Fires when | Needs |
|---|---|---|---|---|
| `erb-def-module` | **chain** | ungated `#hash` on a hash key | inside `Marshal.load`, no application call | activesupport loaded in the target |
| `erb-def-method` | **primitive** | the `@_init` guard bypass | only when the application calls `def_method` | nothing |

Calling the second one a "chain" would be a lie, and the distinction teaches something real: the dangerous call site can live in *your* code. The lab's target application calls `template.def_method(...)` if the deserialized object responds to it, which is a plausible thing for a template-caching layer to do and is exactly the cooperation the primitive needs.

**Why CWE-693 matters pedagogically.** A mitigation existed, was deliberate, was six years old, and covered two of five entry points. Partial guards read as safety and they audit as safety. This is the strongest available argument for the position that allowlisting individual sinks is a losing game.

The lab's exploit gate proves both halves by pulling two real images one version apart: the chain fires on the vulnerable one and is blocked on the patched one, with the boundary asserted in both directions.

## What actually happened in Ruby

Short version, all traced to primary sources.

**CVE-2013-0156, the one that made the Ruby world care.** Rails' XML parameter parser let a request declare the *type* of a parameter, and the supported list included `yaml` and `symbol`. So a request body could instruct the framework to hand attacker-controlled bytes to the unsafe YAML parser, before any application code ran, on **every** controller:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<bang type="yaml">--- !ruby/object:Time {}
</bang>
```

Five lines, and it contains the entire vulnerability class. The upstream advisory's workaround deletes `"symbol"` and `"yaml"` from `ActiveSupport::XmlMini::PARSING`, and it is blunt about the rest:

> "there is no fix for YAML object injection"

**rubygems.org was compromised on 2013-01-30** using this class of flaw, and it is documented by the maintainers themselves. RubyGems.org called `YAML.load` on the `metadata.gz` of uploaded gems, so an attacker uploaded a gem whose metadata instantiated objects and exfiltrated config files. Per [the maintainers' own writeup](https://blog.rubygems.org/2013/01/31/data-verification.html), **no API keys were actually exposed**, because the service ran on Heroku and kept secrets in `ENV` rather than in config files. An accident of deployment style, not a control. Response took roughly 53 hours and included re-verifying SHA512 checksums for every gem against community mirrors.

Note the vector: not an HTTP request into a Rails app, but **gem metadata processing**. Same sink, different door. There is no dollar figure and there does not need to be one. The cost was ecosystem-wide trust.

**The key-management pair, thirteen years apart, and they belong together.**

- **CVE-2019-5420** (Rails, CVSS 9.8): in development mode Rails derived `secret_key_base` from the application's own name, which an attacker could recover by requesting an invalid route. With the key, mint a correctly signed payload and get RCE. **NVD assigns CWE-330 and CWE-77, not CWE-502.** The root cause was a predictable secret; deserialization was merely the payload. The fix was key generation, not a serializer change.
- **CVE-2026-39324** (rack-session, CVSS 9.3): the key was fine, and the *failure path* fell open. Quoting NVD: "If cookie decryption fails, the implementation falls back to a default decoder instead of rejecting the cookie." Fail-open beat the cryptography.

Together they make the case that "sign and encrypt the payload" is necessary and demonstrably not sufficient: what your code does when verification **fails** is part of the control. (Rails applications are explicitly *not* affected by the rack-session one. It uses a different code path. Getting that wrong would misinform every Rails reader.)

**CVE-2022-32224, the modern shape.** Active Record's `serialize :options` defaulted to YAML and deserialized with `YAML.unsafe_load`. An attacker who can write to the database, typically via SQL injection, escalates to RCE when the row is read back. Two things make it the best modern teaching case. It is a **second-order sink**: the untrusted data arrives from your own database, so any threat model drawing the trust boundary at the HTTP edge misses it entirely. And **the fix shipped an opt-out**, `use_yaml_unsafe_load`, because safe-by-default broke real applications. That tension between a safe default and a compatibility escape hatch that quietly restores the vulnerability is the single most transferable idea here, and it recurs in Psych 4, PyTorch 2.6, and Rails' cookie serializer.

**Two negatives worth more than most of the positives.**

The two most significant pieces of Ruby deserialization research in recent years **received no CVE at all**. Luke Jahnke's [Gem::SafeMarshal escape](https://nastystereo.com/security/ruby-safe-marshal-escape.html) (2024-12-03) and his Ruby 3.4 universal gadget chain (2024-11-24) were both fixed as ordinary RubyGems point releases. An NVD keyword search for `SafeMarshal` returns zero results. **A scanner, corpus, or curriculum built on CVE feeds alone will miss the actual state of the art.** Track the RubyGems `### Security:` changelog headings and the primary researchers' writeups instead.

And: **no Ruby or Rails deserialization CVE appears in the CISA KEV catalog**, verified programmatically against all 1,653 entries. The only Rails entries in KEV are path traversals. Ruby deserialization is a rich research area with **no CISA-confirmed mass-exploitation event**. There is documented commodity-botnet exploitation of CVE-2013-0156 and one documented ecosystem compromise. That is a real but much smaller claim than the one usually made, and saying it plainly is the fastest way to keep a knowledgeable reader.

## Everyone else got it too

**Java, 2015.** The technique landed at OWASP AppSec California on 2015-01-28, in Chris Frohoff and Gabriel Lawrence's "Marshalling Pickles: How Deserializing Objects Will Ruin Your Day," which covered Python `pickle`, Ruby `Marshal`, PHP serialization, and Java **together** and introduced ysoserial. Ruby was in the original talk; this project is not a footnote to the Java story, it is part of the same disclosure.

The era exploded ten months later, and not because of the talk. [Foxglove Security's post](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) on 2015-11-06 weaponized it against named enterprise products and shamed the vendors in public:

> "Even though proof of concept code was released OVER 9 MONTHS AGO, none of the products mentioned in the title of this post have been patched, along with many more."

Oracle's security alert landed four days later. That is a useful thing to understand about how disclosure actually moves vendors.

Java's structural answer was **JEP 290**, "Filter Incoming Serialization Data," created 2016-04-22 and delivered in Java 9. The critical caveat: **a serialization filter is not enabled or configured by default.** Nine years after ysoserial, the Java default is still unfiltered.

**.NET** went furthest. Microsoft's guidance is the most unambiguous vendor statement on this class anywhere: "**`BinaryFormatter` is insecure and can't be made secure.**" Their analogy is worth stealing: "assume that calling `BinaryFormatter.Deserialize` over a payload is the equivalent of interpreting that payload as a standalone executable and launching it." Starting in .NET 9 the in-box implementation throws on use.

**PHP** has the densest gadget space of any of them, because `__wakeup`, `__destruct`, and `__toString` give far more reachable magic methods than Java's single `readObject`. Roughly tens of chains for Java, and roughly **170 chains across 44 frameworks** for phpggc. (The 44 framework directories were counted twice and agree. The 170 came from a single count, so treat it as approximate; the comparison holds either way.) The best in-the-wild case is CVE-2015-8562 (Joomla), where the payload arrives in a **User-Agent header**, which makes the "untrusted input is everywhere, not just the request body" point better than any diagram. Sucuri documented the curve: first exploit 2015-12-12, and by 12-14 "basically every site and honeypot we have being attacked."

The single best idea to steal from PHP is Sam Thomas's `phar://` work (Black Hat USA 2018). Phar archive metadata is deserialized by **ordinary file operations**: `fopen`, `file_exists`, `file_get_contents`, `filesize`. An application can suffer deserialization **with no `unserialize()` call anywhere in its code**. That is the strongest available argument against the mental model "grep for the dangerous function and you have found the attack surface." The transferable lesson for Ruby readers: **the audit question is not "where do we call `Marshal.load`" but "what reaches a deserializer."**

**Python** supplies the best argument that denylist scanning loses. `picklescan`, the scanner the ML ecosystem relies on, has accumulated **26+ CVEs of its own** between 2025-02 and 2026-06:

| CVE | CVSS | The bypass |
|---|---|---|
| CVE-2025-1716 | 9.8 | `pip` was not on the unsafe-globals list; `pip.main()` pulls a malicious package |
| CVE-2025-1889 | 9.8 | Non-standard file extensions fall outside scan scope |
| CVE-2025-1945 | 9.8 | Flipping bits in ZIP headers hides the pickle from the scanner while `torch.load()` still loads it |
| CVE-2025-10156 | 9.8 | A deliberately bad CRC halts the scanner |
| CVE-2025-71350 | 8.1 | `torch.utils.collect_env.run` was not blocked |

Twenty-six CVEs, each one "we forgot about *this* callable." And it is not one bad tool: Trail of Bits' `fickling` has the identical failure in CVE-2026-22608, chainable to RCE **while the tool reports the file as safe**.

Note the CWE on both `fickling`'s and picklescan's first: **CWE-184, "Incomplete List of Disallowed Inputs."** MITRE has a dedicated weakness class for "your denylist is missing something," and both of the ecosystem's leading pickle scanners have been assigned it.

**Denylist scanning of a serialization stream is not losing on execution. It is losing on architecture.** That is the honest counterweight to this project's own scanner, and it is stated in exactly those terms: a gadget-discovery tool tells you what chains exist *today*. It is not a control.

The one thing that did work, across three ecosystems, was **changing the default.** PyTorch flipped `torch.load`'s `weights_only` to `True` in 2.6.0 (2025-01-29). NumPy flipped `allow_pickle` to `False` in 1.16.3, its release notes saying "in response to CVE-2019-6446." Ruby made `YAML.load` safe in 3.1. All three broke real users' workflows, and that cost is precisely what kept the unsafe default in place for years. A decade of warnings did nothing; changing the default did.

## Where this class stands, honestly

**The current OWASP citation is `A08:2025 – Software or Data Integrity Failures`.** Note the exact wording, because the naming has drifted across three editions and getting it wrong is the most likely error anyone makes here:

| Edition | Number | Exact name |
|---|---|---|
| 2017 | A08:2017 | **Insecure Deserialization** (its own dedicated category) |
| 2021 | A08:2021 | Software **and** Data Integrity Failures |
| **2025** | **A08:2025** | Software **or** Data Integrity Failures |

Insecure deserialization has not had its own Top 10 category since 2017. It is one of 14 mapped CWEs inside A08, and CWE-502 is explicitly among them.

**CWE-502** is named "Deserialization of Untrusted Data," has been in the CWE Top 25 every year from 2019 through 2025, and **ranks #15 in the 2025 list** with a score of 5.23, up one place from #16 in 2024. Its neighbours are stack and heap buffer overflows.

**The KEV numbers**, downloaded and parsed locally rather than asked of a search engine (catalog version 2026.07.24):

| Measure | Value |
|---|---|
| Total KEV entries | 1,653 |
| Entries mapped to **CWE-502** | **69 (4.17%)** |
| CWE-502 rank among all CWEs in KEV | **7th** |
| CWE-502 entries with known ransomware campaign use | **24 of 69 (34.8%)** |
| Baseline: all KEV entries with known ransomware use | 332 of 1,653 (**20.1%**) |

Two findings from that worth carrying away. **Deserialization bugs are roughly 1.7x more likely to be used by ransomware crews than the average confirmed-exploited vulnerability.** It is the strongest honest impact claim available for this class, it comes from a government catalog rather than a vendor, and anyone with `curl` can reproduce it. And **the rate is not declining**: 2025 was the highest single year on record, and Microsoft SharePoint alone picked up five CWE-502 KEV entries inside twelve months, one of them ("ToolShell," CVE-2025-53770) with ransomware use confirmed.

If you see MITRE's CWE page report 11 KEV entries for CWE-502 rather than 69, both are right and they measure different things. The CWE Top 25 methodology analyses the 39,080 CVE records published between 2024-06-01 and 2025-06-01, so its count is scoped to a one-year publication window. The 69 is the all-time count in the live catalog. Quoting them side by side without that note reads as an error.

**There is no credible aggregate dollar figure for this bug class.** Numbers of that shape circulate. They come from vendor marketing and extrapolations from "average cost of a breach" surveys, and they are not traceable to incident data. A repo laundering a marketing number into an academic-looking citation is worse than having no number.

## Corrections: things you will read that are wrong

Every item below is something a confident write-up plausibly asserts, checked against a primary source, and found wrong. This list is the most useful thing in this chapter, because it is a map of where the popular retelling of this vulnerability class fails.

| The common claim | What the record says |
|---|---|
| **Equifax was a deserialization breach.** | **Wrong.** CVE-2017-5638 is OGNL injection, NVD **CWE-755**, CISA KEV **CWE-20**. The Struts deserialization CVE is CVE-2017-9805, a different bug in a different component, and it was not the Equifax vector. |
| **CVE-2013-0156 is a CWE-502 record.** | **Wrong.** NVD assigns **CWE-20**. So does CVE-2013-3567 (Puppet). Filtering NVD by CWE-502 to enumerate "the deserialization CVEs" silently drops the most famous Ruby one. |
| **CVE-2019-5420 is a deserialization CVE.** | **Misleading.** NVD assigns **CWE-330 and CWE-77**. The root cause is a predictable dev-mode `secret_key_base`. The fix was key generation. |
| **The current OWASP category is "A08:2021 Software and Data Integrity Failures."** | **Stale.** It is **A08:2025 Software *or* Data Integrity Failures.** "Or", not "and". |
| **`YAML.load` is unsafe in Ruby.** | **Version-dependent, and the unqualified claim is now wrong.** Verified by execution: Psych 3.3.2 (Ruby 3.0.7) deserializes arbitrary objects; Psych 4.0.4 (Ruby 3.1.7) and later raise `Psych::DisallowedClass`. **`Marshal.load` reconstructs arbitrary objects on every version tested.** It never got a safe default. |
| **Apache Commons Collections had a CVE.** | **Wrong, and it hides the lesson.** All three identifiers are vendor-scoped: CVE-2015-4852 (Oracle), CVE-2015-7501 (Red Hat), CVE-2015-6420 (Cisco). The library never received one, and the ASF publicly argued it should not. |
| **The 2016 SFMTA / San Francisco Muni ransomware attack was Oracle WebLogic CVE-2015-4852.** | **Unsupported, and contradicted by SFMTA.** Their own statement: "The SFMTA network was not breached from the outside, nor did hackers gain entry through our firewalls." The WebLogic association describes the *attacker's general toolkit across many victims*, not a finding about SFMTA. CISA KEV marks CVE-2015-4852 `knownRansomwareCampaignUse: "Unknown"`. |
| **RDoc CVE-2024-27281 was fixed in 6.3.4 / 6.4.1 / 6.5.1 / 6.6.3.** | **Wrong.** The Ruby advisory states those contain an **incorrect fix**. The correct versions are 6.3.4.1, 6.4.1.1, 6.5.1.1, 6.6.3.1. |
| **CVE-2026-39324 (rack-session) affects Rails.** | **Wrong.** The upstream advisory says Rails is typically not affected; it uses a different code path. |
| **ruby-saml's 2024-2025 CVEs are deserialization bugs.** | **Wrong.** CVE-2024-45409 is CWE-347. CVE-2025-25291 / CVE-2025-25292 are signature wrapping via a parser differential. Serious, critical, widely exploited, and not CWE-502. |
| **Luke Jahnke's Gem::SafeMarshal escape has a CVE.** | **No CVE exists.** Fixed as an ordinary RubyGems point release under a `### Security:` changelog heading. |
| **Equifax's breach cost $1.4 billion "per SEC filings."** | **Unverified as a filed figure.** It traces to earnings-call commentary relayed by press. Defensible: **$113.3M** (FY2017 10-K, verbatim) and **$575M to $700M** (FTC settlement). |

One method warning falls out of that table and it is worth stating on its own: **filtering a vulnerability corpus by CWE-502 to "find the deserialization CVEs" is a broken method, and it silently drops most of the canon.** CVE-2013-0156 is CWE-20. CVE-2015-8562 (Joomla, mass-exploited) is CWE-20. CVE-2016-4010 (Magento) is CWE-74. CVE-2025-27407 (graphql-ruby) is CWE-94. Older records predate consistent CWE-502 mapping, and CNAs disagree with NVD routinely. The KEV numbers in this chapter use the catalog's own `cwes` field and therefore inherit the same limitation: they are a floor, not a census.

Finally, a standing hazard. This topic is heavily polluted by content-farm output. One article claiming a Ruby `Oj.load` object-injection RCE uses a **placeholder CVE ID**, has no GHSA, no version range, and names a product that does not exist. If a claim has no primary source, it does not belong in a teaching document. That rule did more work on this topic than on any other in this repo.

## Where to go next

[02-ARCHITECTURE.md](./02-ARCHITECTURE.md) turns these ideas into structure: the two readers that share one vocabulary, the three decision states and why there is no `accepted?` predicate, the scanner's gate-plus-format-plus-arity taxonomy, and why the parser and the detector are deliberately allowed to disagree about the same stream.
