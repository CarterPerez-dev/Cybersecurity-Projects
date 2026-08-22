<!-- ©AngelaMos | 2026 -->
<!-- 04-CHALLENGES.md -->

# Challenges

Every challenge here has the same completion bar as the project itself: **the control has to go red when you remove it.** Write the test, watch it fail, implement, then delete your implementation and check that your test, and specifically your test, goes red. If it stays green you built decoration.

Two rules that apply to all of them:

- A new scored rule needs benign corpus cases. If it cannot survive them it does not ship.
- A new layer needs a benchmark class of its own, so the ablation can prove it is load-bearing rather than alibied.

## Easy

### 1. Add a chat-template marker

**Build:** current models use control tokens this project does not list. Add markers for a model family that is not covered, for example Gemma's `<start_of_turn>` or Command-R's `<|START_OF_TURN_TOKEN|>`.

**Why:** delimiter forgery is the highest-precision ingress rule there is, because real support tickets do not contain model control sequences. Extending it is cheap and the false-positive risk is near zero.

**You will learn:** how a precision-first rule differs from a recall-first one, and why this one is `HIGH` severity while the imperative rule is `MEDIUM`.

**Hints:** `config.CHAT_TEMPLATE_MARKERS`. Add cases to `bench/corpus/attacks/delimiter_forgery.yaml`. Check the marker cannot appear in ordinary prose before you add it.

**Test it works:** `just bench` still shows 100% on `delimiter_forgery` with a larger denominator, and the hard-benign class has not moved.

### 2. Report which reading matched

**Build:** when ingress fires on a derived reading rather than the raw text, the finding does not say so. Add that to the evidence.

**Why:** "matched after base64 decode" is a materially different signal from "matched in plain text". An operator triaging alerts wants to know.

**You will learn:** why `evidence` is digested in the audit log, and how to add signal without adding an attacker-controlled string to a record.

**Hints:** `IngressLayer._first_imperative` iterates readings. Return which one hit. Keep the evidence field free of raw attacker text, or make sure the digest still covers it.

**Test it works:** an embedded base64 payload produces evidence naming the decode, and the audit log still contains no payload bytes.

### 3. A `--explain` mode for the benchmark

**Build:** a flag that prints, for every corpus case, which layer and rule caught it and by which reading.

**Why:** the benchmark says a class is at 100%. It does not say whether every case was caught by the rule you intended. A class can sit at 100% while half of it is caught incidentally by a different layer, which means your rule is untested.

**You will learn:** attribution as distinct from detection, and why the two-number ablation exists.

**Hints:** `evaluate()` already has the verdict. Thread the findings out instead of a bool.

**Test it works:** run it and find at least one case caught by something other than its class's intended rule. There are some.

## Intermediate

### 4. Structured output validation

**Build:** a layer that validates model output against a schema before it reaches your application, so a model that was told to emit JSON emits JSON or the verdict is BLOCK.

**Why:** a large fraction of real agent breakage is not exfiltration, it is the model being talked into emitting something the parser downstream was not expecting. This is `LLM05:2025 Improper Output Handling`.

**You will learn:** where the boundary sits between a firewall concern and an application concern, which is a genuinely arguable line.

**Hints:** implement the `Layer` protocol shape for the egress side. Decide deliberately whether a schema violation is invariant or scored, and write down why.

**Test it works:** a valid document passes, an injected document that breaks the schema blocks, and gutting the check turns exactly one test red.

### 5. Per-origin taint policy

**Build:** taint that carries its origin channel into the tool decision, so `NO_UNTRUSTED_INFLUENCE` can be relaxed for an origin the operator trusts more, for example an internal wiki, while staying hard for a public ticket queue.

**Why:** the current model is binary. Real deployments have gradations, and forcing everything to the strictest setting is how a control gets turned off entirely.

**You will learn:** how to add expressiveness to a policy without creating a way to accidentally disable an invariant. That is the hard part, and it is the whole exercise.

**Hints:** `Context.tainted_by` already returns origins, not a boolean. `Tool.guards` is where the relaxation belongs. Consider what happens when two DATA spans from different origins are both present, because the answer is not obvious.

**Test it works:** a trusted origin permits the tool, an untrusted one refuses it, **and mixing both refuses**. That last case is the one that matters.

### 6. Make the proxy honest about pasted retrieval

**Build:** an opt-in header or request field that lets a client mark which message contains retrieved content, so the proxy can treat it as DATA instead of inferring USER.

**Why:** this is the proxy's documented weakness. Retrieved content pasted into a user message is what most RAG applications do, and it is exactly the case inference gets wrong.

**You will learn:** why the library API forces provenance to be declared, by building the smallest possible version of that for a protocol that has no slot for it.

**Hints:** `infer_context` in `proxy/infer.py`. The `ChatMessage` model already allows extra fields. Keep the failure mode conservative: an unrecognised marking should mean untrusted, not trusted.

**Test it works:** the same injection blocks when marked and does not when unmarked, and the startup warning still fires, because the mode is still weaker than the library.

## Advanced

### 7. A second victim agent

**Build:** an `Agent` implementation backed by a local model through Ollama, behind a flag, defaulting off.

**Why:** the mock is deterministic and gullible by construction. A real model is neither. Watching the firewall behave identically against both is the demonstration that it never inspects the model.

**You will learn:** what actually changes when the backend is real, which should be nothing on the firewall side and quite a lot on the "did the attack work" side.

**Hints:** `Agent` is one method. Keep it out of every test, every gate, and every default path. The keyless offline story is a feature and breaking it would be a regression.

**Test it works:** the same policy produces the same verdicts against both backends on the same corpus. Where they differ, the difference is in whether the model complied, never in what the firewall decided.

### 8. Canary generation and rotation

**Build:** derive canaries per session from a keyed function instead of registering literals, so a leaked canary identifies which session leaked it.

**Why:** in a real deployment you want to know which tenant, which request, which document. A static canary tells you a leak happened. A derived one tells you where.

**You will learn:** the tension between a canary you can match cheaply and one that carries information, and where `MIN_CANARY_LENGTH` comes from.

**Hints:** the matcher strips to alphanumerics and casefolds before matching. Whatever you generate has to survive that with at least 8 characters left, and `Firewall.__init__` will raise `PolicyError` if it does not.

**Test it works:** two sessions get different canaries, each matches only its own, and a canary too short after stripping is refused loudly at construction rather than dropped.

### 9. Adversarial corpus generation

**Build:** a generator that composes attack primitives, encoding, unicode smuggling, delimiter forgery, indirection, into stacks the hand-written corpus does not contain, and reports which compositions get through.

**Why:** the benchmark's own output says the corpus measures what the author thought of. This is the direct attack on that limitation.

**You will learn:** why the exhaustive 584-stack egress test exists and why the ingress side has no equivalent. Expect to find real misses. That is the point.

**Hints:** model it on the egress property test. Do not auto-promote anything you find into the scored corpus; untrusted input never writes itself into ground truth. Write findings to `candidates/` for review, which is what `just harvest` already does.

**Test it works:** it finds at least one composition that gets through, and you can state precisely why the existing rules miss it.

## Expert

### 10. A formal argument for the fencing invariant

**Build:** a machine-checked or rigorously-argued statement of the property "a DATA span cannot terminate its own fence", including the assumptions it rests on.

**Why:** the project calls this an invariant. That word should mean something stronger than "we tested it a lot".

**You will learn:** how much of a security property is actually the CSPRNG's guarantee, how much is the renderer's, and what happens at the boundary between them.

**Plan:**
1. State the property precisely. What is quantified over, and what is the adversary allowed to know?
2. Enumerate the assumptions: nonce entropy, per-request freshness, that `render` is the only path to a prompt string, that the model does not leak the fence in its output.
3. Check each assumption against the code. **At least one is weaker than it looks**, and finding which is the exercise.
4. Write the argument, and write the counterexample for the assumption that does not hold.

**Test it works:** you can name a deployment configuration where the invariant does not hold and explain exactly why.

### 11. Multi-turn taint across a real conversation

**Build:** a taint model that survives a full conversation, including the case the design explicitly punted on: a prior assistant turn that already passed egress but contained attacker-influenced content.

**Why:** this is a **known, recorded weakness**. Mapping assistant turns to DATA would taint every conversation after turn one and make tool authorization useless in proxy mode. Mapping them to USER means a payload that survived an earlier turn is re-read as semi-trusted. Neither is right.

**You will learn:** why the current answer is a documented compromise rather than a solution, and how expensive the correct answer is.

**Plan:**
1. Reproduce it. Get a payload through egress in turn one and have it influence turn three.
2. Decide what the correct trust level for a prior assistant turn even is. Argue both sides before you build.
3. Consider a fourth `Trust` level, and consider carefully whether adding one is worth it, because a closed three-value set is part of why the model is comprehensible.
4. Measure what your change does to tool authorization in a normal multi-turn session. If everything is refused by turn four, you have made the agent useless, which is a different failure.

**Test it works:** the cross-turn payload is caught, **and** a benign ten-turn conversation still permits its tools at turn ten.

## Mix and match

- **9 plus 3.** Generate adversarial stacks, then use explain mode to see which layer caught the survivors. You will find cases caught by the wrong rule.
- **5 plus 11.** Per-origin taint and multi-turn taint are the same problem at different time scales.
- **4 plus 6.** Output validation plus honest proxy provenance gets you close to a drop-in that is not lying about its guarantees.

## Performance work

The closure in `normalize/views.py` dominates the p99, at roughly 3 ms. Two directions:

**Memoize across layers.** `ingress` and `provenance` both call `readings()` on the same span text in the same request. Caching between them is straightforward. The reason it was not done is that layer independence is a property the tests check directly, and a shared cache couples them. **Do not do this without a test proving the layers still hold independently**, which is exactly what makes it interesting.

**Bound the frontier smarter.** The closure explores breadth-first to a fixed budget. Some views are far more productive than others on real input. Measure before you tune, because at one point the closure saturated at 12 variants and raising the budget from 96 to 5000 changed nothing.

## Security work

- **Sanitization.** There is no sanitizing mode, and the design argues against one, because normalization must never silently rewrite legitimate content. If you disagree, build it and make the argument. State what the model sees and what the user sees, and how a reviewer tells them apart.
- **Detection of the firewall itself.** A model told to describe its own prompt will describe the fence. Does that matter? Argue it either way, then measure whether an attacker who knows the fence format gains anything.
- **Rate limiting by cost, not count.** The arena limits attempts. It does not limit the work an attempt causes, and a 4,000-character ticket of stacked encodings costs more than a plain one.

## Contributing back

If you find a real bypass, the useful report has: the exact payload, the policy it beat, which layer should have caught it, and whether it is an ingress miss (expected, ingress is incomplete by design) or an invariant break (serious).

The distinction matters. Ingress misses are cheap and expected. An invariant break is a genuine finding, because those layers are supposed to hold regardless of payload.

## Completion checklist

- [ ] Added a rule and a benign case that keeps it honest
- [ ] Gutted your own control and watched **your** test go red
- [ ] Ran `just bench` and read the hard-benign line, not the pooled one
- [ ] Found a case the corpus does not cover
- [ ] Explained to someone else why ingress is scored and provenance is not
- [ ] Beat arena level 6 without reading the source
- [ ] Read a verdict and predicted which layer fired before looking

## Getting help

Read the verdict first. Every finding names its layer and rule, which is what that field is for.

`just bench` with a modified policy is the fastest way to isolate which layer is responsible for a behaviour you did not expect. Turn layers off one at a time.

When something passes that should not, check whether your test goes through `Firewall.inspect` or through `decide()` directly. The second skips `escalate()`, and that difference hid a false positive in this project for eleven milestones.
