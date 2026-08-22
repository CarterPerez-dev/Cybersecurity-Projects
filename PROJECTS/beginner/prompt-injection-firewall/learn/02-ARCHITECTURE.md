<!-- ©AngelaMos | 2026 -->
<!-- 02-ARCHITECTURE.md -->

# Architecture

## High level

```
                        YOUR APPLICATION
                               |
              declares provenance explicitly
                               |
                               v
    +--------------------------------------------------+
    |                    Context                        |
    |  spans: (SYSTEM, "you are support")               |
    |         (USER,   "where is my order")             |
    |         (DATA,   "<ticket body>", origin=...)     |
    |  nonce: a3f9c1e0d47b2856   per request, CSPRNG    |
    |  tainted_by: derived from spans, never set        |
    +--------------------------------------------------+
                               |
                    firewall.inspect(ctx)
                               |
          +--------------------+--------------------+
          |                    |                    |
     normalize             ingress             provenance
     (reports)            (scored)            (invariant)
          |                    |                    |
          +--------------------+--------------------+
                               |
                     escalate() then decide()
                               |
                          Verdict  ---- BLOCK? stop here
                               |
                       firewall.render(ctx)
                               |
              +----------------+----------------+
              | <<<UNTRUSTED-a3f9c1e0d47b2856   |
              |   ...content verbatim...        |
              | <<<END-a3f9c1e0d47b2856>>>      |
              +----------------+----------------+
                               |
                        THE MODEL (untrusted)
                               |
                          AgentReply
                     text + tool_calls
                               |
                firewall.inspect_egress(reply, ctx)
                               |
                    +----------+----------+
                    |                     |
                toolauth               egress
               (invariant)           (invariant)
                    |                     |
                    +----------+----------+
                               |
                            decide()
                               |
                            Verdict
```

Two inspection points, not one. `inspect()` runs before the model. `inspect_egress()` runs after. They share the decision algebra and nothing else.

## Component breakdown

| Module | Responsibility | Reads payload meaning? |
|---|---|---|
| `context.py` | The trust-tagged prompt. Taint derivation | n/a |
| `verdict.py` | `Severity`, `Decision`, `Finding`, `Verdict` | n/a |
| `policy.py` | Which layers run, thresholds, `escalate()`, `decide()` | n/a |
| `firewall.py` | Orchestration, fencing, fail-closed wrapping | n/a |
| `normalize/unicode.py` | Tag block, zero-width, bidi, confusables, NFKC | reads bytes, decides nothing |
| `normalize/unwrap.py` | Transport decoding, whole-span and embedded | reads bytes, decides nothing |
| `normalize/views.py` | The bounded closure over reversible readings | shared by three layers |
| `layers/normalize.py` | Emits findings for every transform required | no |
| `layers/ingress.py` | Template markers, instruction-shaped text | **yes, and it is labelled** |
| `layers/provenance.py` | Nonce presence in DATA | no |
| `layers/toolauth.py` | Taint, guards, effects, argument schema | no |
| `layers/egress.py` | Canary closure, URL host control | no |
| `tools.py` | `Effect`, `Guard`, `Tool`, `ToolCallRequest`, `AgentReply` | n/a |
| `audit.py` | JSONL records carrying no attacker content | n/a |
| `agent/mock.py` | The deliberately gullible model | n/a |
| `proxy/` | OpenAI-compatible surface, inferred provenance | n/a |
| `arena/` | Six levels, sessions, limits, bypass capture | n/a |

One row is doing something different from all the others, and that is the design.

## The data model

### Trust is a closed set

```python
class Trust(StrEnum):
    SYSTEM = "system"   # you wrote it
    USER   = "user"     # the human at the keyboard wrote it
    DATA   = "data"     # something on the internet wrote it
```

Three levels, not a number. A numeric trust score invites arithmetic, and there is no meaningful sense in which two USER spans equal one SYSTEM span.

### A span cannot be malformed

```python
@model_validator(mode = "after")
def _origin_matches_trust(self) -> Self:
    if self.trust is Trust.DATA and self.origin is None:
        raise ValueError("a DATA span must declare its origin")
    if self.trust is not Trust.DATA and self.origin is not None:
        raise ValueError(f"a {self.trust} span cannot have an origin")
    return self
```

Untrusted content without a stated source is not representable. You cannot forget to say where a document came from, because the constructor refuses.

### Taint is derived, not stored

Covered in `01-CONCEPTS.md`, and it is worth restating as an architectural property: there is **no setter**. `tainted_by` is a `@property` computed from the spans. The class of bug where a flag and reality disagree cannot occur, because there is only one representation.

`Context` is frozen and every builder method returns a new instance, so a context cannot be mutated out from under a verdict that already described it.

### Findings name themselves

```python
Finding(layer = "provenance", rule = "nonce-forgery",
        severity = Severity.CRITICAL, invariant = True,
        span_index = 2, evidence = "fence nonce present in DATA")
```

Every finding carries its layer and rule so a consumer can render `BLOCKED by provenance/nonce-forgery`. This is not cosmetic. The arena's entire teaching mechanism is that the player sees which rule stopped them, so verdict legibility is a hard requirement rather than a nicety.

`evidence` is **derived from attacker content** and is treated as hostile throughout. It never reaches the audit log un-digested.

## The decision algebra

```
escalate(findings, policy):
    strict_data off  ->  unchanged
    strict_data on   ->  data-imperative and chat-template-marker
                         become invariant

decide(findings, policy):
    any invariant                      ->  BLOCK
    max scored severity >= threshold   ->  BLOCK
    otherwise                          ->  ALLOW
```

Three properties worth naming.

**Invariants are not thresholded.** No policy setting disables one. `block_threshold` only ever moves the bar for scored findings.

**INFO never blocks.** `decide()` filters `severity > Severity.INFO` out of the scored comparison. This exists so `layer-disabled` notices can ride along in every verdict without ever affecting it.

**Escalation is a pure function over findings, not a layer.** The original design had the provenance layer re-emit ingress findings as invariant. That would require one layer to receive another layer's output, which breaks the uniform `inspect(ctx, policy)` shape that lets the orchestrator wrap all layers identically. Making it a function that the `Firewall` applies during orchestration keeps the `Layer` protocol clean.

## Fail-closed

Every layer call is wrapped:

```python
def _run(self, name: str, ctx: Context) -> list[Finding]:
    if not self._enabled(name):
        return [self._disabled(name)]
    try:
        return self.layers[name].inspect(ctx, self.policy)
    except Exception as error:
        return [self._layer_error(name, error)]
```

An exception becomes `Finding(rule="layer-error", severity=CRITICAL, invariant=True)`, which forces BLOCK. A firewall that fails open on an unhandled exception is worse than no firewall, because it reports success while doing nothing.

Note the bare `except Exception`. That is deliberate and it is the one place in this codebase where catching everything is correct: the point is that *no* failure mode reaches the model.

`evidence` is `type(error).__name__` and never the exception message, because messages can contain the input that caused them.

**A disabled layer is recorded, not silent.** `layer-disabled` at INFO severity enters the verdict, so a consumer can always distinguish "this layer ran and found nothing" from "this layer never ran". The arena uses exactly this to tell a player that level 2 was winnable because a layer was off, not because the attack was clever.

## Threat model

**Defended.** An attacker who controls the content of an untrusted span the agent will read: a ticket, a retrieved document, a web page, a tool result, an email body, a filename. This is the realistic and overwhelmingly common case.

**Defended, partially and honestly.** An attacker who controls the user turn and is talking the agent out of its constraints, to the extent that egress and tool authorization hold. Ingress catches the naive attempts and misses the good ones. That is stated rather than hidden.

**Not defended.** An attacker who controls the system prompt, the policy file, the model weights, or the firewall process. Outside the trust boundary by construction.

**Explicitly assumed hostile: the model.** The firewall never trusts model output, model-declared intent, or model compliance. The system prompt does tell the model that DATA spans are inert, because it raises attack cost, and that instruction is documented as **not a control**.

## Defense in depth, and what each layer actually buys

```
attack class            normalize  ingress  provenance  toolauth  egress
----------------------  ---------  -------  ----------  --------  ------
role override                        X
delimiter forgery                    X
nonce forgery                                    X
unicode smuggling           X        X
encoded payload             X        X
embedded encoded            X        X
indirect injection                   X
tool coercion                                              X
tool arg smuggling                                         X
unconfirmed spend                                          X
encoded exfiltration                                                X
url exfiltration                                                    X
```

The benchmark reports this as a **two-number ablation**: what each layer catches alone, and what it adds to the full stack. Those are different questions.

`normalize` scores solo 10, marginal 0. A single leave-one-out number would call it inert and delete it. It is not inert, it is **alibied**: `ingress` normalizes internally for its own matching, so in the full stack it covers normalization completely. Turn `ingress` off, as arena level 2 does, and those 10 cases are the only thing standing between a player and an invisible payload.

A layer with **both** numbers at zero is inert and gets deleted. The suite fails if that ever happens.

## Configuration

Every constant lives in `config.py`. Not most of them. All of them, including the regex fragments the imperative patterns are assembled from and the codepoint tuples the Unicode sets are built out of. There are no magic numbers or strings anywhere else in the package.

`config.py` is also pure ASCII by construction. The Unicode sets are built from integer codepoints rather than written as literals:

```python
ZERO_WIDTH_CODEPOINTS: Final = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)
ZERO_WIDTH_CHARS: Final = frozenset(chr(p) for p in ZERO_WIDTH_CODEPOINTS)
```

A config file about invisible characters that itself contains invisible characters is a file nobody can review.

`Policy` is the runtime knob: which layers are enabled, the block threshold, `strict_data`, the canary list, the host allowlist, and forbidden effects. Arena levels are YAML files loaded into `Policy` instances.

## Storage

Almost nothing, deliberately.

| What | Where | Why |
|---|---|---|
| Sessions | in memory, LRU + TTL | The arena is a demo, not an account system |
| Audit records | JSONL at `NS_AUDIT_PATH`, disabled by default | No path means no records, which is the right default |
| Bypass payloads | JSONL at `NS_BYPASS_PATH` | So `just harvest` has something to read |
| Corpus | YAML in the repo | Reviewed by hand, never written by the application |

The core library performs **no I/O at all**. No network, no filesystem, no clock reads beyond elapsed-time measurement. That is what makes it testable and what makes the arena safe to expose.

### The audit record carries no attacker content

```json
{"policy_id":"level-6","decision":"block","elapsed_ms":0.027,
 "spans":[{"trust":"data","origin":"ticket:ab15089d7d9114ef"}],
 "findings":[{"layer":"ingress","rule":"data-imperative",
              "severity":"MEDIUM","invariant":false,
              "span_index":2,"evidence_digest":"3081bc7f2caf4077"}]}
```

Both `evidence` and the origin `ref` are digested. Evidence is derived from span text, and in proxy mode the origin ref comes straight out of the request body, so both are attacker-influenced. A log the operator considers safe to keep must not become a place attacker content is stored.

## Deployment

```
                    Cloudflare tunnel (optional overlay)
                               |
                               v
              +----------------------------------+
              |  nginx  (serves the built UI,    |
              |          proxies /api)           |
              |  127.0.0.1:33572                 |
              +----------------+-----------------+
                               |  internal network only
              +----------------v-----------------+
              |  arena  (FastAPI, uvicorn)       |
              |  read_only: true                 |
              |  cap_drop: ALL                   |
              |  no-new-privileges               |
              |  tmpfs /tmp                      |
              |  volume /var/lib/not-sandboxed   |
              |  cpus 1.0, memory 512M           |
              +----------------------------------+
```

The API container is never published to the host. Only nginx binds a port, and it binds to `127.0.0.1`.

**Ports are configurable high numbers, never defaults.** UI `33572`, dev UI `61878`, proxy `39441`. Binding a well-known port is how you collide with whatever else the operator is already running.

**The container image bakes the virtualenv and the entrypoint calls `uvicorn` directly.** An earlier version ran `uv run uvicorn` at container start, which re-resolves the environment on every boot and, more importantly, needs a writable cache. Under `read_only: true` it restart-looped on `Could not create temporary file`. No test could have caught that, because the suite never starts a container.

**Dev and prod are namespace-isolated by construction.** Project names and container names are structural literals, one set per compose file, never variables. Each compose recipe passes its own env file explicitly. There is nothing to switch between environments and therefore nothing to forget.

## Design decisions

**Library first, proxy second.** The proxy is a convenience wrapper where provenance is inferred and therefore weaker. Building the proxy first would have made the weak mode the default mode.

**A deterministic mock agent as the default backend.** Because the firewall never inspects the model, firewall behavior is identical whether the backend is the mock, a local model, or a hosted API. The mock makes failures unambiguous: if the secret leaks, the firewall failed, and "the model was having an off day" is not available as an explanation. It also runs in CI, offline, free, with no flakiness.

**The caller declares provenance.** This is the one piece of work the API pushes onto you and it is not an oversight. It is the only honest way to know what is untrusted, and the API is shaped so the declaration is unavoidable: `Context.data()` requires an `Origin`.

**Arena levels are configurations, not difficulties.** Level 3 is not "harder", it is "provenance is on now". A player who beats level 2 learns that normalization plus ingress is not enough, which is a true and useful thing to learn. Difficulty tuning would have taught nothing.

**Normalization is a `Layer`, not a loose pre-pass.** The fail-closed contract has to cover it, and the uniform shape is what lets the orchestrator wrap all three request-side layers identically. The cost is that `ingress` normalizes again internally, so that work happens twice. That is deliberate: layer independence is a property the tests check directly, and sharing a cached shadow would couple them.

## Performance

```
p50   0.53 ms
p99   3.09 ms
```

The dominant cost is the bounded closure in `normalize/views.py`, which `ingress`, `provenance`, and `egress` all use. It is budgeted twice: `MAX_VARIANT_ROUNDS` bounds depth, and a per-caller variant cap bounds breadth. `egress` gets 96 readings, `ingress` and `provenance` get 24, because ingress runs on every request and egress runs on model output.

That closure is why p99 is three milliseconds rather than a quarter of one. Before it was applied to ingress, p50 was 0.05 ms and an encoded payload embedded in prose walked straight through. The cost buys a real class of detection and it is stated rather than hidden.

Both directions are bounded. `MAX_NORMALIZE_BYTES` caps decoder input at 256 KiB. `MAX_EGRESS_BYTES` caps outbound scanning at 64 KiB, per string and in aggregate across a reply, and exceeding it is an **invariant BLOCK**. Refusing to scan an outbound message is not a reason to release it.

## Extensibility

**A new scored rule** goes in `ingress.py` with its pattern in `config.py`, plus benign corpus cases. If it cannot survive the benign corpus it does not ship.

**A new invariant layer** implements the `Layer` protocol, registers in `LAYER_ORDER`, and needs a benchmark class of its own so the ablation can prove it is load-bearing.

**A new tool guard** adds a `Guard` member, a rule constant in `TOOLAUTH_INVARIANT_RULES`, and a branch in `_guard_findings`. There is a structural test that fails if a `Guard` member exists with no rule behind it, which exists because `USER_CONFIRMED` was declared and read nowhere for eleven milestones.

**A new backend** implements `Agent`, which is one method: `respond(prompt) -> AgentReply`.

## Limitations

- **Ingress is incomplete by construction.** Not a bug, a category.
- **Proxy provenance is inferred and wrong for most RAG applications.** Pasted retrieval reads as USER.
- **A prior assistant turn maps to USER, not DATA.** Mapping it to DATA would taint every conversation after turn one and make tool authorization useless in proxy mode. A payload that survived an earlier turn is re-read as semi-trusted, and that is a real weakness recorded here rather than discovered later.
- **There is no sanitizing mode.** The design originally specified a third decision, `SANITIZE`, that would send normalized text to the model instead of the original. It was declared and never implemented, and writing these docs is what surfaced that: `Decision.SANITIZE` and `Verdict.sanitized` existed for eleven milestones with zero producers anywhere in the codebase. Both were deleted rather than left in place, because a public enum member reads as a shipped capability. The design's own reasoning argues against building it: normalization must never silently rewrite a user's legitimate content, which is the whole reason the layer reports instead of deciding. **Original text is what reaches the model, always.**
- **Sessions are in-process.** Two arena replicas do not share state.

## Comparison

| | This | Guardrail libraries | LLM-as-judge | Fine-tuned classifier |
|---|---|---|---|---|
| Survives paraphrase | invariant layers yes, ingress no | no | no | partly |
| Needs a model | no | usually no | **yes** | yes |
| Itself injectable | no | no | **yes** | no |
| Runs offline | yes | yes | no | with weights |
| Stops tool misuse | yes | rarely | no | no |
| Stops exfiltration | yes | sometimes | no | no |
| Honest about limits | this is the point | varies | rarely | rarely |

The row that matters is the last one. Most tools in this space report a detection rate and no false-positive rate, or report both against a corpus they wrote. This one reports the false-positive rate on the hard class, on its own line, and tells you in its own output not to quote the detection number.
