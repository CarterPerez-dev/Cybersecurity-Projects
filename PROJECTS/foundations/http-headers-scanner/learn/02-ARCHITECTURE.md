# Architecture

This file explains how the code is organised and why. It is the bridge between "I get what HTTP headers are" (the previous file) and "I can read this exact Python code" (the next file). Read it after concepts and before implementation.

The whole scanner is one Python file plus one test file. Less than 700 lines total. That is small enough that you might wonder why we are using the word "architecture" at all. The answer: even small programs benefit from being split into pieces, and the WAY they get split matters. A real production scanner is going to grow into many files. Learning what the split looks like at this size makes the bigger ones less scary.

## 1. The big picture

The scanner is a pipeline. Data flows left to right through four stages:

```
   ┌────────┐  URL  ┌──────────┐  bytes   ┌────────────┐  findings  ┌──────────┐
   │  User  │ ────▶ │  scan()  │ ──────▶  │ evaluate_  │ ────────▶  │  render  │
   │  CLI   │       │  fetches │          │  header()  │            │  report  │
   └────────┘       └──────────┘  loop    │   ×6       │            └──────────┘
                                          └────────────┘
```

1. **CLI layer.** The user types `headers https://example.com`. `argparse` turns that into a normal Python object with `args.url` and `args.timeout`.
2. **Network layer (`scan()`).** Makes one HTTPS request, follows redirects, returns the raw headers as a dict.
3. **Evaluation layer (`evaluate_header()`).** Pure function. Takes one rule and the response headers, returns one finding. Called once per rule. No network. No printing.
4. **Render layer (`_render_report()`).** Takes the report, prints a coloured table plus the grade panel plus recommendations.

The reason it is laid out this way: each stage is independently testable. We can hand `evaluate_header()` a fake dict of headers and check the finding, without ever touching the internet. We can build a fake `ScanReport` and check the score and grade, without running `scan()` at all.

If any of these stages were mashed together (for example, if `scan()` directly printed its output and the math lived inside the print logic), testing would mean spinning up a real or fake web server every time. Splitting them apart is the whole reason you can write 20 tests that run in under a second.

## 2. The four key data shapes

We use **dataclasses** for our data. A dataclass is just a class where Python writes the boilerplate for you. Instead of this:

```python
class HeaderRule:
    def __init__(self, header, severity, description, recommendation, must_match=None):
        self.header = header
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.must_match = must_match
```

You write this:

```python
@dataclass(frozen=True, slots=True)
class HeaderRule:
    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None
```

The `@dataclass` decorator on top reads the field declarations and generates the `__init__` for you. It also generates equality (`==`), a string representation, and a few other useful things.

Two flags worth understanding:

- **`frozen=True`** makes the dataclass **immutable**. Once you create a `HeaderRule`, you cannot do `rule.severity = "low"`. Trying to modify a field raises an error. This is good for "value object" types where you want guarantees that no other piece of code can change them out from under you.
- **`slots=True`** makes instances **smaller in memory**. Without slots, every Python object carries around a hidden dictionary for its attributes, which is flexible but uses more memory. With slots, attributes go into fixed slots, no dict. For a record type with a known set of fields, this is pure win. Costs you nothing.

We have four shapes total:

### 2.1 `HeaderRule`: "what we are looking for"

One rule is one thing-to-check. Header name, severity, description (for humans), a recommendation (what to set if missing), and an optional `must_match` regex (for headers like `X-Content-Type-Options` where the *value* has to be right, not just present — a plain word like `"nosniff"` works as a substring check, while a richer pattern like `r"max-age\s*=\s*[1-9]"` rejects HSTS values that disable themselves).

This is the rule the scanner walks down. The whole list of rules lives in a module-level constant called `RULES`. Adding a new header check means appending to that list. The rest of the code is generic.

### 2.2 `HeaderFinding`: "what we found"

One finding is the result of running one rule against the server's response. It carries:

- The rule it came from (so the renderer can show severity, recommendation, etc. without doing a second lookup).
- A `status`: `ok`, `weak`, or `missing`.
- The `actual_value` the server sent (or `None` if the header was missing).
- A short human-readable `note` describing what happened ("Present", "Present and contains `nosniff`", "Header `X` is not set", etc.).

Findings are also frozen. Once we evaluate a rule, the result does not change. That makes the report safe to pass around to multiple functions without worrying that one of them mutates it.

### 2.3 `ScanReport`: "the whole result"

One report wraps everything from one scan. The original URL (what the user typed), the final URL (after redirects), the HTTP status code, and the list of findings (one per rule).

The interesting part: `score` and `grade` are **computed properties**, not stored fields. They are functions decorated with `@property` that look at the findings on the fly. This means:

- We do not have to remember to recalculate them when findings change (they cannot change, the report is frozen, but the principle stands).
- A test can build a report with a synthetic set of findings and immediately ask `report.score`, no plumbing required.

### 2.4 The `Severity` and `Status` types

These are **Literal types**:

```python
Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]
```

A `Literal` type tells the type checker "this is a string, but it can only ever be one of these exact values." Why bother? Two reasons:

1. **Typo protection.** If you write `severity = "hgih"` somewhere, mypy catches it before you even run the code. Without `Literal`, the type would just be `str` and any typo would slip through.
2. **Documentation.** Just by looking at the type signature you know the legal values. You do not have to grep through the code to find out.

We could have used an `Enum` instead. Carter's style guide prefers `Literal` for small fixed sets because it keeps the values as plain strings (easy to print, easy to log, easy to use as dict keys).

## 3. Layer separation: the I/O fence

The single most important architectural decision in this project is the **fence between code that touches the network and code that does not**. Let us trace it.

```
┌─────────────────────────────────────────────────────────────────────┐
│  THE I/O LAYER                                                      │
│  - scan()                       (calls httpx.get, hits the network) │
│  - main()                       (reads sys.argv, calls scan)        │
│  - _render_report()             (writes to the terminal)            │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                │  passes a dict[str, str] or a ScanReport
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  THE PURE LAYER                                                     │
│  - evaluate_header(rule, headers) -> HeaderFinding                  │
│  - ScanReport.score property                                        │
│  - ScanReport.grade property                                        │
│  - RULES list, SEVERITY_POINTS dict                                 │
└─────────────────────────────────────────────────────────────────────┘
```

Everything in the **pure layer**:
- Takes inputs.
- Returns outputs.
- Touches no network. Touches no filesystem. Prints nothing.

Everything in the **I/O layer**:
- Talks to the outside world.
- Eventually passes its results into the pure layer.

Why this matters: the pure layer is **trivially testable**. You build inputs by hand, you check outputs. No mocking required. The I/O layer is harder to test (you have to mock the network or the terminal), but it is also the small part. Most of the bugs in a scanner are in the math, not in the call to httpx. Putting the math in a pure function means you test the math with confidence and the network code with only a few smoke tests.

This is sometimes called **functional core, imperative shell**. Coined by Gary Bernhardt. Same idea: keep the part that decides what to do pure, push the part that actually does it to the edges.

## 4. The data flow, end to end

Let us trace one scan from terminal to output. The user types:

```
$ just run -- https://github.com
```

```
1. SHELL → main()
   ─────────────────────────────────────────────────────
   `just run` calls `uv run headers https://github.com`.
   `uv run` activates the venv, runs `headers` which is
   declared in pyproject.toml as the entry point that
   maps to http_headers_scanner:main.
   sys.argv is now ["headers", "https://github.com"].

2. main() → _build_argument_parser()
   ─────────────────────────────────────────────────────
   We construct an argparse parser, add the `url` arg
   and the `--timeout` option, then call parse_args().
   Result: args.url = "https://github.com", args.timeout = 10.0

3. main() → scan(url, timeout)
   ─────────────────────────────────────────────────────
   scan() calls httpx.get() with follow_redirects=True
   and a custom User-Agent. httpx does DNS, opens a TCP
   connection, negotiates TLS, sends the GET request,
   reads the response, follows any redirects. Returns a
   Response object.

4. scan() → response_headers (a dict[str, str])
   ─────────────────────────────────────────────────────
   We convert httpx's Headers object to a plain dict.
   This is the "leave the I/O world, enter the pure
   world" handoff. Past this point, nothing knows or
   cares about httpx.

5. scan() → [evaluate_header(rule, headers) for rule in RULES]
   ─────────────────────────────────────────────────────
   A list comprehension. Run evaluate_header() once for
   each of the six rules. Each call is pure: it looks
   up the header in the dict (case-insensitive), checks
   must_match (via re.search, case-insensitive) if set,
   returns a HeaderFinding.

6. scan() → ScanReport
   ─────────────────────────────────────────────────────
   Bundle the URL, final URL, status code, and findings
   into a frozen ScanReport. scan() is done.

7. main() → _render_report(report, console)
   ─────────────────────────────────────────────────────
   The renderer builds a rich Table, adds one row per
   finding, prints it. Then builds the grade Panel,
   prints it. Then iterates over non-ok findings and
   prints their recommendations.

8. main() → exit code
   ─────────────────────────────────────────────────────
   Look at report.grade. A or B → return 0 (success).
   C or D → return 1 (warning). F or network error → 2.
   sys.exit(main()) sends the code to the shell.
```

The key thing to notice: steps 5 and 6 are pure. If you want to write a test that exercises the scoring and finding logic, you skip step 3 entirely and call `evaluate_header()` directly with hand-built inputs. That is exactly what `test_http_headers_scanner.py` does.

## 5. Why each function is the size it is

A common question for beginners: how do you know when to split a chunk of code into a new function?

A useful rule of thumb: **one job per function**. If you can describe what a function does in one sentence without "and," it is probably the right size. If you have to say "this fetches the URL AND parses the headers AND grades them AND prints the table," it is too big.

Look at our functions through that lens:

- **`evaluate_header()`**: "Apply one rule to one set of headers and return a finding." One job.
- **`scan()`**: "Fetch a URL and return a report." One job. It does also call `evaluate_header()` internally, but that is delegation, not a second job.
- **`_render_report()`**: "Pretty-print a report to the terminal." One job.
- **`_build_argument_parser()`**: "Build the argparse parser." One job. Worth splitting out so tests can call it without firing main().
- **`main()`**: "Glue the others together and pick an exit code." One job: orchestration.

The underscore prefix on `_render_report` and `_build_argument_parser` is a Python convention meaning "this is private, not part of the public API." Other code in the same file can still call them, but anyone importing the module should consider them internal.

## 6. The single source of truth: the `RULES` list

Notice that `RULES` is defined once, at the top of the file, as a list of `HeaderRule` objects. The scoring functions, the evaluation function, and the renderer all walk this list at runtime. None of them have hardcoded knowledge of which headers exist.

What this buys us: **adding a seventh header to check is a one-line change**. Append a `HeaderRule` to the list. The scanner picks it up automatically. The test suite picks it up automatically (the synthetic-report helper uses `RULES` directly). No code in `scan()`, in the rendering, in the scoring needs to change.

This is what people mean when they say "data driven" code. The behaviour is determined by data (the rules table), not by hardcoded logic per case. It is also one of the easiest patterns to recognise once you start looking for it.

The same pattern, with the same benefits, shows up in real production scanners:
- Nuclei (a vuln scanner) reads YAML templates that look a lot like our HeaderRule, just bigger.
- ESLint plugins are mostly rules tables.
- Nmap NSE scripts are individual rule files in a directory.

## 7. Why we use httpx, not requests

`requests` is the famous Python HTTP library. `httpx` is the newer one. They have very similar APIs. We picked httpx because:

- **First-class type hints.** mypy understands httpx out of the box. requests still requires `types-requests` stubs.
- **HTTP/2 support.** Newer sites speak HTTP/2 by default. requests is HTTP/1.1 only.
- **Async-ready.** httpx has a sync API (what we use) and an async API for when you grow up.
- **Active maintenance.** requests is in maintenance mode. httpx is where new development happens.

For this project we only use the sync API. The async API would let us scan many URLs in parallel, which is a great extension challenge in `04-CHALLENGES.md`.

## 8. Why we use respx for testing

When you write a test that calls `scan("https://example.com")`, you have a problem: the test now depends on example.com being reachable, fast, and returning predictable headers. None of those are guaranteed. The test would be **flaky** (sometimes pass, sometimes fail, for reasons unrelated to your code).

`respx` solves this by intercepting every httpx call inside a test and returning whatever you set up. Schematically:

```
   Test code             respx (interceptor)         The real internet
   ─────────             ───────────────────         ─────────────────
   respx.get(URL).mock(   intercepts httpx.get,
       return_value=...   never sends a packet,
   )                      hands back the fake
   scan(URL)         ───▶ Response object        ──╳  never reached
```

A test using respx is fast (no network), deterministic (the fake response is exactly what you set up), and offline-friendly. The cost is that you have to be careful: `respx` only intercepts httpx, so a scan that used `requests` under the hood would silently bypass the mock.

## 9. Error handling philosophy

Two layers of error handling.

In `scan()`, we **let errors propagate**. If DNS fails, if the host refuses the connection, if the request times out, httpx raises an exception. We do not catch it. The function's job is to fetch and grade, not to decide what to do when fetching fails.

In `main()`, we **catch `httpx.RequestError` once** and turn it into a clean message plus exit code 2. The user does not need to see a 30-line Python traceback for "could not connect." They need to see "request failed."

This is a pattern worth internalising: **the library code lets errors bubble up, the CLI code translates them into user-friendly output.** The library author does not know what context the library is being called from, so they should not pretend to know how to handle errors. The CLI author knows exactly what context the call is being made in (a user typed a command), so they can present errors appropriately.

## 10. Exit codes that mean something

Most CLIs return exit code 0 for success and 1 for any kind of failure. Our scanner uses three:

```
0 → grade A or B   (CI: green, no action needed)
1 → grade C or D   (CI: yellow, worth investigating)
2 → grade F or network error  (CI: red, must fix)
```

This is useful when you wire the scanner into CI. A pipeline can run:

```
just run -- https://my-deployed-site.com
if [ $? -gt 1 ]; then exit 1; fi   # fail the build only on F or error
```

You can decide for yourself what threshold counts as "fail the build." The point is the scanner gives you the information to decide. A binary success/failure exit code throws away too much detail.

## 11. What does NOT belong in this architecture

For a foundations project, we deliberately keep things out:

- **No async.** A single URL does not need it. The sync API is easier to read.
- **No subcommands.** No `headers scan`, `headers explain`, `headers config`. Just one job, run it.
- **No config file.** All settings come from CLI flags. No `~/.config/headers.toml`. Add one if you extend it.
- **No database.** Each run is independent. No history. Add one if you want trends over time (challenge file has details).
- **No plugin system.** The rules table is just a list. To "extend" the scanner, you edit the list.

These are all things a more mature scanner would have, and every one of them is a great extension idea. None of them belong in a project whose goal is "be the smallest possible thing that teaches the core idea."

## 12. Key files reference

A quick map of the project:

| Path | What is in it |
|------|---------------|
| `http_headers_scanner.py` | The whole scanner. Rules, evaluation, scan, CLI. |
| `test_http_headers_scanner.py` | All tests. Uses pytest and respx. |
| `pyproject.toml` | Project metadata, dependencies, tool configs (ruff, mypy, pylint, yang, pytest). |
| `uv.lock` | Exact versions of every transitive dependency. Reproducible builds. |
| `justfile` | Shortcut commands: `just test`, `just lint`, `just run`. |
| `install.sh` | One-shot installer for new clones. |
| `learn/` | The documentation you are reading. |

## Next

Move on to **[03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md)** for the line-by-line walkthrough, or jump to **[04-CHALLENGES.md](./04-CHALLENGES.md)** for extension ideas.
