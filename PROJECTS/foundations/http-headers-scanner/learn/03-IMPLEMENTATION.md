# Implementation Walkthrough

This file walks through the actual code in `http_headers_scanner.py` (and a bit of `test_http_headers_scanner.py`) line by line. By the end you should understand every piece of the file: what it does, why it is there, and what would break if you removed it.

This is the longest file in the learn folder. Take it in chunks. The order below matches the order things appear in the source.

## 0. Reading conventions

Each section names a function, class, or constant from `http_headers_scanner.py`. Open the file in your editor on the side and search for the name. The code excerpts in this guide are real, copied directly from the file, but the file is also short enough that you can scroll the whole thing in a couple of pages.

## 1. The file docstring

The file starts with a long triple-quoted string. In Python, a string at the very top of a file is called the **module docstring**. It is the official place to explain what the file is about.

```python
"""
©AngelaMos | 2026
http_headers_scanner.py

Scan a URL and grade its HTTP security headers A–F

When a browser asks a website for a page, the server sends back the
page itself PLUS a bunch of metadata called "HTTP response headers."
...
"""
```

A few things to notice:

- **The first three lines are the project's standard file header.** Every file in the project starts this way: a copyright line, a blank-ish line, the filename. The `©AngelaMos | 2026` part is the project's branding, not something you would normally see in a generic Python tutorial.
- **The body is unusually long for a docstring.** Most files have a one-line summary. This one is detailed because it is a teaching project. The docstring is the first thing any reader sees (`help(http_headers_scanner)` prints it, IDEs show it on hover), so we use it to teach.
- **It ends with a list of "what this file exposes."** This is a real convention. Tells readers what they can import from the module without scrolling through 600 lines.

## 2. Imports

```python
import argparse
import re
import sys
from dataclasses import dataclass
from typing import Literal

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
```

PEP 8 (Python's style guide) wants imports grouped into three sections separated by blank lines:

1. **Standard library**: things that ship with Python. Here: `argparse`, `re`, `sys`, `dataclasses`, `typing`.
2. **Third-party**: things you installed with `uv` / `pip`. Here: `httpx`, `rich`.
3. **Local**: things from this same project. We have none.

`re` is the standard library's regular-expression module. We use `re.search(pattern, value, re.IGNORECASE)` inside `evaluate_header()` to check whether a header's value matches a rule's required pattern. Regexes give us a way to express "max-age must be a positive integer" in one line, instead of having to parse the HSTS directive structure ourselves.

Each module is imported with a tight inline comment explaining what we use it for. Beginners often ask "what does `import` even do?" Short answer: it tells Python "go find this module and make its names available in this file." `import argparse` makes `argparse.ArgumentParser` available. `from dataclasses import dataclass` makes the bare name `dataclass` available so we can use `@dataclass` directly without writing `@dataclasses.dataclass`.

## 3. The Severity and Status types

```python
Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]
```

These are **type aliases**. They give a friendly name to a more complex type. Anywhere you write `Severity` from now on, the type checker reads `Literal["high", "medium", "low"]`.

The reason `Literal` exists: a regular `str` means "any string." If we annotated `severity: str`, then `severity = "hgih"` would compile fine and only blow up at runtime when something tried to look it up. With `severity: Severity`, mypy refuses to let `"hgih"` near the field. The typo is caught at edit time.

This is more discipline than most beginner Python you will see online. It is a deliberate choice for a teaching project: we want you to absorb the habit early.

## 4. `HeaderRule` dataclass

```python
@dataclass(frozen=True, slots=True)
class HeaderRule:
    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None
```

A dataclass is a regular class that has the boring parts (constructor, equality, string repr) written for you by the `@dataclass` decorator. We covered the `frozen` and `slots` flags in `02-ARCHITECTURE.md`. The short version: `frozen` prevents anyone from modifying the fields after construction, `slots` makes the instances smaller in memory.

The fields:

- **`header`**: the HTTP header name we are looking for. Stored with canonical casing (e.g. `"Strict-Transport-Security"`) but compared case-insensitively at lookup time.
- **`severity`**: drives the score. `"high"` = 30 points, `"medium"` = 15, `"low"` = 5.
- **`description`**: one sentence explaining the header. Currently used for documentation; we could also render it in the table.
- **`recommendation`**: what to add to fix a missing or weak header. Shown in the "Recommendations" section at the bottom of the output.
- **`must_match`**: optional. A regex pattern the value must match (case-insensitive) to be considered `ok`. For HSTS the pattern is `r"max-age\s*=\s*[1-9]"` (rejects `max-age=0`); for `X-Content-Type-Options` it is `"nosniff"` (a plain word works as a substring match under `re.search`). If `None`, presence alone is enough.

The trailing `= None` on `must_match` is its **default value**. Means you can construct a `HeaderRule` without specifying it. Only fields with defaults can be omitted at construction time.

## 5. The `RULES` table

```python
RULES: list[HeaderRule] = [
    HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        ...
        must_match=r"max-age\s*=\s*[1-9]",
    ),
    HeaderRule(
        header="Content-Security-Policy",
        severity="high",
        ...
    ),
    ...
]
```

This is the **single source of truth** for which headers we check. The list-of-dataclasses pattern is one of the most useful in Python: each entry is structured, immutable, and easy to add to.

A pattern detail: we use **keyword arguments** for every field, not positional. We write `HeaderRule(header="...", severity="...", ...)`, not `HeaderRule("...", "...", ...)`. Why? Two reasons:

1. **Readability.** When someone reads the code, they see `severity="high"` and know exactly what the second value means. Positional `("Strict-Transport-Security", "high", ...)` makes them count fields.
2. **Refactor safety.** If you add a new field later (say `references: list[str]`), positional calls might land the new value in the wrong place. Keyword calls are unambiguous.

Why is this list at module level, not inside a function? Because it never changes. Building it once at import time is cheaper than rebuilding it on every scan. It is also accessible to the test suite (`from http_headers_scanner import RULES`).

## 6. `SEVERITY_POINTS` mapping

```python
SEVERITY_POINTS: dict[Severity, int] = {
    "high": 30,
    "medium": 15,
    "low": 5,
}
```

A dictionary mapping each severity to its point value. Notice the type annotation: `dict[Severity, int]`. That tells the type checker "keys must be `"high"` / `"medium"` / `"low"`, values must be ints." If you tried to add `"critical": 50` to this dict, mypy would refuse: `"critical"` is not in the `Severity` Literal type.

Why a dict and not a function with three if statements? Because it is data, not logic. Data driven code is easier to extend (add another severity, edit one line) and easier to test (you can assert the exact point values).

## 7. `HeaderFinding` dataclass

```python
@dataclass(frozen=True, slots=True)
class HeaderFinding:
    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str
```

A finding is the result of evaluating one rule against one response. It carries:

- **`rule`**: the rule that was evaluated. Storing the whole rule inside the finding (rather than just its name) means the renderer never has to do a second lookup to know the severity or recommendation.
- **`status`**: one of `"ok"`, `"weak"`, `"missing"`. The Literal type catches typos.
- **`actual_value`**: whatever the server actually sent. `None` if the header was missing.
- **`note`**: a short human-friendly string. Shown in the table.

Why is `actual_value` typed `str | None`? Because the field is genuinely sometimes a string and sometimes nothing. `None` is Python's way of saying "no value." The type `str | None` makes that explicit. Anywhere you use `finding.actual_value`, the type checker forces you to either handle the None case or assert that it cannot be None.

The `|` syntax (e.g. `str | None`) is the modern way (Python 3.10+). The older way was `Optional[str]` from the `typing` module. Both work; the new syntax is shorter.

## 8. `ScanReport` dataclass with computed properties

```python
@dataclass(frozen=True, slots=True)
class ScanReport:
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]

    @property
    def score(self) -> int:
        ...

    @property
    def grade(self) -> str:
        ...
```

A report has four stored fields plus two computed properties.

### 8.1 Why `final_url` is separate from `url`

`url` is what the user typed. `final_url` is where they ended up after redirects. They are often the same. They are different when, say, `http://example.com/` redirects to `https://example.com/`. We track both because:

- The user wants to see the URL they typed acknowledged in the output.
- The grade really belongs to the final URL (the redirected destination is what their browser actually shows).

### 8.2 The `score` property

```python
@property
def score(self) -> int:
    total = sum(SEVERITY_POINTS[r.severity] for r in RULES)
    if total == 0:
        return 0

    earned = 0.0
    for finding in self.findings:
        full = SEVERITY_POINTS[finding.rule.severity]
        if finding.status == "ok":
            earned += full
        elif finding.status == "weak":
            earned += full / 2

    return int((earned / total) * 100 + 0.5)
```

Step by step:

1. **`@property`** on the line above turns the method into something you access without parentheses. `report.score`, not `report.score()`. Looks like a field, computed on demand.
2. **`total = sum(SEVERITY_POINTS[r.severity] for r in RULES)`** computes the total achievable points by walking the rules. The expression inside `sum(...)` is a **generator expression**: it produces one number per rule (the point value for that rule's severity), then sum adds them up. With the current 2-high, 2-medium, 2-low rules, total = 100.
3. **`if total == 0: return 0`** is a guard. If somebody deleted the rules table at runtime, we would otherwise divide by zero. Returning zero is a safe answer.
4. **The main loop** walks every finding. For each one, look up the full point value for its rule's severity. If status is `ok`, add the full points. If `weak`, add half. If `missing`, add nothing (no explicit branch; the variable is unchanged).
5. **`int((earned / total) * 100 + 0.5)`** is the final score. The `+ 0.5` then `int(...)` is a manual round-half-up. We use it because Python's built-in `round()` uses banker's rounding (round half to even), which would map `round(0.5)` to `0` and `round(2.5)` to `2`. Mathematically defensible (it cancels out bias over a large sample) but surprising at the `.5` boundary, where a score should always round up. `int(x + 0.5)` is the form everyone expects.

### 8.3 The `grade` property

```python
@property
def grade(self) -> str:
    score = self.score
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"
```

Notice that each branch `return`s directly, so there are no `elif`s and no final `else`. This is a common idiom called **early return**. The function reads top to bottom: as soon as a condition matches, you are done. It also avoids "arrow code" where each branch is more indented than the last.

Notice also that **we call `self.score` once**, store the result, then compare it five times. If we wrote `if self.score >= 90:` etc., the property would re-run each time. For a tiny score function it would not matter, but the habit of caching repeated expensive lookups is worth forming early.

## 9. `evaluate_header()`: the heart of the scanner

This is the **pure function** at the core of everything. No network. No prints. Just rule plus headers in, finding out.

```python
def evaluate_header(
    rule: HeaderRule,
    response_headers: dict[str, str],
) -> HeaderFinding:
    target = rule.header.lower()

    actual_value: str | None = None
    for name, value in response_headers.items():
        if name.lower() == target:
            actual_value = value
            break

    if actual_value is None:
        return HeaderFinding(
            rule=rule,
            status="missing",
            actual_value=None,
            note=f"Header `{rule.header}` is not set",
        )

    if rule.must_match is None:
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note="Present",
        )

    if re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note=f"Present and matches `{rule.must_match}`",
        )

    return HeaderFinding(
        rule=rule,
        status="weak",
        actual_value=actual_value,
        note=(
            f"Present but does not match `{rule.must_match}` "
            f"(got `{actual_value}`)"
        ),
    )
```

Three branches, in order:

1. **Missing.** We loop over the response headers, lowercase each name, compare against the lowercased target. If we never find a match, `actual_value` stays `None`, and we return a `missing` finding.
2. **Present, no must_match check.** If the rule does not require a specific pattern, presence alone is enough. Return `ok`.
3. **Present, must_match check.** If the rule has a `must_match`, run `re.search(pattern, value, re.IGNORECASE)`. A plain word like `"nosniff"` works as a substring check; a richer pattern like `r"max-age\s*=\s*[1-9]"` enforces a real condition (HSTS must be set to a positive integer, not the actively-harmful `max-age=0`). If the pattern matches, `ok`. If not, `weak`.

A few things worth pointing out:

**The case-insensitive lookup.** HTTP header names are case insensitive per RFC 7230. Different servers return them with different casings. Some return `Strict-Transport-Security`, some `strict-transport-security`, some even `STRICT-TRANSPORT-SECURITY` (rare but legal). Lowercasing both sides is the simplest portable way to handle this.

We could have used a case-insensitive dict (httpx returns one), but the function should accept a plain dict for testing purposes. In practice `scan()` already converts the response headers to a plain `dict[str, str]` before calling `evaluate_header`, so this function never sees an `httpx.Headers` object directly — but the contract is "any `dict[str, str]` works," which is what makes hand-built test inputs trivial.

**Why we `break` out of the loop early.** Once we found the header, we have what we need. Continuing the loop would waste CPU.

**The f-strings in `note`.** An f-string is a string with `{expression}` placeholders that get filled in at runtime. `f"Header `{rule.header}` is not set"` becomes `Header `Strict-Transport-Security` is not set` if the rule's header is HSTS. The backticks around the header name make it look monospaced if the renderer happens to be markdown-aware, and it generally helps the eye.

**No else branches.** Each branch returns. Once you return, the function is done. No need to write `elif` or `else`. This is the same early-return pattern from the `grade` property.

## 10. `scan()`: the network call

```python
DEFAULT_USER_AGENT: str = (
    "http-headers-scanner/1.0 "
    "(+https://github.com/CarterPerez-dev/Cybersecurity-Projects)"
)


def scan(
    url: str,
    *,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ScanReport:
    response = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": user_agent},
    )

    response_headers = dict(response.headers)
    findings = [evaluate_header(rule, response_headers) for rule in RULES]

    return ScanReport(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=findings,
    )
```

### 10.1 The User-Agent

The User-Agent string identifies who is making the request. Browsers send things like `Mozilla/5.0 (X11; Linux x86_64) ...`. Our scanner sends `http-headers-scanner/1.0 (+https://...)`. This is polite for two reasons:

- Server operators reading their access logs can tell who is hitting them and check our project page if they wonder why.
- Some sites block the default httpx UA. A custom UA is more likely to get a real response.

### 10.2 The `*,` in the signature

```python
def scan(
    url: str,
    *,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ScanReport:
```

The `*,` between `url` and `timeout` forces callers to pass `timeout` and `user_agent` by keyword. You cannot call `scan("https://example.com", 5.0)`. You have to call `scan("https://example.com", timeout=5.0)`.

Why force that? Because `5.0` does not obviously mean "five seconds of timeout" when you read the call site. `timeout=5.0` does. Keyword-only arguments make call sites more readable and refactor-safe. The cost is exactly one extra character (`timeout=`) when calling the function.

### 10.3 `follow_redirects=True`

When the server says "this URL has moved, try this other one," we follow the redirect automatically. Many sites redirect `http://` to `https://` or `www.` to bare domain. The user typed one URL but their browser would end up on a different one. We want to grade the one their browser would actually see.

### 10.4 The handoff to the pure layer

```python
response_headers = dict(response.headers)
findings = [evaluate_header(rule, response_headers) for rule in RULES]
```

These two lines are the "leave I/O world, enter pure world" handoff we talked about in the architecture file. `dict(response.headers)` converts the httpx Headers object into a plain dict. The list comprehension on the next line runs `evaluate_header()` for each rule.

A **list comprehension** is shorthand for "make a list by running an expression over each item in a source." The equivalent for-loop would be:

```python
findings = []
for rule in RULES:
    findings.append(evaluate_header(rule, response_headers))
```

Same result, more lines. The comprehension is preferred when the body is one expression.

## 11. Rendering

```python
STATUS_COLORS: dict[Status, str] = {
    "ok": "green",
    "weak": "yellow",
    "missing": "red",
}

GRADE_COLORS: dict[str, str] = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}


def _render_report(report: ScanReport, console: Console) -> None:
    table = Table(...)
    table.add_column(...)
    ...
    for finding in report.findings:
        status_color = STATUS_COLORS[finding.status]
        table.add_row(...)
    console.print(table)

    if report.final_url.startswith("http://"):
        console.print(
            "[yellow]Note:[/yellow] this response was served over plain "
            "HTTP. Browsers IGNORE HSTS over HTTP, ..."
        )

    grade_color = GRADE_COLORS[report.grade]
    panel = Panel(...)
    console.print(panel)

    actionable = [f for f in report.findings if f.status != "ok"]
    if actionable:
        console.print("\n[bold]Recommendations:[/bold]")
        for finding in actionable:
            console.print(...)
```

The renderer uses **rich**, a third-party library for pretty terminal output. The patterns:

- **A `Table` object** with columns. You add rows one at a time. `console.print(table)` draws it as a Unicode-bordered table.
- **`[green]something[/green]`** is rich's markup syntax. It is roughly like HTML for terminal colors. `[bold cyan]Result[/bold cyan]` would render "Result" in bold cyan.
- **`Panel(...)`** wraps content in a bordered box.

The renderer is intentionally separate from `scan()` and `evaluate_header()`. The pure code does not know or care about colors. If we ever want a JSON output mode for CI, we add a second renderer (`_render_json(report)`) and keep all the other code unchanged.

The `actionable = [f for f in report.findings if f.status != "ok"]` line is another comprehension: build a list of every finding whose status is not `ok`. These are the ones we have recommendations for. If the list is empty (perfect score), we skip the section entirely.

**The HTTP warning.** Right after the table, we check `report.final_url.startswith("http://")`. Per RFC 6797 §8.1, browsers MUST IGNORE the `Strict-Transport-Security` header when it arrives over plain HTTP — only HSTS received over HTTPS counts. So if a user points the scanner at `http://example.com` and the server returns HSTS, that HSTS earns full credit in our grading even though no real browser would honor it. The yellow note makes the caveat visible at the only place that matters: the user-facing report. We do not change the grading logic — one rule, one outcome — but the user sees an honest "this grade is misleading until the site enforces HTTPS" line right next to the score.

## 12. The argparse plumbing

```python
def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headers",
        description="Scan a URL for HTTP security headers and grade the result A–F.",
    )
    parser.add_argument(
        "url",
        help="Full URL to scan (must include http:// or https://).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds to wait before giving up on the request (default: 10).",
    )
    return parser
```

**argparse** is the standard library's command-line argument parser. You declare what your program accepts, argparse handles the rest: parsing, type conversion, generating `--help` output, rejecting bad input.

Two arguments declared:

- **`url`**: positional (no `--` prefix). Required. If the user does not provide it, argparse errors out and prints the usage automatically.
- **`--timeout`**: optional. Defaults to `10.0`. `type=float` tells argparse to convert the string `"5"` into the float `5.0`.

The function is intentionally separate from `main()` so tests can build the parser and call `parse_args([...])` on a synthetic list, without having to mess with `sys.argv`.

## 13. `main()`: orchestration

```python
def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    try:
        report = scan(args.url, timeout=args.timeout)
    except httpx.RequestError as exc:
        console.print(f"[red]Request failed:[/red] {type(exc).__name__}: {exc}")
        return 2

    _render_report(report, console)

    if report.grade in ("A", "B"):
        return 0
    if report.grade in ("C", "D"):
        return 1
    return 2
```

This function is small on purpose. Its job is to be the glue. Steps:

1. Build the argparse parser. `parse_args()` with no argument reads `sys.argv` implicitly.
2. Create a `Console` (rich's main object for printing).
3. Try to scan. If `httpx.RequestError` (the parent of every network-related error) is raised, print a clean message and return exit code 2.
4. Render the report.
5. Pick an exit code based on the grade.

The `try / except` here is the **only** place we catch network errors. We let them propagate from `httpx.get()` up through `scan()` up to `main()`. The reason: lower-level functions cannot know what to do with errors. The CLI knows what to do (show the user, exit). The CLI is the right layer to catch.

`type(exc).__name__` is "the name of the exception's class as a string." For a connection timeout it would be `ConnectTimeout`. For DNS failure, `ConnectError`. Including this in the output gives the user a clue about what went wrong without dumping a full traceback.

## 14. The script entrypoint

```python
if __name__ == "__main__":
    sys.exit(main())
```

This pattern shows up in every Python script. It means "if this file was invoked directly (not imported as a module), run main."

When you `python http_headers_scanner.py`, Python sets a special variable `__name__` to `"__main__"`. When some other code does `import http_headers_scanner`, `__name__` is set to `"http_headers_scanner"` instead.

So `if __name__ == "__main__":` is "only when running as a script, not when being imported." Tests import the file, so they need `main()` to NOT run automatically.

`sys.exit(main())` calls main, then passes its return value (0, 1, or 2) to the operating system as the exit code.

## 15. The test file walkthrough

The tests live in `test_http_headers_scanner.py`. We will not go through every line, but here are the key patterns.

### 15.1 Fixtures

```python
@pytest.fixture
def hsts_rule() -> HeaderRule:
    return HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        ...
        must_match=r"max-age\s*=\s*[1-9]",
    )
```

A **fixture** is pytest's way of saying "before this test runs, set up this thing for it." Any test function that has a parameter named `hsts_rule` will receive whatever this fixture returns. Pytest matches by name.

We use fixtures so the rule is constructed in one place. If the `HeaderRule` shape changes (new field added), we update the fixture, not five different tests.

### 15.2 The pure-function tests

```python
def test_evaluate_header_present_with_required_substring(
    hsts_rule: HeaderRule,
) -> None:
    headers = {"Strict-Transport-Security": "max-age=31536000"}
    finding = evaluate_header(hsts_rule, headers)
    assert finding.status == "ok"
    assert finding.actual_value == "max-age=31536000"
```

Each test follows the **arrange-act-assert** pattern:

1. **Arrange.** Build the input. Here: a tiny dict of headers.
2. **Act.** Call the function under test.
3. **Assert.** Check the result is what we expected.

`assert` is Python's "this must be true or fail the test." If `finding.status != "ok"`, pytest raises an AssertionError and prints what the actual value was.

Because `evaluate_header` is pure, these tests are dead simple. No mocking, no setup beyond the fixture, no teardown.

### 15.3 The score and grade tests

The `_make_report` helper builds a synthetic `ScanReport` by pairing each rule with a status. Then the test asks `report.score` and `report.grade` and asserts they are what we expected.

This is the payoff for making `score` and `grade` properties of `ScanReport`: we can test them without running `scan()`. We just hand-build the inputs.

### 15.4 The respx-mocked scan tests

```python
@respx.mock
def test_scan_mocks_a_clean_response_and_grades_it_correctly() -> None:
    respx.get("https://safe.example.com/").mock(
        return_value=httpx.Response(
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                ...
            },
        )
    )

    report = scan("https://safe.example.com/")

    assert report.status_code == 200
    assert report.score == 100
```

The `@respx.mock` decorator above the function tells respx: "during this test, intercept every httpx call and use the routes I set up below."

`respx.get("https://safe.example.com/").mock(return_value=httpx.Response(...))` says "when something does an HTTP GET to that URL, hand back this canned response, do not actually go to the internet."

Then `scan("https://safe.example.com/")` does its thing. httpx tries to fetch the URL; respx intercepts; the fake response comes back; the rest of the code never knows the difference. We assert on the score.

The redirect test (`test_scan_records_final_url_after_redirect`) sets up two mocked routes: the first returns a 301 to the second, the second returns 200. The scanner follows the redirect, and we assert that `report.final_url` reflects where we ended up.

## 16. Tooling: lint, type-check, format

The project ships with four quality tools wired up through `just`:

```
just lint    # runs ruff, then pylint, then mypy
just format  # runs yang in place
just test    # runs pytest
just fix     # runs ruff with --fix (auto-fixes what it can)
```

What each tool does:

- **ruff** is a fast Python linter. Catches a long list of style and correctness issues. Modern replacement for flake8.
- **pylint** is a slower, more opinionated linter. Catches different issues than ruff. We run both because their checks complement each other.
- **mypy** is the static type checker. It reads the type annotations and checks every call against them. Catches `severity = "hgih"` typos and many other bugs at edit time.
- **yang** is the code formatter, a maintained fork of Google's yapf. It rewrites the file to match a configured style (column limit, indentation, etc.). Means the project has a single consistent look regardless of who wrote each line.
- **pytest** is the test runner. Discovers files starting with `test_`, runs every function in them whose name starts with `test_`, reports passes and failures.

In a real workflow you would set up a **pre-commit hook** that runs `just lint` and `just test` before each commit, so broken code never gets committed. We have not done that in this project to keep the foundations tier minimal, but extending it is one of the challenges.

## 17. The pyproject.toml

`pyproject.toml` is the modern Python project metadata file. It replaces the old `setup.py` + `setup.cfg` combo. Worth glancing at, even though you do not usually edit it day to day.

Key sections:

- **`[project]`**: name, version, description, Python version requirement, dependencies.
- **`[project.optional-dependencies]`**: dev dependencies (pytest, mypy, etc.) that end users do not need.
- **`[project.scripts]`**: declares the `headers` command-line script. This is why `uv run headers` works: it knows to invoke `http_headers_scanner:main`.
- **`[tool.ruff]`, `[tool.mypy]`, `[tool.pylint.*]`, `[tool.pytest.ini_options]`**: config for each tool. Centralising config in one file is convenient.

## 18. Common pitfalls when extending

A few things that have tripped people up when adding new rules or features:

**Forgetting to bump the score total in tests.** Currently `RULES` is six rules totalling 100 points. If you add a seventh, the score calculation still works (it sums whatever is in the list), but tests that hardcoded the expected score (e.g. "score should be 50 when half are missing") may break. Fix: write tests in terms of percentages, not absolute point counts.

**Adding a rule whose value parsing is non-trivial.** Our `must_match` field is a single regex. That's plenty for "starts with `nosniff`" or "max-age is a positive integer," but some real headers need much more complex parsing (CSP, for instance, has its own grammar of directives, source expressions, and nonces). If your new rule needs structured parsing, do the parsing in `evaluate_header()` based on the rule's header name, or extend `HeaderRule` with a new field like `value_validator: Callable[[str], bool] | None`.

**Forgetting the case-insensitive comparison.** New code that does `if "X-Frame-Options" in response.headers` will miss servers that return `x-frame-options`. Always lowercase both sides for header name comparison.

**Trying to scan multiple URLs without async.** The sync API blocks one URL at a time. Scanning 100 URLs in sequence is slow. If you want concurrency, switch to `httpx.AsyncClient` and use `asyncio.gather`. The challenges file has a sketch of this.

## 19. Debugging tips

When something goes wrong:

**Run with `-v` for pytest verbose output.**
```
uv run pytest -v
```
Shows you each test name as it runs. Easier to spot which one failed.

**Use the `--pdb` flag for an interactive debugger.**
```
uv run pytest --pdb
```
Drops into Python's debugger on the first failing test. Type `l` for the source around the failure, `p variable_name` to inspect, `c` to continue.

**Print the actual headers when the scanner gives wrong results.**
Edit `scan()` to print `response_headers` before the loop. Run the scanner against a known site. Compare what you see to what your browser's dev tools say. Different User-Agents sometimes get different responses.

**Use `curl -I` as a sanity check.**
```
curl -I https://example.com
```
The `-I` flag fetches only headers. If the headers you see there do not match what the scanner reports, something is up with the request the scanner is making.

## 20. Next

Read **[04-CHALLENGES.md](./04-CHALLENGES.md)** for ideas to extend the scanner. Pick one that interests you, try it, and see how the architecture holds up when you push on it.
