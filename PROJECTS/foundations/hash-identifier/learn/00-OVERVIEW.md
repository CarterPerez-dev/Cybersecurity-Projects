# Hash Identifier

## What this is

A small Python program that looks at a string of weird-looking characters and tells you what kind of cryptographic hash it probably is. You give it something like this:

```
5f4dcc3b5aa765d61d8327deb882cf99
```

and it tells you "that's an MD5 hash" with a reason for why it thinks so.

That's the whole job. It does not crack the hash. It does not turn the hash back into a password. It just answers the question "what flavor of hash is this?" — which is the question you have to answer *first* before any other tool will help you.

## Why anyone needs this

The first thing that happens when a real attack succeeds is that the attacker walks out with a database dump full of password hashes. The hashes look like nonsense, but they are not random — every hash carries clues about how it was made. Once you know the algorithm (MD5, SHA-256, bcrypt, Argon2, whatever) you can hand the hash to a cracking tool like [hashcat](https://hashcat.net) or [John the Ripper](https://www.openwall.com/john/) and start trying to recover the original password.

But here's the thing: hashcat needs you to tell it the algorithm. It has [over 400 hash modes](https://hashcat.net/wiki/doku.php?id=example_hashes), each with a different number. Mode 0 is MD5. Mode 100 is SHA-1. Mode 3200 is bcrypt. If you pick the wrong mode, hashcat will sit there forever and find nothing. So before cracking, you identify. That's this tool.

**Real-world moments where you'd reach for this:**

- A pentester finds a dump file on a compromised server full of strings like `$2b$12$EixZaYVK1...` and needs to know what to feed hashcat.
- A CTF challenge hands you a hash and zero hints about what algorithm made it.
- You're reading a breach writeup and want to understand whether the leaked passwords were stored as fast unsalted MD5 (a disaster) or slow salted bcrypt (much better).
- The [2012 LinkedIn breach](https://en.wikipedia.org/wiki/2012_LinkedIn_hack) leaked 6.5 million unsalted SHA-1 hashes. The first thing any researcher had to do before doing *anything* was confirm "yes, these are SHA-1." Forty-character hex strings. Easy. The tool you're about to read would have told them that in milliseconds.

## What you will learn

**Security ideas:**

- What a cryptographic hash actually is (a function that turns any input into a fixed-length jumble that you can't reverse).
- The three signals every hash leaks about itself: its **prefix**, its **length**, and its **character set**.
- Why modern password hashes (`$2b$...`, `$argon2id$...`) *announce themselves* on purpose, and why old fast hashes (MD5, SHA-1) don't.
- The difference between a fast hash (made for speed, terrible for passwords) and a slow hash (made on purpose to resist cracking).
- Why you can never recover the password from a hash, only *guess* the password and check if its hash matches.

**Python ideas (assuming this is your first time):**

- How to read a Python file from top to bottom and understand what it's doing.
- What `import` does and where the standard library ends and third-party packages begin.
- Functions, type hints (`str`, `int`, `list[str]`), and what `-> bool` means after a function signature.
- `@dataclass` — a shortcut for making little record-like objects.
- `frozenset`, `dict`, `list`, `tuple` — the core Python containers and when to pick which.
- How a command-line tool actually starts running (the `if __name__ == "__main__"` line at the bottom).
- How a test file works and why every function in the main code has tests next to it.

**Tools you'll touch:**

- [`uv`](https://github.com/astral-sh/uv) — the modern Python package manager. Like `pip` but ~100× faster.
- [`just`](https://github.com/casey/just) — a command runner. Instead of memorizing long commands, you type `just test` or `just run`.
- [`rich`](https://github.com/Textualize/rich) — the library that prints the pretty colored table at the end.
- [`pytest`](https://pytest.org) — Python's test runner.
- [`ruff`](https://github.com/astral-sh/ruff) + [`mypy`](https://mypy-lang.org) + [`pylint`](https://pylint.org) — the linters that yell at you if your code is wrong, slow, or sloppy.

## What you need before starting

**Knowledge you should have:**

- You've used a terminal at least once (you know what `cd` and `ls` do).
- You vaguely know that "a hash" is a one-way function. If not, [01-CONCEPTS.md](./01-CONCEPTS.md) will get you there in 10 minutes.
- You can read code, or at least you're willing to. We will explain every Python feature as we hit it.

**Knowledge you do NOT need:**

- Any prior Python experience. The whole point of the **foundations** tier is that you start here.
- Any prior cybersecurity experience.
- Any math beyond "counting." There is no math in this project. Cryptography uses math under the hood, but identifying a hash by its shape doesn't.

**Software you need installed:**

- Python 3.13 or newer.
- The `uv` tool (the install script will get this for you if you don't have it).
- The `just` tool (also handled by the install script).
- A terminal. Any terminal. On Mac it's Terminal.app or iTerm2; on Linux it's whatever your distro shipped; on Windows it's WSL2 + Ubuntu (we strongly recommend WSL2 instead of native Windows).

You do *not* need an IDE — a text editor is fine. We recommend [VS Code](https://code.visualstudio.com) with the Python extension, but `nano`, `vim`, `helix`, or whatever you already use will work.

## Quick start

From inside `PROJECTS/foundations/hash-identifier/`:

```bash
./install.sh
```

That script will install `uv` and `just` if missing, create a virtual environment (an isolated Python sandbox just for this project), install all the dependencies, and verify the tests pass. It prints what it's doing as it goes — read the output, don't just close the terminal.

Then try the tool:

```bash
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
```

You should see a colored table identifying that string as MD5 (with NTLM, MD4, and RIPEMD-128 as less-likely alternatives — all four produce 32 hex characters, so length alone can't separate them).

Try a few more:

```bash
# bcrypt — modern password hash, announces itself with the $2b$ prefix
just run -- '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'

# SHA-256 — 64 hex characters
just run -- e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# A JWT (this is NOT a hash, but the tool will say so politely)
just run -- eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

# Total garbage — the tool will say "no idea" rather than guess
just run -- helloworld
```

**Note on quoting:** when a hash starts with `$`, you must wrap it in single quotes (`'$2b$...'`). Without quotes, your shell will try to expand `$2` as a shell variable and chop the hash up. This is a shell thing, not a Python thing — every Unix shell does it.

## Project layout

```
hash-identifier/
├── hash_identifier.py        the whole tool — one file, ~680 lines
├── test_hash_identifier.py   tests for every behavior the tool claims to have
├── install.sh                one-shot setup script
├── justfile                  shortcuts for run / test / lint / format
├── pyproject.toml            project config: dependencies, linter rules, etc.
├── README.md                 short pointer to this learn/ folder
├── learn/                    you are here
│   ├── 00-OVERVIEW.md        quick start (this file)
│   ├── 01-CONCEPTS.md        what hashes are and how identification works
│   ├── 02-ARCHITECTURE.md    how the code is structured, with diagrams
│   ├── 03-IMPLEMENTATION.md  line-by-line walkthrough of the code
│   └── 04-CHALLENGES.md      extension ideas if you want to go further
└── assets/                   images, screenshots
```

One file of code is on purpose. The foundations tier is meant to be readable in one sitting. The intermediate and advanced tiers split into many files; foundations does not.

## Where to go next

1. **[01-CONCEPTS.md](./01-CONCEPTS.md)** — understand *what* a hash is, *why* identification is the first move, and *how* prefix/length/charset clues actually work. Read this even if you think you know it; the framing matters.
2. **[02-ARCHITECTURE.md](./02-ARCHITECTURE.md)** — see the six-step pipeline the tool uses to make a decision, drawn out as a flow diagram.
3. **[03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md)** — read `hash_identifier.py` with us, line by line. Every Python feature gets explained when it first appears.
4. **[04-CHALLENGES.md](./04-CHALLENGES.md)** — extensions you can try on your own once you've absorbed the rest.

## Common problems

**"command not found: just"**
The install script should set this up, but if it didn't: `curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash`. Then close and reopen your terminal so it sees the new tool.

**"command not found: uv"**
Same idea: `curl -LsSf https://astral.sh/uv/install.sh | sh`, then reopen your terminal.

**`just run -- $2b$12$...` chops the hash up**
You forgot the single quotes around the hash. Re-run with `just run -- '$2b$12$...'`.

**"ModuleNotFoundError: No module named 'rich'"**
You ran `python hash_identifier.py` directly instead of `just run`. The `just run` recipe uses the virtual environment that has `rich` installed. Either use `just run`, or activate the venv first: `source .venv/bin/activate`, *then* `python hash_identifier.py <hash>`.

**Tests fail right after install**
Tests should pass on a fresh `./install.sh`. If they don't, you probably have an older Python (run `python --version`; you need 3.13+). On Ubuntu, install it via [`deadsnakes`](https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa); on Mac use [Homebrew](https://brew.sh).
