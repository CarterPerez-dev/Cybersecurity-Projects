<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

```json
RRRRRRRRRRRRRRRRR   VVVVVVVV           VVVVVVVVEEEEEEEEEEEEEEEEEEEEEENNNNNNNN        NNNNNNNN        GGGGGGGGGGGGG
R::::::::::::::::R  V::::::V           V::::::VE::::::::::::::::::::EN:::::::N       N::::::N     GGG::::::::::::G
R::::::RRRRRR:::::R V::::::V           V::::::VE::::::::::::::::::::EN::::::::N      N::::::N   GG:::::::::::::::G
RR:::::R     R:::::RV::::::V           V::::::VEE::::::EEEEEEEEE::::EN:::::::::N     N::::::N  G:::::GGGGGGGG::::G
  R::::R     R:::::R V:::::V           V:::::V   E:::::E       EEEEEEN::::::::::N    N::::::N G:::::G       GGGGGG
  R::::R     R:::::R  V:::::V         V:::::V    E:::::E             N:::::::::::N   N::::::NG:::::G
  R::::RRRRRR:::::R    V:::::V       V:::::V     E::::::EEEEEEEEEE   N:::::::N::::N  N::::::NG:::::G
  R:::::::::::::RR      V:::::V     V:::::V      E:::::::::::::::E   N::::::N N::::N N::::::NG:::::G    GGGGGGGGGG
  R::::RRRRRR:::::R      V:::::V   V:::::V       E:::::::::::::::E   N::::::N  N::::N:::::::NG:::::G    G::::::::G
  R::::R     R:::::R      V:::::V V:::::V        E::::::EEEEEEEEEE   N::::::N   N:::::::::::NG:::::G    GGGGG::::G
  R::::R     R:::::R       V:::::V:::::V         E:::::E             N::::::N    N::::::::::NG:::::G        G::::G
  R::::R     R:::::R        V:::::::::V          E:::::E       EEEEEEN::::::N     N:::::::::N G:::::G       G::::G
RR:::::R     R:::::R         V:::::::V         EE::::::EEEEEEEE:::::EN::::::N      N::::::::N  G:::::GGGGGGGG::::G
R::::::R     R:::::R          V:::::V          E::::::::::::::::::::EN::::::N       N:::::::N   GG:::::::::::::::G
R::::::R     R:::::R           V:::V           E::::::::::::::::::::EN::::::N        N::::::N     GGG::::::GGG:::G
RRRRRRRR     RRRRRRR            VVV            EEEEEEEEEEEEEEEEEEEEEENNNNNNNN         NNNNNNN        GGGGGG   GGGG
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2337-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/rveng)
[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![capstone](https://img.shields.io/badge/disassembler-capstone-6d4aff?style=flat)](https://www.capstone-engine.org)
[![No execution](https://img.shields.io/badge/binaries-never%20executed-2ea043?style=flat)](#it-never-runs-a-binary)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> An interactive reverse-engineering learning platform. It hands you a real compiled binary, asks a concrete question about it, gives you an in-browser hex viewer, disassembler, section map, and string scanner to answer it, and grades your answer. Only when you are right does it reveal the original C source, so you connect the machine code you just read back to the code that produced it. One framework-free Python analysis engine wears three faces: a web app, a read-only HTTP API, and an embeddable library.

## Why a reverse-engineering platform

A pile of worksheets and pre-compiled binaries can walk you through reverse engineering, but it cannot check your work and it cannot become anything more. rveng keeps the solve-then-reveal loop and makes it a real system. The engine that parses ELF, drives the disassembler, resolves imports, and grades answers is the core. The web app turns the worksheet into an interactive lab: an in-browser hex viewer, live disassembly, a section map, and a gradeable challenge runner. The engine and its lesson content are decoupled from the web framework, so they embed into a larger application as a standalone reverse-engineering feature. One core, three consumers, curated content.

## It never runs a binary

The single load-bearing decision, and the reason a web app that eats binaries is safe: the backend never executes any binary. Every operation is reading and parsing bytes.

- Hex dump, ELF header parse, section walk, symbol read, and string scan are all pure byte reads.
- Disassembly is decoding, not running. capstone reads instruction bytes and returns their text form; it never transfers control to the decoded code.
- Patch challenges are graded by a static byte diff against a known-good patched target. The patched binary is never executed.

Challenge binaries are curated and pre-compiled and shipped as static assets; nobody uploads an executable to run. So there is no arbitrary-code-execution surface, no sandbox to escape, and no resource-exhaustion path through a hostile binary, because nothing is ever run. This is a hard constraint, not a preference. Any feature that would require executing a binary is out of scope until it is redesigned against this posture, most likely by moving execution to an isolated, disposable sandbox that is explicitly not the analysis backend.

## Features

**The engine**
- A hand-rolled ELF64 parser: header, section table, and symbol table read straight from raw bytes
- x86-64 disassembly via capstone in Intel syntax, annotated with comparisons, conditional branches, call targets, and RIP-relative data references
- Import resolution through the PLT, walking `.plt`, `.rela.plt`, `.dynsym`, and `.dynstr` the way the loader would, so a bare `call 0x401050` becomes `call atoi`
- Cross-references (who calls this, what data it touches) and a basic-block control-flow graph for a single function
- Function discovery in stripped binaries by scanning executable sections for the standard prologue, so a symbol-stripped binary is still navigable

**The platform**
- Six curated challenges over one sample binary, spanning the five core reverse-engineering skills plus a stripped variant
- Solve-then-reveal grading in three machine-checkable categories: found-value, identified-symbol, and patched-bytes
- Progress persisted in SQLite behind a swappable interface, so it drops into a host application's own store without touching the engine
- A React web app and a read-only FastAPI, served together for one-command self-hosting

## Quick Start

rveng self-hosts on localhost with Docker. No account, no secret, no external service, nothing to configure.

```bash
curl -fsSL https://angelamos.com/rveng/install.sh | bash
# then open http://localhost:8790
```

One command takes a fresh machine to the app built and running: it installs Docker if it is missing, builds the engine image and the React app, brings the stack up, and waits until it answers. The first thing you do is open the browser.

Already have the repo cloned? Run it straight from the project directory:

```bash
just up          # build and serve on http://localhost:8790
just dev-up      # hot-reload dev stack on http://localhost:8791
just test        # engine tests, no server (uv run pytest -q)
just typecheck   # frontend type check, no server
just down        # stop
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see every recipe grouped by area: `dev` (dockerized Vite hot-reload), `prod` (the self-host stack), `verify` (tests and type check), and `cleanup`.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Architecture

One analysis engine with three faces. The engine is framework-free Python that knows nothing about HTTP or React. A thin FastAPI layer adapts it to the web. A React app consumes that API. Progress lives behind a small interface so the whole thing embeds into a larger application without dragging a web framework along.

```
                         +--------------------------+
                         |   rveng/engine/  (pure)  |
                         |  elf disasm plt xref cfg  |
                         |  hex strings patch discover|
                         |  challenge (grading)      |
                         +------------+--------------+
                                      |
                    +-----------------+-----------------+
                    |                                   |
              +-----+------+                     +------+------+
              |  HTTP API  |                     |   library   |
              |  FastAPI   |                     |  (import it)|
              +-----+------+                     +-------------+
                    |
              +-----+------+
              | React app  |
              +------------+
```

In production, nginx serves the built frontend and proxies `/api` to the engine container, which stays a pure API and never learns to serve a SPA. Development mirrors that with nginx fronting the Vite dev server for hot reload. The two stacks use structural-literal project names (`rveng` and `rveng-dev`), so they are namespace-isolated by construction and never collide.

```
PROD (compose.yml, "rveng")          DEV (dev.compose.yml, "rveng-dev")

 browser :8790                        browser :8791
     |                                    |
  [ nginx ]  serves dist             [ nginx ] --> [ vite HMR ]
     |  /api                             |  /api
  [ api ]  uvicorn                   [ api ] uvicorn --reload
     |                                    |
  rveng_data (sqlite progress)       rveng_data_dev
```

## Project Structure

```
rveng/
├── compose.yml           # prod self-host: nginx + api (name: rveng)
├── dev.compose.yml       # dev: nginx + vite HMR + api --reload
├── justfile              # dev / prod / verify / cleanup recipes
├── install.sh            # one-shot curl|bash: installs Docker, builds, runs
├── uninstall.sh          # tears the stacks down and removes the cache
├── infra/
│   ├── docker/           # api.dockerfile, vite.dev.dockerfile, vite.prod.dockerfile (multistage -> nginx)
│   └── nginx/            # dev.nginx (fronts Vite HMR), prod.nginx (serves dist)
├── src/rveng/
│   ├── engine/           # the pure analysis core (no HTTP, no framework)
│   │   ├── elf.py        # hand-rolled ELF64 header / sections / symbols
│   │   ├── disasm.py     # capstone x86-64 decode + annotation
│   │   ├── plt.py        # PLT / GOT import resolution
│   │   ├── xref.py       # cross-references from decoded instructions
│   │   ├── cfg.py        # basic-block control-flow graph
│   │   ├── discover.py   # stripped-binary function discovery
│   │   ├── hex.py  strings.py  patch.py   # dump, string scan, byte diff
│   │   └── challenge.py  # the challenge model and solve-then-reveal grader
│   └── api/              # thin FastAPI adapter over the engine
│       ├── app.py        # create_app() and every read-only route
│       ├── store.py      # challenge loader + ProgressStore (in-memory / sqlite)
│       ├── schemas.py limits.py middleware.py server.py
├── challenges/           # the six curated challenges (target + source + answer)
├── frontend/             # the React face (self-contained, extractable)
└── learn/                # the teaching track
```

## Learn

This project ships a full teaching track. Read it in order, or jump to what you need.

| Doc | What it covers |
|-----|----------------|
| [`learn/00-OVERVIEW.md`](learn/00-OVERVIEW.md) | What rveng is, the no-execution posture, and a quick tour |
| [`learn/01-CONCEPTS.md`](learn/01-CONCEPTS.md) | Reverse-engineering theory: static analysis, ELF, symbols, the PLT, patching, grounded in real analysis |
| [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) | The one-engine-three-faces design and how a request flows, with diagrams |
| [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) | A code walkthrough of every engine module against the sample binary |
| [`learn/04-CHALLENGES.md`](learn/04-CHALLENGES.md) | The six challenges, what each teaches, and how to add your own |

## License

[AGPL 3.0](LICENSE).
