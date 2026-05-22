Hey, thanks for picking this up and for thinking it through before opening a PR — appreciate it.

A few things upfront so you've got room to do this your way:

**On the synopsis** — `SYNOPSES/beginner/Steganography.Multi.Tool.md` is a *suggestion*, not a spec. You don't have to follow it exactly. The only thing I really care about is that the **scale/complexity is at least equivalent** to what the synopsis implies. If you want to swap stacks entirely — different language, add a web frontend, whatever — go for it, as long as the end result isn't smaller in scope than what's described.

**On the core idea** — the one thing that should stay is the "multi" part. This is a steganography *tool* (not a detector), and it should cover **at least 5 different stego formats/techniques**, ideally 6. They all need to be solid implementations — I'd rather have 5 good ones than 6 where one is half-baked.

**On the 3-PR split** — fine by me. Each PR should ship with **tests for what it adds** — not exhaustive, just enough to confirm each technique actually round-trips correctly. Don't go overboard. You can save the lint pass for the end if that's easier.

**On stack/tooling** — pick whatever you want, but a few hard requirements per language:

- **Python**: `ruff` + `mypy` are required. `pylint` is optional but I'll probably run it during review, so I'd recommend it — you'll need to disable a lot of rules to make it sane; look at the `pyproject.toml` in any of my recent Python projects for what I ignore. Format with `yapf`, column limit ~90.
- **Go**: `golangci-lint` (+ `gofmt`/`goimports`).
- **TypeScript**: `Biome` for format + lint. (And yes — if you go JS, it has to be TypeScript, not plain JS.)
- **Any language**: a `justfile` for install / lint / test / run targets. I keep this consistent across the whole repo, so please get familiar with it. Think of it as a nicer `Makefile`.

**On references** — the two you picked aren't the best choices:

- `keylogger/` was one of the very first projects in the repo. It works, but a lot has improved since then.
- `metadata-scrubber-tool/` was an external contribution — useful as a "another contributor did this" example but not really written in my style.

Better references for senior-level Python style in this repo:

- `PROJECTS/intermediate/dlp-scanner/` — most recent intermediate Python project, closest in scale/feel to what you're proposing
- `PROJECTS/beginner/base64-tool/` and `PROJECTS/beginner/caesar-cipher/`
- `PROJECTS/foundations/password-manager/` — technically foundations, but it's the most complex one in that tier and pretty close to intermediate in style

Look at those for code structure, `pyproject.toml`, `justfile`, and overall layout.

**On the `learn/` folder and README** — I write/standardize those across every project to keep them consistent, so don't sweat matching the exact format. If you take a shot at them, great, but if not I'll handle them after merge. Same for `install.sh` and any other dev-tooling polish — I can clean up around you, the main thing is the code itself.

**On AI usage** — I'm going to be direct because it's relevant to how I'll review:

Using AI to write code is totally fine — even heavily. What I push back on is *unsupervised* AI work (the "let it rip and come back when it says it's done" approach). The distinction matters: you're the project manager, the AI is the dev. You make the big calls, you micromanage the scope, and you verify the output.

A few things that meaningfully raise the quality bar when working with AI on a project this size:

1. **Amplify the model with research before it codes.** AI training data is not omniscient — it's training data. Spend time gathering up-to-date info on the libraries you'll use, senior-level patterns specific to *this* stack and *this* domain, advanced/nuanced techniques in steganography itself, recent changes in the ecosystem. Feed that to the model before it writes anything. The gap between "AI that knows generic Python" and "AI that's been primed with senior patterns + current best practices in stego + the specific libraries you chose" is enormous.

2. **The project scope is bigger than any single context window.** You will burn through multiple AI sessions before this is done. The seams *between* those sessions — what gets carried forward, what gets re-established, what assumptions silently drift — are where quality usually dies. Most of the time the drift is subtle and you don't catch it until the project is "finished" and inconsistent. Plan for those handoffs deliberately.

3. **Senior dev with AI ≠ junior dev with AI.** The same model produces wildly different output depending on who's driving. I can spot low-effort AI output quickly, and I review strictly *because* AI can be excellent when used well — so the floor for what counts as "good enough" is higher, not lower.

None of this is gatekeeping or meant to scare you off — but fair warning: there are ~70 projects in this repo and the bar I'm holding them all to is "role-model code people study," not "good enough and it works," so expect strict review feedback even when the work is solid.

Go ahead and start on PR 1 whenever you're ready. Ping me if anything's unclear as you go.
