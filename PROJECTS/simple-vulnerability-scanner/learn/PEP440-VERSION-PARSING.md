# PEP 440: Python Version Parsing from Scratch

Parsing Python version strings was one of the harder parts of building angela. If you're working on anything that touches the Python ecosystem, PEP 440 is worth understanding — it's weirder than you'd expect.

---

## The problem

Python versions are **not** semantic versioning. They follow [PEP 440](https://peps.python.org/pep-0440/), which has components semver doesn't:

```
[epoch!] release [pre-release] [.postN] [.devN] [+local]
```

Real examples from PyPI:

| Version | What it means |
|---------|---------------|
| `1.2.3` | Normal release |
| `2!1.0` | Epoch 2 — beats any version with epoch 0 or 1 |
| `1.0a1` | Alpha pre-release |
| `1.0b2` | Beta pre-release |
| `1.0rc1` | Release candidate |
| `1.0.dev3` | Development snapshot |
| `1.0.post1` | Post-release (stable — just a docs or metadata fix) |
| `1.0+ubuntu1` | Local version label (never shows up on PyPI) |

---

## Why you can't just string-compare

If you naively compare version strings, `1.0a1` looks "newer" than `1.0` because `a` > empty string in ASCII. But Python's actual ordering is:

```
1.0.dev1 < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1
```

A tool that gets this wrong will upgrade users to unstable pre-releases. That's why angela implements the full spec.

---

## How the parser works

The parser lives in `internal/pypi/version.go`. It uses a single compiled regex to pull out all the components in one pass:

```
(?i)^v?
(?:(\d+)!)?                          # epoch
(\d+(?:\.\d+)*)                      # release segments
(?:[-_.]?(alpha|a|beta|b|...|rc)[-_.]?(\d*))?  # pre-release
(?:[-_.]?(post|rev|r)[-_.]?(\d*)|-(\d+))?     # post-release
(?:[-_.]?(dev)[-_.]?(\d*))?          # dev release
(?:\+([a-z0-9]...))?$                # local version
```

Each section maps to a field in the `Version` struct:

```go
type Version struct {
    Raw     string
    Epoch   int
    Release []int    // [1, 2, 3] for "1.2.3"
    PreKind string   // "a", "b", or "rc"
    PreNum  int
    Post    int      // -1 means absent
    Dev     int      // -1 means absent
    Local   string
}
```

The `-1` sentinel for Post and Dev is important — it's how you tell "not present" apart from "present with value 0". Both `1.0.post0` and `1.0.post` are valid PEP 440 (implicit zero), but they're different from `1.0` which has no post-release at all.

---

## Normalization

PEP 440 allows a bunch of different spellings that all mean the same thing:

| Input | Normalized |
|-------|-----------|
| `alpha` | `a` |
| `beta` | `b` |
| `c`, `pre`, `preview` | `rc` |
| `rev`, `r` | `post` |
| `1.0-1` | `1.0.post1` (implicit post via dash-number) |
| `1.0a` | `1.0a0` (implicit zero) |
| `v1.0` | `1.0` (strip leading v) |

The parser normalizes all of these during extraction, so the rest of the codebase never has to think about variant spellings.

---

## Version comparison

Python's `packaging` library compares versions by converting them to tuples that sort naturally. angela does the same thing:

```go
func (v Version) Compare(other Version) int {
    // 1. Compare epochs
    // 2. Compare release segments (with implicit zero extension)
    // 3. Compare pre-release (using sentinel values)
    // 4. Compare post-release
    // 5. Compare dev-release
}
```

The trick is in the sentinel values:

| Component state | Sort key |
|----------------|----------|
| Dev-only (no pre, no post) | `MinInt, MinInt` — sorts before everything |
| Pre-release `a1` | `0, 1` — alpha rank 0 |
| Pre-release `b2` | `1, 2` — beta rank 1 |
| Pre-release `rc1` | `2, 1` — rc rank 2 |
| Final release (no pre) | `MaxInt, MaxInt` — sorts after all pre-releases |

Using `math.MinInt` and `math.MaxInt` means the comparison function is just a sequence of `cmp.Compare` calls — no special-case branching needed.

---

## Stability detection

A version is **stable** if it has no pre-release tag and no dev tag:

```go
func (v Version) IsStable() bool {
    return v.PreKind == "" && v.Dev < 0
}
```

Post-releases count as stable — `1.0.post1` is a docs fix or metadata correction, not an unstable build.

---

## Takeaways

A single compiled regex handles every PEP 440 form in one pass. The alternative would be a hand-written state machine with 3x the code and no real upside.

Normalizing at parse time (alpha→a, preview→rc) keeps things clean — nothing downstream ever has to handle variant spellings.

The version parser currently has 90+ test cases across 10 functions. When you're implementing something spec-driven like this, writing the test cases from the spec first and then making them pass is the way to go.
