# ty - Extremely Fast Python Type Checker

**Official Docs**: https://docs.astral.sh/ty

## What is ty?

ty is an **extremely fast** Python type checker written in Rust by Astral (the creators of uv and Ruff). It's designed to be:
- **10-100x faster** than mypy and pyright
- **Zero configuration** to get started
- **Compatible** with existing type annotations
- **Production-ready** for large codebases

Think: "Ruff for type checking" - blazing fast, modern, and built for scale.

---

## Installation

### Add to your project dependencies:

```bash
# With uv (recommended)
uv add --dev ty

# With pip
pip install ty
```

Or run it directly without installing:
```bash
uvx ty check
```

---

## Quick Start

### 1. Basic Usage

```bash
# Check entire project
ty check

# Check specific files/directories
ty check src/
ty check src/models/User.py

# Watch mode (recheck on file changes)
ty check --watch
```

### 2. Exit Codes

- `0` - No errors
- `1` - Type errors found
- `2` - Invalid config/CLI options
- `101` - Internal error

### 3. Output Formats

```bash
# Default verbose output with context
ty check

# Concise (one per line)
ty check --output-format concise

# GitHub Actions annotations
ty check --output-format github

# GitLab Code Quality JSON
ty check --output-format gitlab
```

---

## Configuration

### Option 1: pyproject.toml (Recommended)

```toml
[tool.ty]
# Python version (auto-detected from requires-python if not set)
python-version = "3.12"

# Source directories
[tool.ty.src]
include = ["src", "tests"]
exclude = ["src/generated/**", "*.proto"]

# Python environment (auto-detected from .venv if not set)
[tool.ty.environment]
root = ["./src"]
python = "./.venv"

# Rule severity configuration
[tool.ty.rules]
# Make warnings errors
possibly-missing-attribute = "error"
possibly-missing-import = "error"

# Downgrade errors to warnings
division-by-zero = "warn"

# Disable specific rules
redundant-cast = "ignore"
unused-ignore-comment = "ignore"

# Override rules for specific files
[[tool.ty.overrides]]
include = ["tests/**"]
[tool.ty.overrides.rules]
unresolved-reference = "warn"

# Terminal output
[tool.ty.terminal]
error-on-warning = false  # exit code 1 if warnings exist
output-format = "full"    # full | concise | github | gitlab
```

### Option 2: ty.toml (Alternative)

Create `backend/ty.toml` (same structure, no `[tool.ty]` prefix):

```toml
python-version = "3.12"

[src]
include = ["src", "tests"]

[rules]
possibly-unresolved-reference = "warn"
```

---

## Important Rules

### Error-Level (Default)

These **will fail** your CI/CD:

| Rule | What it catches |
|------|----------------|
| `call-non-callable` | Calling non-callable objects: `4()` |
| `division-by-zero` | Division by zero: `5 / 0` |
| `unresolved-import` | Missing modules: `import nonexistent` |
| `unresolved-reference` | Undefined variables: `print(undefined_var)` |
| `unresolved-attribute` | Missing attributes: `obj.missing_attr` |
| `invalid-argument-type` | Wrong arg types: `func(x: int)` called with `func("str")` |
| `invalid-return-type` | Return type mismatch |
| `missing-argument` | Missing required args: `func(x: int)` called as `func()` |
| `unknown-argument` | Unknown kwargs: `func(x=1, unknown=2)` |
| `unsupported-operator` | Bad operators: `"string" + 123` |
| `invalid-assignment` | Type mismatch: `x: int = "string"` |

### Warning-Level (Default)

Won't fail CI unless you enable `--error-on-warning`:

| Rule | What it catches |
|------|----------------|
| `possibly-unresolved-reference` | Variables that **might** not be defined (conditional) |
| `possibly-missing-attribute` | Attributes that **might** not exist (conditional) |
| `possibly-missing-import` | Imports that **might** be missing (conditional) |
| `redundant-cast` | Unnecessary `cast()` calls |
| `deprecated` | Usage of deprecated APIs |
| `undefined-reveal` | `reveal_type()` without importing it |

### Ignore-Level (Disabled by Default)

Must explicitly enable:

| Rule | What it catches |
|------|----------------|
| `unused-ignore-comment` | Unused `# type: ignore` or `# ty: ignore` |
| `possibly-unresolved-reference` | Possibly undefined refs in conditional code |
| `division-by-zero` | Preview rule - division by zero |

---

## Suppression Comments

### ty-specific suppression

```python
# Suppress specific rule
result = unsafe_operation()  # ty: ignore[invalid-argument-type]

# Suppress multiple rules
value = risky()  # ty: ignore[unresolved-attribute, invalid-return-type]

# Multi-line expressions (comment on first OR last line)
result = long_function(  # ty: ignore[missing-argument]
    arg1,
    arg2
)

# Combine with other tools
x = 1  # ty: ignore[division-by-zero]  # fmt: skip
```

### Standard type: ignore (PEP 484)

```python
# ty respects standard type: ignore
result = something()  # type: ignore

# But ty: ignore is preferred for specificity
result = something()  # ty: ignore[invalid-return-type]
```

### Disable all checking in a function

```python
from typing import no_type_check

@no_type_check
def untyped_function():
    return "anything" + 123  # no errors
```

### Check for unused suppressions

```toml
[tool.ty.rules]
unused-ignore-comment = "warn"  # warn about unused suppressions
```

---

## Common Configurations for Production

### Strict Mode (Recommended)

```toml
[tool.ty.rules]
# Treat all "possibly" rules as errors
possibly-missing-attribute = "error"
possibly-missing-import = "error"
possibly-unresolved-reference = "error"

# Catch unused suppressions
unused-ignore-comment = "warn"

# Stricter terminal behavior
[tool.ty.terminal]
error-on-warning = true
```

### Gradual Adoption (Recommended for existing codebases)

```toml
[tool.ty.rules]
# Downgrade strict rules to warnings
unresolved-attribute = "warn"
invalid-argument-type = "warn"

# Focus on critical errors only
[tool.ty.terminal]
error-on-warning = false
```

### FastAPI-Specific

```toml
[[tool.ty.overrides]]
include = ["src/routes/**", "src/dependencies/**"]

[tool.ty.overrides.rules]
# FastAPI uses runtime dependency injection
unresolved-reference = "warn"  # for Depends() params
```

---

## CLI Flags Reference

### Rule Control

```bash
# Override rule severity
ty check --error possibly-unresolved-reference
ty check --warn division-by-zero
ty check --ignore redundant-cast

# Can combine multiple
ty check --error rule1 --warn rule2 --ignore rule3
```

### Environment

```bash
# Specify Python environment
ty check --python .venv

# Python version
ty check --python-version 3.12

# Platform
ty check --python-platform linux
ty check --python-platform all  # no platform assumptions
```

### Output Control

```bash
# Verbosity
ty check -v      # verbose
ty check -vv     # very verbose
ty check -q      # quiet
ty check -qq     # silent

# Exit codes
ty check --exit-zero           # always exit 0
ty check --error-on-warning    # warnings = exit 1
```

---

## Environment Variables

```bash
# Log level (for debugging ty itself)
TY_LOG=debug ty check
TY_LOG=trace ty check

# Parallelism limit
TY_MAX_PARALLELISM=4 ty check

# Profile performance
TY_LOG_PROFILE=1 ty check  # creates tracing.folded

# Python path (additional search paths)
PYTHONPATH=/extra/path ty check

# Virtual environment
VIRTUAL_ENV=/path/to/.venv ty check
```

---

## Integration

### CI/CD (GitHub Actions)

```yaml
name: Type Check

on: [push, pull_request]

jobs:
  typecheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v5

      - name: Install dependencies
        run: uv sync --all-extras

      - name: Type check
        run: uv run ty check --output-format github
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ty
    rev: v0.0.1  # use latest version
    hooks:
      - id: ty
```

### VS Code

```json
// .vscode/settings.json
{
  "python.linting.enabled": true,
  "python.linting.tyEnabled": true,
  "python.linting.tyArgs": ["check"],
}
```

### Just/Makefile

```make
# Makefile
.PHONY: typecheck
typecheck:
	ty check

.PHONY: typecheck-watch
typecheck-watch:
	ty check --watch
```

---

## ty vs mypy vs pyright

| Feature | ty | mypy | pyright |
|---------|----|----|---------|
| **Speed** | 🚀 10-100x faster | Baseline | Fast (but slower than ty) |
| **Language** | Rust | Python | TypeScript |
| **Config** | Minimal (auto-detects) | Verbose | Verbose |
| **Strictness** | Configurable | Very strict | Very strict |
| **IDE Support** | Growing | Excellent | Excellent (VSCode) |
| **Ecosystem** | New (2024) | Mature (2012) | Mature (2019) |
| **Plugin Support** | Limited | Extensive | Limited |
| **Adoption** | Early | Industry standard | Microsoft standard |

### Migration from mypy

ty is **mostly compatible** with mypy. You can run both in parallel:

```toml
[tool.ty.rules]
# Map mypy behavior to ty
invalid-argument-type = "error"  # mypy: arg-type
invalid-return-type = "error"    # mypy: return-value
unresolved-attribute = "error"   # mypy: attr-defined
```

Key differences:
- ty is **faster** but **less mature**
- mypy has more plugins (e.g., sqlalchemy, django)
- ty auto-detects more (less config needed)
- ty focuses on speed, mypy on completeness

**Recommendation**: Use ty in dev for **fast feedback**, keep mypy in CI for **comprehensive checks** (for now).

---

## Troubleshooting

### ty can't find my virtual environment

```bash
# Explicitly specify
ty check --python .venv

# Or in pyproject.toml
[tool.ty.environment]
python = "./.venv"
```

### False positives in generated code

```toml
[tool.ty.src]
exclude = ["src/generated/**", "alembic/versions/**"]
```

### ty is too strict

```toml
# Downgrade specific rules
[tool.ty.rules]
possibly-missing-attribute = "warn"
possibly-unresolved-reference = "warn"
```

### Performance profiling

```bash
# Generate flamegraph
TY_LOG_PROFILE=1 ty check

# View with flamegraph.pl or speedscope.app
```

---

## Best Practices for This Project

### 1. Use ty for fast local development

```bash
# Quick checks while coding
ty check --watch
```

### 2. Keep mypy for CI completeness

```yaml
# Both in CI
- run: ty check              # fast, catches most issues
- run: mypy src/             # thorough, catches edge cases
```

### 3. Suppress intentional violations

```python
# FastAPI dependency injection
async def get_db(db: Annotated[AsyncSession, Depends(get_db_session)]):
    # ty might not understand Depends()
    return db  # ty: ignore[invalid-return-type]
```

### 4. Configure for async/SQLAlchemy

```toml
[[tool.ty.overrides]]
include = ["src/repositories/**", "src/services/**"]

[tool.ty.overrides.rules]
# Async/SQLAlchemy patterns ty might not understand yet
unresolved-attribute = "warn"
```

---

## Key Takeaways

✅ **DO**:
- Use `ty check --watch` during development
- Configure `pyproject.toml` for your project
- Enable `unused-ignore-comment` to keep suppressions clean
- Use `--error-on-warning` in CI for strictness

❌ **DON'T**:
- Blindly suppress errors (investigate first)
- Use `# type: ignore` without rule codes
- Disable important rules globally (use overrides)
- Expect feature parity with mypy (yet)

---

## Quick Reference Card

```bash
# Development
ty check                           # check everything
ty check --watch                   # watch mode
ty check src/models/               # specific directory

# CI/CD
ty check --error-on-warning        # warnings = errors
ty check --output-format github    # GitHub annotations

# Debugging
ty check -vv                       # very verbose
TY_LOG=debug ty check              # ty internal logs

# Configuration
ty check --python .venv            # specify venv
ty check --python-version 3.12     # specify version
ty check --error rule-name         # override rule severity
```

---

## Resources

- **Official Docs**: https://docs.astral.sh/ty
- **GitHub**: https://github.com/astral-sh/ty
- **Changelog**: https://github.com/astral-sh/ty/releases
- **Rule Reference**: https://docs.astral.sh/ty/reference/rules
- **Astral Blog**: https://astral.sh/blog

---

**Last Updated**: 2025-12-06
**ty Version**: 0.0.1-alpha.30+
**Maintained By**: Astral (creators of uv, Ruff)
