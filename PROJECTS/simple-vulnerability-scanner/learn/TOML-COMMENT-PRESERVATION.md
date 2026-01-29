# Preserving Comments in Dependency Files

When angela updates version specifiers, it can't blow away the developer's comments, blank lines, and formatting. This turns out to be a surprisingly annoying problem. Here's how angela handles it for both `pyproject.toml` and `requirements.txt`.

---

## The constraint

A developer's `pyproject.toml` looks like this:

```toml
[project]
name = "myapp"
version = "1.0.0"

# Core runtime dependencies
dependencies = [
    "requests>=2.28.0",  # HTTP library - pin for security
    "django>=3.2,<4.0",
    "flask[async]>=2.0",
]
```

After running `angela update`, the file should look like:

```toml
[project]
name = "myapp"
version = "1.0.0"

# Core runtime dependencies
dependencies = [
    "requests>=2.32.3",  # HTTP library - pin for security
    "django>=5.1.5",
    "flask[async]>=3.1.0",
]
```

Only the version numbers changed. Every comment, every space, every quote style — still there. Same goes for `requirements.txt` — inline comments, section headers, all of it should survive.

---

## Why TOML libraries can't do this

Both major Go TOML libraries (BurntSushi/toml and pelletier/go-toml) work by unmarshaling into Go structs, then marshaling back:

```go
var proj PyProject
toml.Unmarshal(data, &proj)         // comments stripped
proj.Dependencies[0] = "requests>=2.32.3"
output, _ := toml.Marshal(proj)     // comments gone, formatting changed
```

Go's reflection system has no way to store comment metadata on struct fields. The unmarshal/marshal round-trip just destroys them. This isn't a library bug — it's a fundamental limitation of how Go struct serialization works.

pelletier/go-toml v2 does have an `unstable` package that exposes AST access with comments preserved in the parse tree, but there's no serializer — you'd have to write your own TOML emitter from scratch.

---

## Regex surgery

angela's approach: don't parse and re-serialize. Treat the file as a byte buffer and surgically replace only the version specifier.

The implementation for pyproject.toml lives in `internal/pyproject/writer.go`:

1. Build a regex that matches the full dependency string inside quotes:
   ```
   "requests>=2.28.0"
   ```

2. Capture groups isolate the pieces:
   - Group 1: package name (`requests`)
   - Group 2: extras (`[async]` or empty)
   - Group 3: version specifier (`>=2.28.0`)
   - Group 4: markers (`;python_version>='3.8'` or empty)

3. Replace only group 3, keep everything else.

4. Validate before and after — feed the result through go-toml v2's unmarshaler to make sure the edit didn't break the TOML syntax.

```go
func (u *Updater) UpdateDependency(pkg, newSpec string) error {
    for _, q := range []byte{'"', '\''} {
        pattern := buildDepPattern(pkg, q)
        found := false
        u.content = pattern.ReplaceAllFunc(u.content,
            func(match []byte) []byte {
                found = true
                return replaceSpec(pattern, match, newSpec, q)
            },
        )
        if found {
            var probe map[string]any
            if err := toml.Unmarshal(u.content, &probe); err != nil {
                return fmt.Errorf("update produced invalid TOML: %w", err)
            }
            return nil
        }
    }
    return fmt.Errorf("dependency %q not found", pkg)
}
```

---

## requirements.txt uses the same idea

The `requirements.txt` writer in `internal/requirements/writer.go` works the same way — regex-based surgery on raw bytes. The difference is simpler: no quotes to worry about, no TOML validation needed. Lines look like:

```
django>=3.2.0
requests==2.28.1  # HTTP client
```

The regex matches the package name (with PEP 503 normalization) and its version specifier, replaces the spec, and leaves everything else alone — including inline comments.

Both writers share the same atomic write pattern (temp file + rename) and the same PEP 503 name normalization approach. The pyproject writer just has extra complexity for quote styles and TOML validation.

---

## The tricky parts

### PEP 503 name normalization

Package names on PyPI are case-insensitive and treat `-`, `_`, and `.` as equivalent:

```
Some_Package == some-package == some.package
```

The regex has to match all variants. angela splits the normalized name on `-` and joins with `[-_.]?`:

```go
parts := strings.Split(normalized, "-")
for i, p := range parts {
    parts[i] = regexp.QuoteMeta(p)
}
namePattern := strings.Join(parts, `[-_.]?`)
```

So the pattern for `some-package` becomes `some[-_.]?package`, which matches `some_package`, `some.package`, and `somepackage`.

### Go RE2 doesn't support backreferences

The TOML research suggested using `\1` to match closing quotes with the opening quote. Go's `regexp` package uses RE2, which doesn't do backreferences.

The workaround: try each quote style separately. Loop over `{'"', '\''}` and build a pattern specific to that quote character.

### Atomic file writes

angela writes to a `.tmp` file first, then renames over the original. If the process dies mid-write, the original is untouched:

```go
func (u *Updater) WriteFile(path string) error {
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, u.content, 0o600); err != nil {
        return fmt.Errorf("write temp: %w", err)
    }
    if err := os.Rename(tmp, path); err != nil {
        _ = os.Remove(tmp)
        return fmt.Errorf("rename: %w", err)
    }
    return nil
}
```

It's two syscalls, but the file is never in a half-written state.

---

## This is how production tools do it

Renovate and Dependabot both use regex/string manipulation for updating dependency files. They don't parse and re-serialize either — they do the same kind of surgical modification. No TOML, YAML, or JSON library in any language perfectly round-trips formatting and comments. Regex surgery sounds hacky, but it's the approach that actually works.

Go's RE2 engine guarantees linear-time matching, so even on large files with complex patterns there's no risk of catastrophic backtracking. Just keep in mind it doesn't support backreferences or lookaheads — design your patterns around that.
