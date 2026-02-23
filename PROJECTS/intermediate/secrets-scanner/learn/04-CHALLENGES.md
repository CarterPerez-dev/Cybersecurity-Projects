# Extension Challenges

These challenges extend Portia beyond its current capabilities. Each one teaches a different skill. They're ordered roughly by difficulty and build on the existing codebase without requiring major refactors.

## Challenge 1: Pre-commit Hook Integration

**Difficulty:** Easy | **Time:** 1-2 hours | **Teaches:** Git hooks, shell scripting, developer workflow

Write a script that installs Portia as a Git pre-commit hook. When a developer runs `git commit`, the hook should:

1. Build Portia (or use a pre-built binary)
2. Run `portia git --staged` to scan only staged files
3. If secrets are found, print the findings and abort the commit
4. If no secrets are found, allow the commit to proceed

**Starting point:** Create a `scripts/install-hook.sh` that writes a pre-commit hook to `.git/hooks/pre-commit`. The hook script should call `portia git --staged --format terminal` and check the exit code.

**Hints:**
- Git hooks must be executable (`chmod +x`)
- The hook should exit 0 to allow the commit, non-zero to abort
- You'll need to add exit code support to Portia's CLI (currently it always exits 0). Add `--exit-code` flag that returns exit code 1 when secrets are found. Modify `executeScan` in `internal/cli/scan.go` to call `os.Exit(1)` when findings exist and the flag is set.
- Consider adding a `--quiet` flag that suppresses the banner and spinner for hook usage

**Bonus:** Make it work with the `pre-commit` framework (https://pre-commit.com) by creating a `.pre-commit-hooks.yaml` in the repo root.

## Challenge 2: Custom Rule YAML Loader

**Difficulty:** Medium | **Time:** 2-3 hours | **Teaches:** YAML/TOML parsing, rule validation, config extensibility

Add support for user-defined detection rules in a YAML or TOML file. Users should be able to create `.portia/rules.yml`:

```yaml
rules:
  - id: "internal-api-key"
    description: "Internal API key format"
    severity: HIGH
    keywords: ["ikey_"]
    pattern: 'ikey_[a-zA-Z0-9]{32}'
    secret_group: 0
    entropy: 3.5
```

**Starting point:** Create `internal/rules/custom.go` with a `LoadCustomRules(path string) ([]*types.Rule, error)` function. Call this from `scan.go` after registering builtins.

**Hints:**
- Use `gopkg.in/yaml.v3` for YAML parsing
- Validate the regex pattern by calling `regexp.Compile` and returning a clear error if it fails
- Validate severity against allowed values
- Check for duplicate rule IDs against the existing registry
- Consider supporting `allowlist` in the YAML format with path and value patterns

**Gotcha:** Keywords are critical for performance. If a custom rule has no keywords, it'll run its regex against every chunk. Either require at least one keyword or warn the user that empty keywords will be slow.

## Challenge 3: Incremental Scanning with Cache

**Difficulty:** Medium | **Time:** 2-3 hours | **Teaches:** Hashing, file-based caching, performance optimization

Add a `.portia-cache/scan.json` file that stores SHA-256 hashes of previously scanned files. On subsequent scans, skip files whose hash hasn't changed.

**Starting point:** Create `internal/cache/scan.go` with:
- `type ScanCache struct` holding a map from relative file path to file hash
- `Load(path) (*ScanCache, error)` and `Save(path) error` for persistence
- `IsChanged(relPath string, content []byte) bool` that computes SHA-256 and compares

**Hints:**
- Store the cache in `.portia-cache/scan.json` in the scanned directory
- Use `crypto/sha256` for hashing
- The cache should include the rule count as metadata. If rules change (new rule added), invalidate the entire cache.
- Add a `--no-cache` flag to force a full rescan
- Add cache invalidation in `internal/cli/scan.go` before creating the source
- Consider adding the Portia version to the cache metadata so version upgrades invalidate the cache

**Performance impact:** On a 10,000-file codebase where only 50 files changed, this reduces scan time by ~99.5%.

## Challenge 4: Git Blame Integration

**Difficulty:** Medium | **Time:** 3-4 hours | **Teaches:** Git blame API, attribution, enriched output

After detecting a secret, run `git blame` on the file to determine who committed it and when. Add this information to the finding.

**Starting point:** The `types.Finding` struct already has `Author` and `CommitDate` fields, but they're only populated during git history scans. For directory scans, these fields are empty.

**Hints:**
- Use go-git's `git.Blame` function: `blame, err := git.BlameCommit(commit, path)`
- The blame result gives you the commit SHA, author, and date for each line
- Match the finding's `LineNumber` to the blame result to get attribution
- This should be opt-in (`--blame` flag) since it adds overhead
- For files outside a git repo, skip blame silently
- Add blame data to all three reporter formats (terminal, JSON, SARIF)

**Gotcha:** `git.Blame` requires walking the full commit history for the file. On large repos, this can be slow. Consider caching blame results per file.

## Challenge 5: Multi-repo Scanning

**Difficulty:** Medium | **Time:** 3-4 hours | **Teaches:** Configuration management, concurrent I/O, aggregation

Add a `portia scan-all` command that reads a config file listing multiple repositories and scans them all, producing a unified report.

```toml
[[repos]]
path = "/home/dev/api-server"
excludes = ["vendor/"]

[[repos]]
path = "/home/dev/frontend"
excludes = ["node_modules/", "dist/"]

[[repos]]
url = "https://github.com/org/service.git"
branch = "main"
depth = 50
```

**Starting point:** Create `internal/cli/scanall.go` with a new cobra command.

**Hints:**
- Parse the config file with `pelletier/go-toml`
- For `url` entries, clone to a temp directory using `git.PlainClone`
- Run each repo scan concurrently using an errgroup
- Prefix each finding's `FilePath` with the repo name/path for disambiguation
- Consider a `--parallel N` flag to control concurrency
- Clean up cloned temp directories on exit (use `defer`)

## Challenge 6: GitHub Action

**Difficulty:** Hard | **Time:** 4-6 hours | **Teaches:** GitHub Actions, Docker, SARIF integration, CI/CD

Build a GitHub Action that runs Portia on pull requests and uploads results to GitHub Code Scanning.

**Starting point:** Create `.github/action/action.yml` and a Dockerfile.

**Structure:**
```
.github/action/
├── action.yml        # Action metadata
├── Dockerfile        # Build Portia in a container
└── entrypoint.sh     # Run Portia and upload SARIF
```

**Hints:**
- The `action.yml` should accept inputs: `path` (default `.`), `format` (default `sarif`), `exclude` (optional), `hibp` (default false)
- The Dockerfile should be a multi-stage build: compile Portia in a Go image, copy the binary to a slim runtime image
- `entrypoint.sh` runs `portia scan --format sarif $INPUT_PATH > results.sarif`, then uploads using `gh api repos/{owner}/{repo}/code-scanning/sarifs`
- Use `github.sha` for the commit SHA in the SARIF upload
- The Action should fail (exit 1) if CRITICAL or HIGH findings are detected

**Testing:** Create a `.github/workflows/test-action.yml` that tests the action against `testdata/fixtures/`.

## Challenge 7: Secret Rotation Suggestions

**Difficulty:** Hard | **Time:** 4-6 hours | **Teaches:** Provider APIs, remediation guidance, structured output

After detecting a leaked secret, provide specific rotation instructions for each provider.

**Starting point:** Create `internal/remediation/remediation.go` with a map from rule ID to remediation steps.

**Example output:**
```
CRITICAL  aws-access-key-id  config.py:1

  Rotation steps:
  1. Go to AWS IAM Console → Users → Security credentials
  2. Create a new access key
  3. Update all services using the old key
  4. Deactivate the old key (don't delete yet)
  5. After 24-48 hours with no issues, delete the old key
  6. Run: aws sts get-caller-identity (to verify new key works)

  Documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
```

**Hints:**
- Create a `Remediation` struct with `Steps []string`, `DocURL string`, `CLICommand string`
- Map rule IDs to remediations: `aws-access-key-id` → AWS IAM rotation, `github-pat-classic` → GitHub settings rotation, `stripe-live-secret` → Stripe dashboard rotation
- Add a `--remediate` flag to the CLI
- For the terminal reporter, print remediation steps indented under each finding
- For JSON/SARIF, include remediation in properties

## Challenge 8: Aho-Corasick Keyword Matching

**Difficulty:** Hard | **Time:** 3-4 hours | **Teaches:** Trie data structures, string matching algorithms, performance

Replace the linear keyword scan in `MatchKeywords` with an Aho-Corasick automaton for O(n) matching against all keywords simultaneously.

**Current approach** (`internal/rules/registry.go` MatchKeywords):
For each rule, for each keyword, call `strings.Contains`. This is O(rules * keywords * content_length).

**Better approach:**
Build a trie from all keywords at registry initialization time. At scan time, run the content through the automaton once. The automaton reports which keywords matched, and you map those back to rules.

**Starting point:** Use `github.com/cloudflare/ahocorasick` or implement your own.

**Hints:**
- Build the automaton in `Registry.Register` or in a `Finalize()` method called after all rules are registered
- The automaton should be case-insensitive (convert all keywords and content to lowercase)
- Map each keyword back to its rule(s) using a reverse index
- Benchmark before and after: `go test -bench=BenchmarkMatchKeywords -benchmem`
- The improvement will be most noticeable on large files with many rules. On small files with few rules, the overhead of building the automaton might make it slower.

**Expected improvement:** On a 500-line file with 150 rules averaging 2 keywords each, the current approach does ~300 `strings.Contains` calls. Aho-Corasick does one pass through the content. For large codebases with thousands of files, this adds up.

## General Tips

- **Write tests first.** Every challenge should start with a failing test. The existing test patterns in `internal/engine/detector_test.go` and `internal/engine/integration_test.go` are good templates.
- **Keep changes isolated.** Each challenge should be implementable without modifying the core detection logic. Use interfaces and composition to extend rather than modify.
- **Benchmark when making performance claims.** Go's `testing.B` benchmarks are simple to write. If you claim something is faster, prove it with numbers.
- **Check the Justfile.** Run `just ci` before considering any challenge complete. All existing tests should still pass.
