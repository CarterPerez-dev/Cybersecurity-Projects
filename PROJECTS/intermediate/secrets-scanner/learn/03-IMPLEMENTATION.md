# Implementation Walkthrough

This document walks through the key code files in Portia. For each section, we'll look at what the code does, why it's designed that way, and what to watch out for.

## Shannon Entropy (`internal/rules/entropy.go`)

The entropy module answers one question: "Is this string random enough to be a secret?"

**ShannonEntropy function:**
The function takes a string and a charset (the set of all possible characters). It counts how many times each character appears, computes the probability of each character (count / total), then sums `-p * log₂(p)` across all characters.

The charset parameter matters for the calculation. If you compute entropy using only the characters present in the string, every string with all unique characters gets the same entropy. By computing against the full charset (e.g., all 62 alphanumeric characters), the result reflects how much of the available randomness space the string actually uses.

**DetectCharset function:**
Before computing entropy, Portia guesses the charset:
- If all characters are `0-9a-f`, it's hex. Use the 16-character hex charset.
- If all characters are `A-Za-z0-9+/=`, it's base64. Use the 64-character base64 charset.
- Otherwise, use the 62-character alphanumeric charset as default.

This matters because a hex string `deadbeefcafe` has different entropy depending on whether you evaluate it against 16 possible characters (hex) or 62 (alphanumeric). The hex evaluation is more generous, correctly identifying it as moderately random within its charset.

**Thresholds in practice:**
- `password = "admin"` → entropy ~2.3 (below most thresholds, filtered out)
- `password = "xK9mP2vL5nQ8jR3t"` → entropy ~4.0 (above threshold, flagged)
- `AKIAIOSFODNN7EXAMPLE` → no entropy check needed (structural rule, AKIA prefix is sufficient)

## Rule Registry (`internal/rules/registry.go`)

The registry is a simple map from rule ID to rule struct, with a few key methods:

**MatchKeywords** is the performance-critical function. For each rule in the registry, it checks if any of the rule's keywords appear (case-insensitive) in the content string. This is O(rules * keywords * content_length) in the worst case, but in practice, `strings.Contains` with short keywords against medium-length chunks is fast.

The return value is a slice of matching rules. If a chunk contains `password`, the registry returns all rules that have `password` as a keyword. If the chunk contains `AKIA`, it returns the AWS access key rules.

**Global allowlists** are defined at the bottom of `registry.go`:
- `GlobalPathAllowlist` - regex patterns for paths to skip (go.mod, package-lock.json, node_modules/, vendor/, binary extensions, minified JS)
- `GlobalValueAllowlist` - regex patterns for values to ignore (example, test, dummy, fake, placeholder, YOUR_API_KEY, xxxx..., TODO, CHANGEME)

These are separate from per-rule allowlists. A per-rule allowlist (like AWS's `AKIAIOSFODNN7EXAMPLE`) only applies to that specific rule. Global allowlists apply to all rules.

## Detection Rules (`internal/rules/builtin.go`)

Each rule is a `types.Rule` struct with these fields:

```go
type Rule struct {
    ID          string         // unique identifier like "aws-access-key-id"
    Description string         // human-readable "AWS Access Key ID"
    Severity    Severity       // SeverityCritical, SeverityHigh, etc.
    Keywords    []string       // fast pre-filter: ["AKIA", "ABIA", "ACCA", "ASIA"]
    Pattern     *regexp.Regexp // the actual detection regex
    SecretGroup int            // which capture group contains the secret (0=whole match)
    Entropy     *float64       // minimum entropy threshold (nil = no check)
    Allowlist   Allowlist      // per-rule path/value/stopword overrides
    SecretType  SecretType     // classification: APIKey, Token, Password, etc.
}
```

**Walking through the AWS access key rule:**

```go
{
    ID:          "aws-access-key-id",
    Description: "AWS Access Key ID",
    Severity:    types.SeverityCritical,
    Keywords:    []string{"AKIA", "ABIA", "ACCA", "ASIA"},
    Pattern:     regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`),
    SecretGroup: 1,
    SecretType:  types.SecretTypeAPIKey,
}
```

- **Keywords**: Four possible prefixes. If the chunk doesn't contain any of these four strings, skip this rule entirely.
- **Pattern**: Word boundary `\b`, then one of four prefixes, then exactly 16 uppercase alphanumeric characters, then word boundary. The whole match is captured in group 1.
- **SecretGroup**: 1 means extract from the first parenthesized group (the entire key).
- **No entropy threshold**: AWS keys have a fixed structure, so entropy validation isn't needed. The prefix + length is sufficient.
- **No allowlist**: The global value allowlist already catches `AKIAIOSFODNN7EXAMPLE`.

**Walking through the generic password rule:**

```go
{
    ID:          "generic-password",
    Description: "Password in Assignment",
    Severity:    types.SeverityHigh,
    Keywords:    []string{"password", "passwd", "pwd"},
    Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]`),
    SecretGroup: 1,
    Entropy:     ptr(3.5),
    SecretType:  types.SecretTypePassword,
}
```

- **Keywords**: Three variations of "password"
- **Pattern**: Case-insensitive match for password/passwd/pwd, followed by `:` or `=`, optional whitespace, then a quoted string of at least 8 characters. Group 1 captures just the password value.
- **Entropy threshold**: 3.5 bits. This filters out `password = "admin123"` (low entropy) while catching `password = "xK9mP2vL5nQ8jR3t"` (high entropy).
- The `ptr()` helper function creates a `*float64` from a literal, since Go doesn't allow taking the address of a constant directly.

## Directory Source (`internal/source/directory.go`)

The directory source walks a filesystem and produces chunks:

**WalkDir callback**: For each file system entry:
1. Check context cancellation (allows clean shutdown)
2. Skip known non-interesting directories (`.git`, `node_modules`, `vendor`, `__pycache__`, `.venv`)
3. Check if the relative path matches any exclude patterns
4. Skip binary file extensions (`.png`, `.jpg`, `.exe`, `.zip`, etc.)
5. Check file size against the max limit (default 1MB)
6. If all checks pass, call `emitChunks`

**emitChunks**: Opens the file and reads it line by line using `bufio.Scanner`:
- Accumulates lines into a `strings.Builder`
- Every 50 lines, sends the accumulated text as a `types.Chunk` with the file's relative path and the starting line number
- After the loop, sends any remaining lines as a final chunk

**Why 50-line chunks?** This is a tradeoff between memory usage and detection accuracy. Larger chunks use more memory per worker. Smaller chunks might split a multi-line secret across two chunks. 50 lines is a practical middle ground: most secrets fit on a single line, and 50 lines is small enough to process quickly.

**isExcluded function**: Checks two patterns:
- `filepath.Match` against the filename (base name only). This handles patterns like `*.env`
- `strings.Contains` against the full relative path. This handles patterns like `test/fixtures`

## Git Source (`internal/source/git.go`)

The git source uses go-git v5 to scan repository history without shelling out to the `git` binary.

**scanHistory**: Opens the repository with `git.PlainOpen`, then:
1. Gets a commit iterator filtered by branch (if specified)
2. For each commit, checks if the date is after `--since` and within `--depth`
3. Gets the commit's tree and walks all entries
4. For each blob (file), reads the content, checks size/excludes/binary extensions
5. Splits into 50-line chunks with commit metadata (SHA, author, date)

**scanStaged**: For pre-commit scanning:
1. Opens the repository and reads the git index (staging area)
2. For each index entry, reads the blob content from the object store
3. Produces chunks for only the files that are currently staged

**readBlob**: Reads a git blob object into a string:
```go
func readBlob(obj *object.Blob) (string, error) {
    reader, err := obj.Reader()
    if err != nil {
        return "", err
    }
    defer reader.Close()
    data, err := io.ReadAll(reader)
    if err != nil {
        return "", err
    }
    return string(data), nil
}
```

This uses `io.ReadAll` rather than `strings.Builder.ReadFrom` because `strings.Builder` doesn't have a `ReadFrom` method. A common mistake when working with go-git blobs.

## Detector (`internal/engine/detector.go`)

The detector is where rules meet content:

**Detect function flow:**
1. Call `registry.MatchKeywords(chunk.Content)` to get only relevant rules
2. If no rules match keywords, return nil immediately (fast path)
3. Split chunk content into lines
4. For each matched rule, for each line:
   - Run `rule.Pattern.FindAllStringSubmatchIndex(line, -1)` to find all matches
   - For each match, call `extractSecret` to get the secret from the capture group
   - If the rule has an entropy threshold, compute entropy and skip if below threshold
   - Call `FilterFinding` for false positive checks
   - If all checks pass, append to findings

**extractSecret function:**
```go
func extractSecret(line string, loc []int, group int) string {
    if group > 0 && len(loc) > group*2+1 {
        start := loc[group*2]
        end := loc[group*2+1]
        if start >= 0 && end >= 0 {
            return line[start:end]
        }
    }
    if len(loc) >= 2 {
        return line[loc[0]:loc[1]]
    }
    return ""
}
```

The `loc` array from `FindAllStringSubmatchIndex` contains pairs of start/end indices for each capture group. Group 0 is the whole match (indices 0,1), group 1 is the first parenthesized group (indices 2,3), etc. If the requested group doesn't exist or has negative indices (meaning the group didn't participate in the match), fall back to the whole match.

## Filter (`internal/engine/filter.go`)

The filter chain is the final defense against false positives:

**IsStopword**: The critical fix here was changing from substring matching to delimiter-split exact matching. The original implementation checked if any stopword was a substring of the secret. This caused `AKIAIOSFODNN7EXAMPLE` to match because "example" appeared as a substring. The fix:

```go
parts := strings.FieldsFunc(lower, func(r rune) bool {
    return r == '_' || r == '-' || r == '.' || r == '/'
})
for _, part := range parts {
    if _, ok := stopwords[part]; ok {
        return true
    }
}
```

This splits on common delimiter characters and checks each part independently. `AKIAIOSFODNN7EXAMPLE` doesn't split into "example" because there's no delimiter before it. But `module_controller_config` splits into ["module", "controller", "config"], all of which are stopwords.

**FilterFinding orchestration:**
```
IsPlaceholder(secret) → true = skip
IsTemplated(secret)   → true = skip
IsStopword(secret)    → true = skip
rule.Allowlist.Values  → match = skip
GlobalPathAllowlist    → match = skip
rule.Allowlist.Paths   → match = skip
All checks pass        → finding is real
```

Each layer is independent. A finding only needs to be caught by one layer to be filtered out.

## Pipeline (`internal/engine/pipeline.go`)

The pipeline connects everything with Go concurrency primitives:

**Setup:**
```go
chunks := make(chan types.Chunk, p.workers*4)
findingsCh := make(chan types.Finding, p.workers*4)
g, gctx := errgroup.WithContext(ctx)
```

Two buffered channels: one for chunks (source → workers), one for findings (workers → collector). Buffer size is `workers * 4` for backpressure balance.

**Source goroutine:** Runs `src.Chunks(gctx, chunks)` and defers `close(chunks)`. When the source finishes (or context is cancelled), the channel closes and workers drain remaining items.

**Worker goroutines:** Each worker loops over the chunks channel:
```go
for chunk := range chunks {
    if gctx.Err() != nil {
        return gctx.Err()
    }
    results := p.detector.Detect(chunk)
    for _, f := range results {
        findingsCh <- f
    }
}
```

Workers share a `sync.WaitGroup` separate from the errgroup. When all workers are done, a goroutine closes the findings channel.

**Collector goroutine:** Simple loop that collects all findings into a slice:
```go
for f := range findingsCh {
    mu.Lock()
    allFindings = append(allFindings, f)
    mu.Unlock()
}
```

The mutex isn't strictly necessary since there's only one collector goroutine, but it protects against future changes and makes the data race detector happy.

**Deduplication:** After all goroutines complete, `dedup` removes duplicate findings by creating a composite key from `ruleID + "|" + filePath + "|" + secret + "|" + commitSHA`. This handles cases where the same secret appears in overlapping chunks or across multiple git commits.

## HIBP Client (`internal/hibp/client.go`)

The HIBP client checks secrets against Troy Hunt's breach database:

**SHA-1 hashing:** The secret is hashed with SHA-1 (yes, SHA-1 is cryptographically broken, but HIBP uses it as a lookup key, not for security). The hash is uppercased and split: first 5 characters are the prefix, remaining 35 are the suffix.

**k-anonymity query:** Send the prefix to `https://api.pwnedpasswords.com/range/{prefix}`. The API returns all hash suffixes that share that prefix, along with occurrence counts:
```
0018A45C4D1DEF81644B54AB7F969B88D65:21
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
```

The client parses each line, splits on `:`, and checks if any suffix matches ours. If so, the secret was found in a breach.

**LRU cache:** Before making an API call, check the cache using the 5-character prefix as the key. The LRU cache holds 10,000 entries. Since each prefix covers all secrets with that prefix, caching is very effective when scanning large codebases with similar secrets.

**Circuit breaker:** Wraps the HTTP call in a `gobreaker.CircuitBreaker`. Settings:
- Max consecutive failures: 5
- Timeout (recovery period): 60 seconds
- After 5 straight failures, the circuit opens and immediately returns an error for all subsequent calls. After 60 seconds, it enters half-open state and lets one request through to test if the API is back.

**baseURL field:** The client has a `baseURL` field that defaults to the real HIBP API URL. In tests, this is overridden to point at an `httptest.Server`. This avoids the need for interface-based mocking and keeps the code simple.

## Reporters (`internal/reporter/`)

**Terminal reporter** (`terminal.go`):
- Sorts findings by severity (CRITICAL first)
- Colors: red for CRITICAL, red (non-bold) for HIGH, yellow for MEDIUM, cyan for LOW
- Masks secrets: shows first 4-6 and last 4-6 characters with asterisks in between
- Truncates commit SHAs to 8 characters for readability
- Shows entropy values when present
- Shows HIBP breach status and count when checked

**JSON reporter** (`json.go`):
- Produces a JSON object with `findings` array and `summary` object
- Each finding has: rule_id, description, severity, secret (masked), entropy, file, line, commit, author, hibp_status, breach_count
- Summary has: total_findings, total_rules, duration, hibp_checked, hibp_breached

**SARIF reporter** (`sarif.go`):
- Produces SARIF v2.1.0 compliant JSON
- Maps Portia severity to SARIF levels: CRITICAL/HIGH = "error", MEDIUM = "warning", LOW = "note"
- Each finding becomes a SARIF `result` with `ruleId`, `message`, `level`, and `locations`
- Rule definitions are included in the `tool.driver.rules` array
- Custom properties (entropy, HIBP status, masked secret) go in `result.properties`
