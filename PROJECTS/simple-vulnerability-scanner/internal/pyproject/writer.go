// ©AngelaMos | 2026
// writer.go

package pyproject

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/CarterPerez-dev/angela/internal/pypi"
	toml "github.com/pelletier/go-toml/v2"
)

// Updater performs surgical edits on raw pyproject.toml bytes, preserving
// all comments, whitespace, and key ordering
type Updater struct {
	content []byte
}

// NewUpdater wraps raw file content after validating it as syntactically
// correct TOML
func NewUpdater(content []byte) (*Updater, error) {
	var probe map[string]any
	if err := toml.Unmarshal(content, &probe); err != nil {
		return nil, fmt.Errorf("invalid TOML: %w", err)
	}
	return &Updater{content: content}, nil
}

// UpdateDependency replaces the version specifier for a single dependency
// while preserving quotes, extras, markers, and surrounding formatting.
// Tries double-quote patterns first, then single-quote.
func (u *Updater) UpdateDependency(pkg, newSpec string) error {
	for _, q := range []byte{'"', '\''} {
		pattern := buildDepPattern(pkg, q)
		found := false
		u.content = pattern.ReplaceAllFunc(
			u.content,
			func(match []byte) []byte {
				found = true
				return replaceSpec(pattern, match, newSpec, q)
			},
		)
		if found {
			var probe map[string]any
			if err := toml.Unmarshal(u.content, &probe); err != nil {
				return fmt.Errorf(
					"update produced invalid TOML: %w", err,
				)
			}
			return nil
		}
	}
	return fmt.Errorf("dependency %q not found", pkg)
}

// Bytes returns the current file content
func (u *Updater) Bytes() []byte {
	return u.content
}

// WriteFile atomically writes the updated content to disk
func (u *Updater) WriteFile(path string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, u.content, 0o600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) //nolint:errcheck
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func buildDepPattern(name string, quote byte) *regexp.Regexp {
	normalized := pypi.NormalizeName(name)
	parts := strings.Split(normalized, "-")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	namePattern := strings.Join(parts, `[-_.]?`)

	q := string(quote)
	notQ := `[^` + q + `]`

	return regexp.MustCompile(
		`(?i)` +
			q +
			`(` + namePattern + `)` +
			`(\[[^\]]*\])?` +
			`(\s*[><=!~]` + notQ + `*?)` +
			`(;` + notQ + `*)?` +
			q,
	)
}

func replaceSpec(
	re *regexp.Regexp, match []byte, newSpec string, quote byte,
) []byte {
	groups := re.FindSubmatch(match)
	if len(groups) < 5 {
		return match
	}

	name := groups[1]
	extras := groups[2]
	markers := groups[4]

	var b []byte
	b = append(b, quote)
	b = append(b, name...)
	b = append(b, extras...)
	b = append(b, []byte(newSpec)...)
	b = append(b, markers...)
	b = append(b, quote)
	return b
}

// UpdateFile is a convenience that reads, updates all given dependencies,
// and writes back atomically
func UpdateFile(path string, updates map[string]string) error {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	u, err := NewUpdater(data)
	if err != nil {
		return err
	}

	for pkg, spec := range updates {
		if err := u.UpdateDependency(pkg, spec); err != nil {
			return fmt.Errorf("update %s: %w", pkg, err)
		}
	}

	return u.WriteFile(path)
}
