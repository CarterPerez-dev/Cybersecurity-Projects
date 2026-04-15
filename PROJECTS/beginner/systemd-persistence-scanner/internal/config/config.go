/*
©AngelaMos | 2026
config.go

Ignore-list configuration for suppressing known-good findings

Loads a YAML ignore file that specifies findings to suppress by
path, scanner name, title, or combinations thereof. Reduces noise
on systems with many legitimate persistence entries.
*/

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

type IgnoreRule struct {
	Path    string
	Scanner string
	Title   string
}

type IgnoreList struct {
	Rules []IgnoreRule
}

func LoadIgnoreFile(path string) (IgnoreList, error) {
	if path == "" {
		return IgnoreList{}, nil
	}

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return IgnoreList{}, fmt.Errorf(
			"reading ignore file: %w", err,
		)
	}

	return parseIgnoreFile(data)
}

func parseIgnoreFile(data []byte) (IgnoreList, error) {
	var list IgnoreList
	var current IgnoreRule
	inIgnore := false

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "ignore:" {
			inIgnore = true
			continue
		}

		if !inIgnore {
			continue
		}

		if strings.HasPrefix(line, "- ") {
			list.Rules = appendIfSet(list.Rules, current)
			current = IgnoreRule{}
			line = strings.TrimPrefix(line, "- ")
		} else if !isIndented(line, rawLine) {
			list.Rules = appendIfSet(list.Rules, current)
			break
		}

		parseField(&current, strings.TrimSpace(line))
	}

	list.Rules = appendIfSet(list.Rules, current)
	return list, nil
}

func isIndented(trimmed, raw string) bool {
	return strings.HasPrefix(trimmed, "  ") ||
		strings.HasPrefix(raw, "  ")
}

func appendIfSet(
	rules []IgnoreRule, r IgnoreRule,
) []IgnoreRule {
	if r.Path != "" || r.Scanner != "" || r.Title != "" {
		return append(rules, r)
	}
	return rules
}

func parseField(rule *IgnoreRule, line string) {
	key, val, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	val = strings.TrimSpace(val)

	switch strings.TrimSpace(key) {
	case "path":
		rule.Path = val
	case "scanner":
		rule.Scanner = val
	case "title":
		rule.Title = val
	}
}

func (il IgnoreList) Filter(
	findings []types.Finding,
) []types.Finding {
	if len(il.Rules) == 0 {
		return findings
	}

	var kept []types.Finding
	for _, f := range findings {
		if !il.matches(f) {
			kept = append(kept, f)
		}
	}
	return kept
}

func (il IgnoreList) matches(f types.Finding) bool {
	for _, r := range il.Rules {
		if r.matchesFinding(f) {
			return true
		}
	}
	return false
}

func (r IgnoreRule) matchesFinding(f types.Finding) bool {
	if r.Path != "" && f.Path != r.Path {
		return false
	}
	if r.Scanner != "" && f.Scanner != r.Scanner {
		return false
	}
	if r.Title != "" && f.Title != r.Title {
		return false
	}
	return true
}
