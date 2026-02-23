// ©AngelaMos | 2026
// registry.go

package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

type Registry struct {
	rules    map[string]*types.Rule
	disabled map[string]bool
}

func NewRegistry() *Registry {
	return &Registry{
		rules:    make(map[string]*types.Rule),
		disabled: make(map[string]bool),
	}
}

func (r *Registry) Register(rule *types.Rule) {
	if _, exists := r.rules[rule.ID]; exists {
		panic(fmt.Sprintf(
			"duplicate rule ID: %s", rule.ID,
		))
	}
	r.rules[rule.ID] = rule
}

func (r *Registry) Get(
	id string,
) (*types.Rule, bool) {
	rule, ok := r.rules[id]
	if !ok || r.disabled[id] {
		return nil, false
	}
	return rule, true
}

func (r *Registry) All() []*types.Rule {
	result := make([]*types.Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		if !r.disabled[rule.ID] {
			result = append(result, rule)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

func (r *Registry) Disable(ids ...string) {
	for _, id := range ids {
		r.disabled[id] = true
	}
}

func (r *Registry) MatchKeywords(
	content string,
) []*types.Rule {
	lower := strings.ToLower(content)
	var matched []*types.Rule

	for _, rule := range r.rules {
		if r.disabled[rule.ID] {
			continue
		}
		for _, kw := range rule.Keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				matched = append(matched, rule)
				break
			}
		}
	}
	return matched
}

func (r *Registry) Len() int {
	count := 0
	for id := range r.rules {
		if !r.disabled[id] {
			count++
		}
	}
	return count
}

func (r *Registry) Replace(rule *types.Rule) {
	r.rules[rule.ID] = rule
}

var GlobalPathAllowlist = []*regexp.Regexp{
	regexp.MustCompile(
		`go\.(?:mod|sum|work(?:\.sum)?)$`,
	),
	regexp.MustCompile(
		`(?:^|/)(?:package-lock\.json|pnpm-lock\.yaml|` +
			`yarn\.lock|npm-shrinkwrap\.json|deno\.lock|` +
			`Cargo\.lock|composer\.lock|Gemfile\.lock|` +
			`poetry\.lock|Pipfile\.lock|mix\.lock|` +
			`pubspec\.lock|Podfile\.lock|flake\.lock|` +
			`bun\.lockb)$`,
	),
	regexp.MustCompile(`(?:^|/)node_modules/`),
	regexp.MustCompile(`(?:^|/)vendor/`),
	regexp.MustCompile(`(?:^|/)\.git/`),
	regexp.MustCompile(`(?:^|/)\.svn/`),
	regexp.MustCompile(`(?:^|/)\.hg/`),
	regexp.MustCompile(
		`(?:^|/)(?:__pycache__|\.venv|venv|\.tox|` +
			`\.mypy_cache|\.pytest_cache|\.ruff_cache|` +
			`\.eggs|.*\.egg-info)/`,
	),
	regexp.MustCompile(
		`(?:^|/)(?:\.next|\.nuxt|\.svelte-kit|` +
			`\.terraform|\.gradle|\.mvn|\.bundle|` +
			`Pods|coverage|\.nyc_output)/`,
	),
	regexp.MustCompile(
		`(?:^|/)(?:target|build|dist|out)/`,
	),
	regexp.MustCompile(
		`\.min\.(?:js|css)(?:\.map)?$`,
	),
	regexp.MustCompile(
		`\.(?:png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|otf|` +
			`mp[34]|avi|mkv|mov|zip|tar|gz|rar|7z|pdf|exe|` +
			`dll|so|dylib)$`,
	),
	regexp.MustCompile(`dist-info/`),
}

var GlobalValueAllowlist = []*regexp.Regexp{
	regexp.MustCompile(
		`(?i)^(?:example|test|dummy|fake|placeholder|` +
			`sample|your[-_]?(?:api[-_]?key|token|` +
			`secret|password))`,
	),
	regexp.MustCompile(`^x{4,}$`),
	regexp.MustCompile(`^\*{4,}$`),
	regexp.MustCompile(`^\$\{.+\}$`),
	regexp.MustCompile(`^\{\{.+\}\}$`),
	regexp.MustCompile(`^<[A-Z_]{2,}>$`),
	regexp.MustCompile(`^0{8,}$`),
	regexp.MustCompile(
		`^(?:1{8,}|2{8,}|3{8,}|4{8,}|5{8,}|6{8,}|7{8,}|8{8,}|9{8,})$`,
	),
	regexp.MustCompile(
		`(?i)^(?:none|null|nil|undefined|true|false|` +
			`TODO|FIXME|CHANGEME|INSERT|REPLACE|` +
			`REDACTED|N/A|TBD|REMOVED|MASKED|` +
			`changeit|s3cr3t|p@ssw0rd|admin123)$`,
	),
	regexp.MustCompile(
		`(?i)^(?:dGVzdA==|cGFzc3dvcmQ=|YWRtaW4=)$`,
	),
	regexp.MustCompile(
		`(?i)^(?:PUT_YOUR_|ENTER_YOUR_|ADD_YOUR_)`,
	),
}
