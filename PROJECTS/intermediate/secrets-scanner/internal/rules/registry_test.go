// ©AngelaMos | 2026
// registry_test.go

package rules

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

func testRule(id string, keywords []string) *types.Rule {
	return &types.Rule{
		ID:       id,
		Keywords: keywords,
		Pattern:  regexp.MustCompile(`test`),
		Severity: types.SeverityHigh,
	}
}

func TestRegistryRegisterAndGet(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	rule := testRule("test-rule", []string{"test"})
	reg.Register(rule)

	got, ok := reg.Get("test-rule")
	require.True(t, ok)
	assert.Equal(t, "test-rule", got.ID)
}

func TestRegistryGetMissing(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	_, ok := reg.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistryDuplicatePanics(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	rule := testRule("dup", []string{"test"})
	reg.Register(rule)

	assert.Panics(t, func() {
		reg.Register(testRule("dup", []string{"test"}))
	})
}

func TestRegistryAll(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register(testRule("b-rule", []string{"b"}))
	reg.Register(testRule("a-rule", []string{"a"}))
	reg.Register(testRule("c-rule", []string{"c"}))

	all := reg.All()
	require.Len(t, all, 3)
	assert.Equal(t, "a-rule", all[0].ID)
	assert.Equal(t, "b-rule", all[1].ID)
	assert.Equal(t, "c-rule", all[2].ID)
}

func TestRegistryDisable(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register(testRule("keep", []string{"a"}))
	reg.Register(testRule("drop", []string{"b"}))

	reg.Disable("drop")

	_, ok := reg.Get("drop")
	assert.False(t, ok)

	all := reg.All()
	require.Len(t, all, 1)
	assert.Equal(t, "keep", all[0].ID)
}

func TestRegistryMatchKeywords(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register(
		testRule("aws", []string{"AKIA", "aws"}),
	)
	reg.Register(
		testRule("github", []string{"ghp_"}),
	)
	reg.Register(
		testRule("stripe", []string{"sk_live_"}),
	)

	tests := map[string]struct {
		content  string
		wantIDs  []string
		wantNone bool
	}{
		"matches aws by AKIA prefix": { //nolint:gosec
			content: "found AKIAIOSFODNN7EXAMPLE in config",
			wantIDs: []string{"aws"},
		},
		"matches github token": {
			content: "token = ghp_abc123def456",
			wantIDs: []string{"github"},
		},
		"matches multiple rules": {
			content: "aws key AKIA and ghp_ token here",
			wantIDs: []string{"aws", "github"},
		},
		"case insensitive matching": {
			content: "AWS_ACCESS_KEY with akia prefix",
			wantIDs: []string{"aws"},
		},
		"no matches on unrelated content": {
			content:  "just some normal code here",
			wantNone: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			matched := reg.MatchKeywords(tc.content)
			if tc.wantNone {
				assert.Empty(t, matched)
				return
			}
			ids := make([]string, len(matched))
			for i, r := range matched {
				ids[i] = r.ID
			}
			for _, wantID := range tc.wantIDs {
				assert.Contains(t, ids, wantID)
			}
		})
	}
}

func TestRegistryMatchKeywordsSkipsDisabled(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register(
		testRule("enabled", []string{"secret"}),
	)
	reg.Register(
		testRule("disabled", []string{"secret"}),
	)
	reg.Disable("disabled")

	matched := reg.MatchKeywords("my secret value")
	require.Len(t, matched, 1)
	assert.Equal(t, "enabled", matched[0].ID)
}

func TestRegistryLen(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register(testRule("a", []string{"a"}))
	reg.Register(testRule("b", []string{"b"}))
	assert.Equal(t, 2, reg.Len())

	reg.Disable("a")
	assert.Equal(t, 1, reg.Len())
}

func TestRegistryReplace(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register(testRule("r", []string{"old"}))

	newRule := testRule("r", []string{"new"})
	newRule.Description = "replaced"
	reg.Replace(newRule)

	got, ok := reg.Get("r")
	require.True(t, ok)
	assert.Equal(t, "replaced", got.Description)
}

func TestGlobalPathAllowlist(t *testing.T) {
	t.Parallel()

	allowed := []string{
		"go.sum",
		"go.mod",
		"package-lock.json",
		"pnpm-lock.yaml",
		"node_modules/pkg/index.js",
		"vendor/lib/code.go",
		".git/objects/pack/abc",
		"dist/bundle.min.js",
		"assets/logo.png",
		"data/file.pdf",
		"Cargo.lock",
		"composer.lock",
		"Gemfile.lock",
		"poetry.lock",
		"Pipfile.lock",
		"bun.lockb",
		".svn/entries",
		".hg/store/data",
		"__pycache__/module.cpython-313.pyc",
		".mypy_cache/3.13/module.meta.json",
		".next/server/pages/index.html",
		".terraform/providers/registry.terraform.io",
		"target/debug/build/crate/output",
		"dist/bundle.min.css",
		"dist/bundle.min.css.map",
		"assets/font.otf",
	}

	blocked := []string{
		"src/main.go",
		"config.yaml",
		".env",
		"internal/auth/handler.go",
	}

	for _, path := range allowed {
		matched := false
		for _, re := range GlobalPathAllowlist {
			if re.MatchString(path) {
				matched = true
				break
			}
		}
		assert.True(t, matched,
			"expected %s to be allowlisted", path)
	}

	for _, path := range blocked {
		matched := false
		for _, re := range GlobalPathAllowlist {
			if re.MatchString(path) {
				matched = true
				break
			}
		}
		assert.False(t, matched,
			"expected %s to NOT be allowlisted", path)
	}
}

func TestGlobalValueAllowlist(t *testing.T) {
	t.Parallel()

	allowed := []string{
		"EXAMPLE_KEY",
		"test_token",
		"your-api-key",
		"placeholder",
		"xxxxxxxxxxxx",
		"****",
		"${SECRET_KEY}",
		"{{api_token}}",
		"CHANGEME",
		"none",
		"undefined",
		"<YOUR_API_KEY>",
		"<REPLACE_ME>",
		"<INSERT_TOKEN>",
		"00000000000000000000",
		"1111111111111111",
		"REDACTED",
		"N/A",
		"TBD",
		"REMOVED",
		"MASKED",
		"changeit",
		"PUT_YOUR_KEY_HERE",
		"ENTER_YOUR_TOKEN_HERE",
		"dGVzdA==",
		"cGFzc3dvcmQ=",
	}

	blocked := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"sk_live_4eC39HqLyjWDarjtT1",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZab",
		"xK9mP2vL5nQ8",
	}

	for _, val := range allowed {
		matched := false
		for _, re := range GlobalValueAllowlist {
			if re.MatchString(val) {
				matched = true
				break
			}
		}
		assert.True(t, matched,
			"expected %q to be allowlisted", val)
	}

	for _, val := range blocked {
		matched := false
		for _, re := range GlobalValueAllowlist {
			if re.MatchString(val) {
				matched = true
				break
			}
		}
		assert.False(t, matched,
			"expected %q to NOT be allowlisted", val)
	}
}
