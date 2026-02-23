// ©AngelaMos | 2026
// filter_test.go

package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CarterPerez-dev/portia/internal/rules"
	"github.com/CarterPerez-dev/portia/pkg/types"
)

func TestIsStopword(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		secret string
		extra  []string
		want   bool
	}{
		"exact stopword": {
			secret: "cache",
			want:   true,
		},
		"contains stopword substring": { //nolint:gosec
			secret: "admin_cache_key_value",
			want:   true,
		},
		"random high entropy secret": { //nolint:gosec
			secret: "xK9mP2vL5nQ8jR3t",
			want:   false,
		},
		"extra stopwords match": {
			secret: "myCustomWord123",
			extra:  []string{"custom"},
			want:   true,
		},
		"short stopword ignored": {
			secret: "abcXYZ",
			extra:  []string{"ab"},
			want:   false,
		},
		"real api key not stopped": { //nolint:gosec
			secret: "AKIAIOSFODNN7EXAMPLE",
			want:   false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := IsStopword(tc.secret, tc.extra)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsPlaceholder(t *testing.T) { //nolint:dupl
	t.Parallel()

	tests := map[string]struct {
		secret string
		want   bool
	}{
		"example key": {
			secret: "EXAMPLE_KEY",
			want:   true,
		},
		"your-api-key": {
			secret: "your-api-key",
			want:   true,
		},
		"placeholder": {
			secret: "placeholder",
			want:   true,
		},
		"xxxx pattern": {
			secret: "xxxxxxxxxxxx",
			want:   true,
		},
		"stars pattern": {
			secret: "****",
			want:   true,
		},
		"template var dollar": { //nolint:gosec
			secret: "${SECRET_KEY}",
			want:   true,
		},
		"template var braces": { //nolint:gosec
			secret: "{{api_token}}",
			want:   true,
		},
		"CHANGEME": {
			secret: "CHANGEME",
			want:   true,
		},
		"none": {
			secret: "none",
			want:   true,
		},
		"real secret not placeholder": { //nolint:gosec
			secret: "sk_live_4eC39HqLyjWDarjtT1",
			want:   false,
		},
		"real aws key not placeholder": { //nolint:gosec
			secret: "AKIAIOSFODNN7ABCDEFG",
			want:   false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := IsPlaceholder(tc.secret)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsTemplated(t *testing.T) { //nolint:dupl
	t.Parallel()

	tests := map[string]struct {
		secret string
		want   bool
	}{
		"dollar brace": {
			secret: "${DB_PASSWORD}",
			want:   true,
		},
		"double brace": { //nolint:gosec
			secret: "{{api_key}}",
			want:   true,
		},
		"os getenv": { //nolint:gosec
			secret: `os.Getenv("SECRET_KEY")`,
			want:   true,
		},
		"process env": { //nolint:gosec
			secret: "process.env.API_KEY",
			want:   true,
		},
		"system getenv": { //nolint:gosec
			secret: `System.getenv("TOKEN")`,
			want:   true,
		},
		"ruby env": { //nolint:gosec
			secret: `ENV["SECRET"]`,
			want:   true,
		},
		"real secret": {
			secret: "ghp_ABCDEFabcdef1234567890GHIJKL",
			want:   false,
		},
		"viper get": {
			secret: `viper.GetString("api_key")`,
			want:   true,
		},
		"python config get": { //nolint:gosec
			secret: `config.get("secret")`,
			want:   true,
		},
		"spring value annotation": { //nolint:gosec
			secret: `@Value("${db.password}")`,
			want:   true,
		},
		"helm template": {
			secret: `{{ .Values.secretKey }}`,
			want:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := IsTemplated(tc.secret)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHasAssignmentOperator(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		line string
		want bool
	}{
		"equals sign": {
			line: `password = "secret123"`,
			want: true,
		},
		"colon": {
			line: `token: sk_live_abc123def456`,
			want: true,
		},
		"walrus operator": {
			line: `key := "some_value"`,
			want: true,
		},
		"arrow function": {
			line: `secret => "value"`,
			want: true,
		},
		"function call no operator": {
			line: `getPassword(name)`,
			want: false,
		},
		"import statement": {
			line: `import password_module`,
			want: false,
		},
		"just a variable name": {
			line: `password_variable`,
			want: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := HasAssignmentOperator(tc.line)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsAllowedPath(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path string
		want bool
	}{
		"go.sum": {
			path: "go.sum",
			want: true,
		},
		"package-lock": {
			path: "package-lock.json",
			want: true,
		},
		"node_modules": {
			path: "node_modules/pkg/index.js",
			want: true,
		},
		"vendor": {
			path: "vendor/lib/code.go",
			want: true,
		},
		"git objects": {
			path: ".git/objects/pack/abc",
			want: true,
		},
		"minified js": {
			path: "dist/bundle.min.js",
			want: true,
		},
		"png image": {
			path: "assets/logo.png",
			want: true,
		},
		"source code not allowed": {
			path: "src/main.go",
			want: false,
		},
		"config file not allowed": {
			path: "config.yaml",
			want: false,
		},
		"env file not allowed": {
			path: ".env",
			want: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := IsAllowedPath(
				tc.path,
				rules.GlobalPathAllowlist,
			)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFilterFinding(t *testing.T) {
	t.Parallel()

	emptyRule := &types.Rule{
		Allowlist: types.Allowlist{},
	}

	tests := map[string]struct {
		finding *types.Finding
		rule    *types.Rule
		want    bool
	}{
		"real secret passes filter": {
			finding: &types.Finding{ //nolint:gosec
				Secret:   "AKIAIOSFODNN7ABCDEFG",
				FilePath: "src/config.py",
			},
			rule: emptyRule,
			want: true,
		},
		"placeholder filtered out": {
			finding: &types.Finding{
				Secret:   "your-api-key-here",
				FilePath: "src/config.py",
			},
			rule: emptyRule,
			want: false,
		},
		"template filtered out": {
			finding: &types.Finding{ //nolint:gosec
				Secret:   "${SECRET_KEY}",
				FilePath: "src/config.py",
			},
			rule: emptyRule,
			want: false,
		},
		"allowed path filtered out": {
			finding: &types.Finding{
				Secret:   "real_secret_value_here",
				FilePath: "go.sum",
			},
			rule: emptyRule,
			want: false,
		},
		"stopword filtered out": {
			finding: &types.Finding{
				Secret:   "admin_endpoint_builder",
				FilePath: "src/config.py",
			},
			rule: emptyRule,
			want: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := FilterFinding(tc.finding, tc.rule)
			assert.Equal(t, tc.want, got)
		})
	}
}
