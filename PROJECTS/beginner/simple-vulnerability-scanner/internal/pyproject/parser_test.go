// ©AngelaMos | 2026
// parser_test.go

package pyproject

import (
	"testing"
)

//nolint:gocognit,funlen
func TestParseDependency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantPkg string
		wantSpc string
		extras  []string
		markers string
	}{
		{
			name:    "simple with lower bound",
			input:   "requests>=2.28.0",
			wantPkg: "requests",
			wantSpc: ">=2.28.0",
		},
		{
			name:    "range constraint",
			input:   "django>=3.2,<4.0",
			wantPkg: "django",
			wantSpc: ">=3.2,<4.0",
		},
		{
			name:    "extras",
			input:   "flask[async]>=2.0",
			wantPkg: "flask",
			wantSpc: ">=2.0",
			extras:  []string{"async"},
		},
		{
			name:    "multiple extras",
			input:   "requests[security, socks]>=2.28.0",
			wantPkg: "requests",
			wantSpc: ">=2.28.0",
			extras:  []string{"security", "socks"},
		},
		{
			name:    "markers",
			input:   `pandas>=1.5; python_version>='3.8'`,
			wantPkg: "pandas",
			wantSpc: ">=1.5",
			markers: "python_version>='3.8'",
		},
		{
			name:    "bare name no version",
			input:   "numpy",
			wantPkg: "numpy",
			wantSpc: "",
		},
		{
			name:    "exact pin",
			input:   "black==23.7.0",
			wantPkg: "black",
			wantSpc: "==23.7.0",
		},
		{
			name:    "compatible release",
			input:   "setuptools~=68.0",
			wantPkg: "setuptools",
			wantSpc: "~=68.0",
		},
		{
			name:    "not equal",
			input:   "urllib3!=2.0.0",
			wantPkg: "urllib3",
			wantSpc: "!=2.0.0",
		},
		{
			name:    "whitespace around",
			input:   "  click >= 8.0.0  ",
			wantPkg: "click",
			wantSpc: ">= 8.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dep := ParseDependency(tt.input, "")

			if dep.Name != tt.wantPkg {
				t.Errorf(
					"Name = %q, want %q", dep.Name, tt.wantPkg,
				)
			}
			if dep.Spec != tt.wantSpc {
				t.Errorf(
					"Spec = %q, want %q", dep.Spec, tt.wantSpc,
				)
			}
			if tt.markers != "" && dep.Markers != tt.markers {
				t.Errorf(
					"Markers = %q, want %q",
					dep.Markers, tt.markers,
				)
			}
			if len(tt.extras) > 0 {
				if len(dep.Extras) != len(tt.extras) {
					t.Fatalf(
						"Extras = %v, want %v",
						dep.Extras, tt.extras,
					)
				}
				for i, e := range tt.extras {
					if dep.Extras[i] != e {
						t.Errorf(
							"Extras[%d] = %q, want %q",
							i, dep.Extras[i], e,
						)
					}
				}
			}
		})
	}
}

func TestExtractMinVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		spec string
		want string
	}{
		{">=2.28.0", "2.28.0"},
		{">=3.2,<4.0", "3.2"},
		{"==23.7.0", "23.7.0"},
		{"==3.2.*", "3.2"},
		{"~=68.0", "68.0"},
		{"!=2.0", ""},
		{">1.0", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			t.Parallel()

			got := ExtractMinVersion(tt.spec)
			if got != tt.want {
				t.Errorf(
					"ExtractMinVersion(%q) = %q, want %q",
					tt.spec, got, tt.want,
				)
			}
		})
	}
}
