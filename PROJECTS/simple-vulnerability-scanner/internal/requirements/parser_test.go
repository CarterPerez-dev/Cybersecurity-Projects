// ©AngelaMos | 2026
// parser_test.go

package requirements

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFile(t *testing.T) {
	t.Parallel()

	content := `# Core deps
django>=3.2.0
requests==2.28.1
flask>=2.0,<3.0
numpy  # pinned
click[extra]>=8.0.0; python_version>="3.8"

# Options to skip
-r other.txt
-e ./local-pkg
--index-url https://pypi.org/simple/
`

	path := filepath.Join(t.TempDir(), "requirements.txt")
	os.WriteFile(path, []byte(content), 0o600) //nolint:errcheck

	deps, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if len(deps) != 5 {
		t.Fatalf("len = %d, want 5", len(deps))
	}

	tests := []struct {
		name string
		spec string
	}{
		{"django", ">=3.2.0"},
		{"requests", "==2.28.1"},
		{"flask", ">=2.0,<3.0"},
		{"numpy", ""},
		{"click", ">=8.0.0"},
	}

	for i, tt := range tests {
		if deps[i].Name != tt.name {
			t.Errorf("deps[%d].Name = %q, want %q", i, deps[i].Name, tt.name)
		}
		if deps[i].Spec != tt.spec {
			t.Errorf("deps[%d].Spec = %q, want %q", i, deps[i].Spec, tt.spec)
		}
	}
}

func TestParseFileExtras(t *testing.T) {
	t.Parallel()

	content := "requests[security,socks]>=2.28.0\n"
	path := filepath.Join(t.TempDir(), "requirements.txt")
	os.WriteFile(path, []byte(content), 0o600) //nolint:errcheck

	deps, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if len(deps) != 1 {
		t.Fatalf("len = %d, want 1", len(deps))
	}

	if len(deps[0].Extras) != 2 {
		t.Fatalf("extras len = %d, want 2", len(deps[0].Extras))
	}
	if deps[0].Extras[0] != "security" || deps[0].Extras[1] != "socks" {
		t.Errorf("extras = %v, want [security socks]", deps[0].Extras)
	}
}

func TestParseFileMarkers(t *testing.T) {
	t.Parallel()

	content := "pywin32>=300; sys_platform==\"win32\"\n"
	path := filepath.Join(t.TempDir(), "requirements.txt")
	os.WriteFile(path, []byte(content), 0o600) //nolint:errcheck

	deps, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if deps[0].Markers != `sys_platform=="win32"` {
		t.Errorf("markers = %q, want sys_platform==\"win32\"", deps[0].Markers)
	}
}

func TestParseFileEmpty(t *testing.T) {
	t.Parallel()

	content := "# just comments\n\n-r other.txt\n"
	path := filepath.Join(t.TempDir(), "requirements.txt")
	os.WriteFile(path, []byte(content), 0o600) //nolint:errcheck

	_, err := ParseFile(path)
	if err == nil {
		t.Error("expected error for empty requirements")
	}
}

func TestParseFileNotFound(t *testing.T) {
	t.Parallel()

	_, err := ParseFile("/nonexistent/requirements.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
