// ©AngelaMos | 2026
// writer_test.go

package pyproject

import (
	"strings"
	"testing"
)

const sampleTOML = `# Project configuration
[project]
name = "myapp"
version = "1.0.0"

# Core dependencies
dependencies = [
    "requests>=2.28.0",  # HTTP library
    "django>=3.2,<4.0",
    "flask[async]>=2.0",
    "numpy",
]

[project.optional-dependencies]
# Development tools
dev = [
    "pytest>=7.0.0",
    "black==23.7.0",  # Code formatter
]
`

func TestUpdaterPreservesComments(t *testing.T) {
	t.Parallel()

	u, err := NewUpdater([]byte(sampleTOML))
	if err != nil {
		t.Fatalf("NewUpdater error: %v", err)
	}

	if err := u.UpdateDependency("requests", ">=2.31.0"); err != nil {
		t.Fatalf("UpdateDependency error: %v", err)
	}

	result := string(u.Bytes())

	if !strings.Contains(result, `"requests>=2.31.0"`) {
		t.Error("version was not updated")
	}
	if !strings.Contains(result, "# HTTP library") {
		t.Error("inline comment was lost")
	}
	if !strings.Contains(result, "# Project configuration") {
		t.Error("header comment was lost")
	}
	if !strings.Contains(result, "# Core dependencies") {
		t.Error("section comment was lost")
	}
	if !strings.Contains(result, "# Development tools") {
		t.Error("optional-deps comment was lost")
	}
}

func TestUpdaterPreservesExtras(t *testing.T) {
	t.Parallel()

	u, err := NewUpdater([]byte(sampleTOML))
	if err != nil {
		t.Fatal(err)
	}

	if err := u.UpdateDependency("flask", ">=3.0"); err != nil {
		t.Fatal(err)
	}

	result := string(u.Bytes())
	if !strings.Contains(result, `"flask[async]>=3.0"`) {
		t.Errorf("extras lost or version not updated: %s", result)
	}
}

func TestUpdaterHandlesExactPin(t *testing.T) {
	t.Parallel()

	u, err := NewUpdater([]byte(sampleTOML))
	if err != nil {
		t.Fatal(err)
	}

	if err := u.UpdateDependency("black", ">=24.0.0"); err != nil {
		t.Fatal(err)
	}

	result := string(u.Bytes())
	if !strings.Contains(result, `"black>=24.0.0"`) {
		t.Errorf("exact pin not updated: %s", result)
	}
	if !strings.Contains(result, "# Code formatter") {
		t.Error("inline comment was lost")
	}
}

func TestUpdaterNotFound(t *testing.T) {
	t.Parallel()

	u, err := NewUpdater([]byte(sampleTOML))
	if err != nil {
		t.Fatal(err)
	}

	err = u.UpdateDependency("nonexistent", ">=1.0")
	if err == nil {
		t.Fatal("expected error for missing dependency")
	}
}

func TestUpdaterSkipsBareNames(t *testing.T) {
	t.Parallel()

	u, err := NewUpdater([]byte(sampleTOML))
	if err != nil {
		t.Fatal(err)
	}

	err = u.UpdateDependency("numpy", ">=1.26.0")
	if err == nil {
		t.Fatal("expected error: bare name has no version spec to match")
	}
}

func TestUpdaterMultipleUpdates(t *testing.T) {
	t.Parallel()

	u, err := NewUpdater([]byte(sampleTOML))
	if err != nil {
		t.Fatal(err)
	}

	updates := map[string]string{
		"requests": ">=2.31.0",
		"django":   ">=4.2.8",
		"pytest":   ">=8.0.0",
	}

	for pkg, spec := range updates {
		if err := u.UpdateDependency(pkg, spec); err != nil {
			t.Fatalf("update %s: %v", pkg, err)
		}
	}

	result := string(u.Bytes())

	if !strings.Contains(result, `"requests>=2.31.0"`) {
		t.Error("requests not updated")
	}
	if !strings.Contains(result, `"django>=4.2.8"`) {
		t.Error("django not updated")
	}
	if !strings.Contains(result, `"pytest>=8.0.0"`) {
		t.Error("pytest not updated")
	}

	if !strings.Contains(result, "# HTTP library") {
		t.Error("comment lost after multiple updates")
	}
	if !strings.Contains(result, "# Code formatter") {
		t.Error("comment lost after multiple updates")
	}
}

func TestUpdaterInvalidTOML(t *testing.T) {
	t.Parallel()

	_, err := NewUpdater([]byte(`[invalid`))
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}
