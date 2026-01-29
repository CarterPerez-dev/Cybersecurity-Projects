// ©AngelaMos | 2026
// writer_test.go

package requirements

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateFile(t *testing.T) {
	t.Parallel()

	content := `# Core deps
django>=3.2.0
requests==2.28.1  # HTTP client
flask>=2.0.0
`

	path := filepath.Join(t.TempDir(), "requirements.txt")
	os.WriteFile(path, []byte(content), 0o600) //nolint:errcheck

	updates := map[string]string{
		"django":   ">=6.0.1",
		"requests": ">=2.32.5",
	}

	if err := UpdateFile(path, updates); err != nil {
		t.Fatalf("UpdateFile: %v", err)
	}

	data, _ := os.ReadFile(path) //nolint:errcheck,gosec
	result := string(data)

	if !strings.Contains(result, "django>=6.0.1") {
		t.Error("django not updated")
	}
	if !strings.Contains(result, "requests>=2.32.5") {
		t.Error("requests not updated")
	}
	if !strings.Contains(result, "# Core deps") {
		t.Error("comment lost")
	}
	if !strings.Contains(result, "# HTTP client") {
		t.Error("inline comment lost")
	}
	if !strings.Contains(result, "flask>=2.0.0") {
		t.Error("flask was incorrectly modified")
	}
}

func TestUpdateFilePreservesFormatting(t *testing.T) {
	t.Parallel()

	content := "Django>=3.2.0\nnumpy==1.24.0\n"
	path := filepath.Join(t.TempDir(), "requirements.txt")
	os.WriteFile(path, []byte(content), 0o600) //nolint:errcheck

	updates := map[string]string{
		"django": ">=6.0.1",
	}

	if err := UpdateFile(path, updates); err != nil {
		t.Fatalf("UpdateFile: %v", err)
	}

	data, _ := os.ReadFile(path) //nolint:errcheck,gosec
	result := string(data)

	if !strings.Contains(result, "Django>=6.0.1") {
		t.Error("original casing not preserved")
	}
	if !strings.Contains(result, "numpy==1.24.0") {
		t.Error("numpy was incorrectly modified")
	}
}

func TestUpdateFileNotFound(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "requirements.txt")
	os.WriteFile(path, []byte("flask>=2.0.0\n"), 0o600) //nolint:errcheck

	err := UpdateFile(path, map[string]string{
		"nonexistent": ">=1.0.0",
	})
	if err == nil {
		t.Error("expected error for missing dependency")
	}
}
