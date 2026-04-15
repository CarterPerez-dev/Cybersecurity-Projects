/*
©AngelaMos | 2026
helpers_test.go
*/

package scanner

import (
	"os"
	"testing"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(
		path, []byte(content), 0o600,
	); err != nil {
		t.Fatalf("writing test file %s: %v", path, err)
	}
}
