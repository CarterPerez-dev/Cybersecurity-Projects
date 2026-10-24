// ©AngelaMos | 2026
// bundle_test.go

package khaos

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestBundledRangeWorksWithoutACheckout(t *testing.T) {
	parent := t.TempDir()
	directory, err := cacheRange(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"range/compose.yml", "range/Dockerfile", "go.mod", "go.sum",
		"bundle.go", "cmd/khaos-range/main.go", "internal/dnsrv/resolver.go",
	} {
		if _, err := os.Stat(
			filepath.Join(filepath.Dir(directory), name),
		); err != nil {
			t.Fatalf("missing runtime source %s: %v", name, err)
		}
	}
	again, err := cacheRange(parent)
	if err != nil || again != directory {
		t.Fatalf("reusing range: %q, %v", again, err)
	}
	for _, name := range []string{"docs", "learn", ".git", "scripts"} {
		if _, err := os.Stat(
			filepath.Join(filepath.Dir(directory), name),
		); !os.IsNotExist(
			err,
		) {
			t.Fatalf("unexpected development content %s: %v", name, err)
		}
	}
}

func TestModifiedRangeCacheIsRefused(t *testing.T) {
	for _, change := range []string{"modified file", "extra file", "symlink"} {
		t.Run(change, func(t *testing.T) {
			parent := t.TempDir()
			directory, err := cacheRange(parent)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "compose.yml")
			switch change {
			case "modified file":
				err = os.WriteFile(path, []byte("name: somebody-else\n"), 0o600)
			case "extra file":
				err = os.WriteFile(
					filepath.Join(directory, "extra"),
					nil,
					0o600,
				)
			case "symlink":
				if err = os.Remove(path); err == nil {
					err = os.Symlink(
						filepath.Join(t.TempDir(), "foreign"),
						path,
					)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cacheRange(parent); err == nil {
				t.Fatal("modified range source was accepted")
			}
		})
	}
}

func TestConcurrentRangeExtractionIsAtomic(t *testing.T) {
	const count = 6
	parent := t.TempDir()
	directories := make([]string, count)
	errors := make([]error, count)
	var workers sync.WaitGroup
	for index := range count {
		workers.Go(func() {
			directories[index], errors[index] = cacheRange(parent)
		})
	}
	workers.Wait()
	for index := range count {
		if errors[index] != nil || directories[index] != directories[0] {
			t.Fatalf(
				"worker %d: %q, %v",
				index,
				directories[index],
				errors[index],
			)
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".unpack-") {
			t.Fatalf("unfinished extraction survived: %s", entry.Name())
		}
	}
}
