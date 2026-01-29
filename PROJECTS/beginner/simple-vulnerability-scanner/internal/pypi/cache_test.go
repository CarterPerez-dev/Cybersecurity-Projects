// ©AngelaMos | 2026
// cache_test.go

package pypi

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheGetSetRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache, err := NewCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	entry := &CacheEntry{
		ETag:     `"abc123"`,
		Versions: []string{"1.0", "1.1", "2.0"},
		CachedAt: time.Now(),
	}

	if err := cache.Set("requests", entry); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, ok := cache.Get("requests")
	if !ok {
		t.Fatal("Get returned false after Set")
	}
	if got.ETag != entry.ETag {
		t.Errorf("ETag = %q, want %q", got.ETag, entry.ETag)
	}
	if len(got.Versions) != len(entry.Versions) {
		t.Fatalf(
			"Versions len = %d, want %d",
			len(got.Versions), len(entry.Versions),
		)
	}
	for i, v := range got.Versions {
		if v != entry.Versions[i] {
			t.Errorf(
				"Versions[%d] = %q, want %q",
				i, v, entry.Versions[i],
			)
		}
	}
}

func TestCacheGetMiss(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache, err := NewCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	_, ok := cache.Get("nonexistent")
	if ok {
		t.Fatal("Get returned true for missing key")
	}
}

func TestCacheIsFresh(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache, err := NewCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	fresh := &CacheEntry{CachedAt: time.Now()}
	if !cache.IsFresh(fresh) {
		t.Error("entry cached just now should be fresh")
	}

	stale := &CacheEntry{
		CachedAt: time.Now().Add(-2 * time.Hour),
	}
	if cache.IsFresh(stale) {
		t.Error("entry cached 2 hours ago should be stale")
	}
}

func TestCacheTouch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache, err := NewCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	old := time.Now().Add(-30 * time.Minute)
	entry := &CacheEntry{
		ETag:     `"xyz"`,
		Versions: []string{"1.0"},
		CachedAt: old,
	}
	if err := cache.Set("flask", entry); err != nil {
		t.Fatalf("Set: %v", err)
	}

	cache.Touch("flask")

	got, ok := cache.Get("flask")
	if !ok {
		t.Fatal("Get returned false after Touch")
	}
	if !got.CachedAt.After(old) {
		t.Error("Touch did not update CachedAt")
	}
}

func TestCacheClear(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache, err := NewCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	for _, name := range []string{"a", "b", "c"} {
		setErr := cache.Set(name, &CacheEntry{
			Versions: []string{"1.0"},
			CachedAt: time.Now(),
		})
		if setErr != nil {
			t.Fatalf("Set %s: %v", name, setErr)
		}
	}

	if clearErr := cache.Clear(); clearErr != nil {
		t.Fatalf("Clear: %v", clearErr)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	jsonCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			jsonCount++
		}
	}
	if jsonCount != 0 {
		t.Errorf("Clear left %d .json files", jsonCount)
	}
}

func TestCachePathTraversal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache, err := NewCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	entry := &CacheEntry{
		Versions: []string{"1.0"},
		CachedAt: time.Now(),
	}
	if err := cache.Set("../../../etc/passwd", entry); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, ok := cache.Get("../../../etc/passwd")
	if !ok {
		t.Fatal("Get returned false for traversal key")
	}
	if got.Versions[0] != "1.0" {
		t.Error("wrong version returned")
	}

	path := filepath.Join(dir, "passwd.json")
	if _, err := os.Stat(path); err != nil {
		t.Errorf(
			"expected file at safe path %s, got: %v",
			path, err,
		)
	}

	unsafePath := filepath.Join(
		dir, "../../../etc/passwd.json",
	)
	if _, err := os.Stat(unsafePath); err == nil {
		t.Error("file created at unsafe traversal path")
	}
}
