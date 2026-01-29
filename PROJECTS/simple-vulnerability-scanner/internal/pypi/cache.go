// ©AngelaMos | 2026
// cache.go

package pypi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// DefaultCacheTTL defines how long cached PyPI responses remain valid
const DefaultCacheTTL = 1 * time.Hour

// Cache provides file-backed storage for PyPI API responses with ETag support
type Cache struct {
	dir string
	ttl time.Duration
}

// CacheEntry holds a cached PyPI response alongside its freshness metadata
type CacheEntry struct {
	ETag     string    `json:"etag"`
	Versions []string  `json:"versions"`
	CachedAt time.Time `json:"cached_at"`
}

// NewCache creates a file-backed cache at the given directory
func NewCache(dir string, ttl time.Duration) (*Cache, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &Cache{dir: dir, ttl: ttl}, nil
}

// Get retrieves a cache entry by package name, returning false on miss
func (c *Cache) Get(key string) (*CacheEntry, bool) {
	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return nil, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}
	return &entry, true
}

// IsFresh reports whether the entry is still within its TTL window
func (c *Cache) IsFresh(entry *CacheEntry) bool {
	return time.Since(entry.CachedAt) <= c.ttl
}

// Set writes a cache entry atomically using rename-over-temp
func (c *Cache) Set(key string, entry *CacheEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(c.dir, "tmp-*.json")
	if err != nil {
		return err
	}

	if _, writeErr := tmp.Write(data); writeErr != nil {
		_ = tmp.Close()           //nolint:errcheck
		_ = os.Remove(tmp.Name()) //nolint:errcheck
		return writeErr
	}
	_ = tmp.Close() //nolint:errcheck

	return os.Rename(tmp.Name(), c.path(key))
}

// Touch refreshes the CachedAt timestamp without changing stored data
func (c *Cache) Touch(key string) {
	entry, ok := c.Get(key)
	if !ok {
		return
	}
	entry.CachedAt = time.Now()
	_ = c.Set(key, entry) //nolint:errcheck
}

// Clear removes all cached entries from disk
func (c *Cache) Clear() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			_ = os.Remove(filepath.Join(c.dir, e.Name())) //nolint:errcheck
		}
	}
	return nil
}

func (c *Cache) path(key string) string {
	safe := filepath.Base(key)
	return filepath.Join(c.dir, safe+".json")
}
