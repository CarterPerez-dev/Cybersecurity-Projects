// ©AngelaMos | 2026
// ingest_test.go

package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CarterPerez-dev/nadezhda/internal/config"
	"github.com/CarterPerez-dev/nadezhda/internal/fetch"
	"github.com/CarterPerez-dev/nadezhda/internal/normalize"
	"github.com/CarterPerez-dev/nadezhda/internal/source"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const fixture = "../../testdata/feeds/thehackernews.xml"

func loadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ingest.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func newClient() *fetch.Client {
	return fetch.New(fetch.Options{
		UserAgent:    "nadezhda-test/1.0",
		PerHostRate:  1e6,
		PerHostBurst: 1,
		Timeout:      5 * time.Second,
		MaxRetries:   2,
	})
}

func target(url string) []source.Source {
	return []source.Source{{
		Name: "test", Title: "Test Feed", URL: url,
		Type: source.KindRSS, Weight: 1.0, Tags: []string{"news"}, Enabled: true,
	}}
}

func TestRunIngestsAndDedups(t *testing.T) {
	body := loadFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	st := newStore(t)
	cfg := config.Default()
	targets := target(srv.URL + "/feed")
	now := time.Unix(1_800_000_000, 0)

	first, err := Run(context.Background(), newClient(), st, cfg, targets, now)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	r0 := first.Results[0]
	if r0.Err != nil {
		t.Fatalf("source error: %v", r0.Err)
	}
	if r0.New != 3 || r0.Parsed != 3 {
		t.Fatalf("first run: parsed=%d new=%d, want 3/3", r0.Parsed, r0.New)
	}

	count, err := st.CountArticles()
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("stored articles = %d, want 3", count)
	}

	var title, canonical, contentHash, titleHash string
	if err := st.DB().QueryRow(
		`SELECT title, canonical_url, content_hash, title_hash FROM articles LIMIT 1`,
	).Scan(&title, &canonical, &contentHash, &titleHash); err != nil {
		t.Fatal(err)
	}
	if contentHash != normalize.ContentHash(canonical) {
		t.Errorf("content_hash = %q, want sha256(canonical)", contentHash)
	}
	if titleHash != normalize.TitleHash(normalize.NormalizeTitle(title)) {
		t.Errorf("title_hash = %q, want sha256(normalized title)", titleHash)
	}

	second, err := Run(context.Background(), newClient(), st, cfg, targets, now)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	r1 := second.Results[0]
	if r1.New != 0 || r1.Duplicates != 3 {
		t.Fatalf("second run: new=%d dup=%d, want 0/3", r1.New, r1.Duplicates)
	}

	count, _ = st.CountArticles()
	if count != 3 {
		t.Fatalf("after re-run stored = %d, want 3 (idempotent)", count)
	}
}

func TestRunConditionalNotModified(t *testing.T) {
	body := loadFixture(t)
	const etag = `"abc123"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	st := newStore(t)
	cfg := config.Default()
	targets := target(srv.URL + "/feed")
	now := time.Unix(1_800_000_000, 0)

	first, err := Run(context.Background(), newClient(), st, cfg, targets, now)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if first.Results[0].New != 3 {
		t.Fatalf("first run new = %d, want 3", first.Results[0].New)
	}
	var storedETag string
	if err := st.DB().QueryRow(`SELECT etag FROM fetch_state LIMIT 1`).Scan(&storedETag); err != nil {
		t.Fatal(err)
	}
	if storedETag != etag {
		t.Errorf("persisted etag = %q, want %q", storedETag, etag)
	}

	second, err := Run(context.Background(), newClient(), st, cfg, targets, now)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	r := second.Results[0]
	if !r.NotModified {
		t.Errorf("expected NotModified on second run, got %+v", r)
	}
	if r.New != 0 {
		t.Errorf("new = %d on 304, want 0", r.New)
	}
}

func TestRunFailsSoftOnBadSource(t *testing.T) {
	body := loadFixture(t)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	st := newStore(t)
	cfg := config.Default()
	targets := []source.Source{
		{Name: "bad", URL: bad.URL + "/feed", Type: source.KindRSS, Weight: 1, Enabled: true},
		{Name: "good", URL: good.URL + "/feed", Type: source.KindRSS, Weight: 1, Enabled: true},
	}
	now := time.Unix(1_800_000_000, 0)

	summary, err := Run(context.Background(), newClient(), st, cfg, targets, now)
	if err != nil {
		t.Fatalf("Run returned error, should fail soft: %v", err)
	}
	byName := map[string]SourceResult{}
	for _, r := range summary.Results {
		byName[r.Name] = r
	}
	if byName["bad"].Err == nil {
		t.Error("bad source should record an error")
	}
	if byName["good"].New != 3 {
		t.Errorf("good source new = %d, want 3 (bad source must not abort run)", byName["good"].New)
	}
}
