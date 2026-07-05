// ©AngelaMos | 2026
// fetch_state_test.go

package store

import "testing"

func seedSource(t *testing.T, s *Store) int64 {
	t.Helper()
	id, err := s.UpsertSource(SourceInput{
		Name: "krebs", Title: "Krebs", URL: "https://krebsonsecurity.com/feed/",
		Type: "rss", Weight: 1.0, Tags: []string{"news"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	return id
}

func TestFetchStateMissing(t *testing.T) {
	s := openTemp(t)
	id := seedSource(t, s)
	fs, ok, err := s.GetFetchState(id)
	if err != nil {
		t.Fatalf("GetFetchState: %v", err)
	}
	if ok {
		t.Error("expected no fetch_state for fresh source")
	}
	if fs != (FetchState{}) {
		t.Errorf("expected zero FetchState, got %+v", fs)
	}
}

func TestFetchStateRoundTrip(t *testing.T) {
	s := openTemp(t)
	id := seedSource(t, s)

	want := FetchState{ETag: `"v1"`, LastModified: "Wed, 01 Jul 2026 00:00:00 GMT", LastFetched: 1700, LastStatus: 200}
	if err := s.UpsertFetchState(id, want); err != nil {
		t.Fatalf("UpsertFetchState: %v", err)
	}

	got, ok, err := s.GetFetchState(id)
	if err != nil {
		t.Fatalf("GetFetchState: %v", err)
	}
	if !ok {
		t.Fatal("expected fetch_state to exist")
	}
	if got != want {
		t.Errorf("round-trip = %+v, want %+v", got, want)
	}

	updated := FetchState{ETag: `"v2"`, LastModified: "Thu, 02 Jul 2026 00:00:00 GMT", LastFetched: 1800, LastStatus: 304}
	if err := s.UpsertFetchState(id, updated); err != nil {
		t.Fatalf("second UpsertFetchState: %v", err)
	}
	got, _, _ = s.GetFetchState(id)
	if got != updated {
		t.Errorf("after update = %+v, want %+v", got, updated)
	}
}

func TestInsertArticleStoresTitleHash(t *testing.T) {
	s := openTemp(t)
	id := seedSource(t, s)
	if _, err := s.InsertArticle(Article{
		SourceID: id, CanonicalURL: "https://example.com/a", ContentHash: "hash1",
		TitleHash: "thash1", Title: "A",
	}); err != nil {
		t.Fatalf("InsertArticle: %v", err)
	}
	var th string
	if err := s.DB().QueryRow(`SELECT title_hash FROM articles WHERE content_hash = ?`, "hash1").Scan(&th); err != nil {
		t.Fatal(err)
	}
	if th != "thash1" {
		t.Errorf("title_hash = %q, want thash1", th)
	}
}
