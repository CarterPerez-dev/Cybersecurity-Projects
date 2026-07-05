// ©AngelaMos | 2026
// rebuild_test.go

package cluster

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "cluster.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func seedArticles(t *testing.T, st *store.Store) {
	t.Helper()
	titles := []string{
		"Acme Corp data breach exposes millions",
		"Acme Corp data breach exposed millions",
		"Acme Corp data breach hits millions",
		"Linux kernel 7 released with new scheduler",
	}
	for i, title := range titles {
		sourceID, err := st.UpsertSource(store.SourceInput{
			Name: fmt.Sprintf("src%d", i), URL: fmt.Sprintf("https://outlet%d.example/feed", i),
			Type: "rss", Weight: 1, Enabled: true,
		})
		if err != nil {
			t.Fatalf("upsert source %d: %v", i, err)
		}
		if _, err := st.InsertArticle(store.Article{
			SourceID:     sourceID,
			CanonicalURL: fmt.Sprintf("https://example.com/a/%d", i),
			ContentHash:  fmt.Sprintf("chash-%d", i),
			TitleHash:    fmt.Sprintf("thash-%d", i),
			Title:        title,
			PublishedAt:  int64(100 * (i + 1)),
			FetchedAt:    int64(100 * (i + 1)),
		}); err != nil {
			t.Fatalf("insert article %d: %v", i, err)
		}
	}
}

func clusterSizes(t *testing.T, st *store.Store) []int {
	t.Helper()
	rows, err := st.DB().Query(`SELECT size FROM clusters ORDER BY size`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func countMembers(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM cluster_members`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRebuildClustersEndToEnd(t *testing.T) {
	st := openStore(t)
	seedArticles(t, st)

	stats, err := Rebuild(st, 0.6, bigWindow, 0)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if stats.Total != 2 || stats.MultiSource != 1 || stats.LargestSize != 3 {
		t.Fatalf("stats = %+v, want {Total:2 MultiSource:1 LargestSize:3}", stats)
	}
	if got := clusterSizes(t, st); len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Errorf("cluster sizes = %v, want [1 3]", got)
	}
	if m := countMembers(t, st); m != 4 {
		t.Errorf("cluster_members = %d, want 4 (every article assigned once)", m)
	}
}

func TestRebuildIsIdempotent(t *testing.T) {
	st := openStore(t)
	seedArticles(t, st)

	if _, err := Rebuild(st, 0.6, bigWindow, 0); err != nil {
		t.Fatalf("first Rebuild: %v", err)
	}
	stats, err := Rebuild(st, 0.6, bigWindow, 0)
	if err != nil {
		t.Fatalf("second Rebuild: %v", err)
	}
	if stats.Total != 2 {
		t.Errorf("second run clusters = %d, want 2 (rebuild replaces, no accumulation)", stats.Total)
	}
	if m := countMembers(t, st); m != 4 {
		t.Errorf("cluster_members = %d, want 4 after re-run", m)
	}
}

func TestRebuildLookbackExcludesOld(t *testing.T) {
	st := openStore(t)
	seedArticles(t, st)

	stats, err := Rebuild(st, 0.6, bigWindow, 250)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if stats.Total != 2 {
		t.Errorf("with since=250 only articles at t>=250 cluster, total = %d, want 2", stats.Total)
	}
	if m := countMembers(t, st); m != 2 {
		t.Errorf("members = %d, want 2 (two articles below lookback excluded)", m)
	}
}
