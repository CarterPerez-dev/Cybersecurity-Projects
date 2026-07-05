// ©AngelaMos | 2026
// cve_test.go

package store

import "testing"

func seedArticleWithCVE(t *testing.T, s *Store, cveID string, cvss float64, kev bool) int64 {
	t.Helper()
	sourceID, err := s.UpsertSource(SourceInput{
		Name: "src", URL: "https://ex.example/feed", Type: "rss", Weight: 1, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	articleID, err := s.InsertArticle(Article{
		SourceID: sourceID, CanonicalURL: "https://ex.example/a", ContentHash: "ch", TitleHash: "th",
		Title: "Exploit in the wild", Summary: "details", PublishedAt: 1000, FetchedAt: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertCVEStub(cveID); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkArticleCVE(articleID, cveID); err != nil {
		t.Fatal(err)
	}
	score := cvss
	if err := s.UpdateCVEEnrichment(CVE{
		ID: cveID, CVSSScore: &score, CVSSSeverity: "CRITICAL", IsKEV: kev,
		EnrichedAt: 2000, EnrichStatus: EnrichStatusOK,
	}); err != nil {
		t.Fatal(err)
	}
	return articleID
}

func TestArticlesForCVE(t *testing.T) {
	s := openTemp(t)
	seedArticleWithCVE(t, s, "CVE-2026-1", 9.8, true)
	got, err := s.ArticlesForCVE("CVE-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Title != "Exploit in the wild" {
		t.Errorf("ArticlesForCVE = %+v, want one article", got)
	}
}

func TestLinkArticleCVEIsIdempotent(t *testing.T) {
	s := openTemp(t)
	id := seedArticleWithCVE(t, s, "CVE-2026-1", 5.0, false)
	if err := s.LinkArticleCVE(id, "CVE-2026-1"); err != nil {
		t.Fatalf("re-link should be a no-op: %v", err)
	}
	got, _ := s.ArticlesForCVE("CVE-2026-1")
	if len(got) != 1 {
		t.Errorf("duplicate link produced %d rows, want 1", len(got))
	}
}

func TestListArticlesFilters(t *testing.T) {
	s := openTemp(t)
	seedArticleWithCVE(t, s, "CVE-2026-1", 9.8, true)

	if got, _ := s.ListArticles(ListFilter{KEV: true}); len(got) != 1 {
		t.Errorf("--kev returned %d, want 1", len(got))
	}
	if got, _ := s.ListArticles(ListFilter{MinCVSS: 9.0}); len(got) != 1 {
		t.Errorf("--min-cvss 9 returned %d, want 1", len(got))
	}
	if got, _ := s.ListArticles(ListFilter{MinCVSS: 10.0}); len(got) != 0 {
		t.Errorf("--min-cvss 10 returned %d, want 0", len(got))
	}
	if got, _ := s.ListArticles(ListFilter{Keyword: "exploit"}); len(got) != 1 {
		t.Errorf("--keyword returned %d, want 1", len(got))
	}
	if got, _ := s.ListArticles(ListFilter{Source: "nope"}); len(got) != 0 {
		t.Errorf("unknown source returned %d, want 0", len(got))
	}
}

func TestCVEsNeedingEnrichment(t *testing.T) {
	s := openTemp(t)
	if err := s.UpsertCVEStub("CVE-2026-1"); err != nil {
		t.Fatal(err)
	}
	need, err := s.CVEsNeedingEnrichment(10000, 3600, 1800)
	if err != nil {
		t.Fatal(err)
	}
	if len(need) != 1 {
		t.Fatalf("fresh stub should need enrichment, got %d", len(need))
	}
	score := 5.0
	if err := s.UpdateCVEEnrichment(CVE{ID: "CVE-2026-1", CVSSScore: &score, EnrichedAt: 9000, EnrichStatus: EnrichStatusOK}); err != nil {
		t.Fatal(err)
	}
	if need, _ := s.CVEsNeedingEnrichment(10000, 3600, 1800); len(need) != 0 {
		t.Errorf("recently enriched cve should be skipped, got %d", len(need))
	}
	if need, _ := s.CVEsNeedingEnrichment(99999, 3600, 1800); len(need) != 1 {
		t.Errorf("stale cve (past TTL) should need re-enrichment, got %d", len(need))
	}
}
