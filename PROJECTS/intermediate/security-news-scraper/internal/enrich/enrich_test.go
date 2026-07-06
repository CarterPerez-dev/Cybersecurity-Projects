// ©AngelaMos | 2026
// enrich_test.go

package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CarterPerez-dev/nadezhda/internal/cve"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

func fileServer(t *testing.T, path string) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "enrich.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRunEnrichesLog4Shell(t *testing.T) {
	nvd := fileServer(t, "../../testdata/nvd/CVE-2021-44228.json")
	kev := fileServer(t, "../../testdata/kev/kev-sample.json")
	epss := fileServer(t, "../../testdata/epss/CVE-2021-44228.json")

	st := newStore(t)
	if err := st.UpsertCVEStub("CVE-2021-44228"); err != nil {
		t.Fatal(err)
	}

	clients := Clients{
		Core: cve.NewNVDClient(nvd.Client(), nvd.URL, ""),
		KEV:  cve.NewKEVClient(kev.Client(), kev.URL),
		EPSS: cve.NewEPSSClient(epss.Client(), epss.URL),
	}

	stats, err := Run(context.Background(), st, clients, time.Unix(1_800_000_000, 0), 24, 3)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Enriched != 1 || stats.KEVHits != 1 {
		t.Fatalf("stats = %+v, want Enriched:1 KEVHits:1", stats)
	}

	c, err := st.GetCVE("CVE-2021-44228")
	if err != nil {
		t.Fatal(err)
	}
	if c.CVSSScore == nil || *c.CVSSScore != 10.0 || c.CVSSSeverity != "CRITICAL" {
		t.Errorf("cvss = %v/%q, want 10.0/CRITICAL", c.CVSSScore, c.CVSSSeverity)
	}
	if !c.IsKEV || !c.KEVRansomware {
		t.Errorf("expected KEV + ransomware, got is_kev=%v ransomware=%v", c.IsKEV, c.KEVRansomware)
	}
	if c.EPSS == nil || *c.EPSS < 0.9 {
		t.Errorf("epss = %v, want ~0.99999", c.EPSS)
	}
	if c.EnrichStatus != store.EnrichStatusOK {
		t.Errorf("status = %q, want ok", c.EnrichStatus)
	}
}

func TestRunSkipsFreshAndMarksNotFound(t *testing.T) {
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	t.Cleanup(nvd.Close)
	kev := fileServer(t, "../../testdata/kev/kev-sample.json")
	epss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(epss.Close)

	st := newStore(t)
	if err := st.UpsertCVEStub("CVE-2099-99999"); err != nil {
		t.Fatal(err)
	}
	clients := Clients{
		Core: cve.NewNVDClient(nvd.Client(), nvd.URL, ""),
		KEV:  cve.NewKEVClient(kev.Client(), kev.URL),
		EPSS: cve.NewEPSSClient(epss.Client(), epss.URL),
	}
	now := time.Unix(1_800_000_000, 0)

	stats, err := Run(context.Background(), st, clients, now, 24, 3)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.NotFound != 1 {
		t.Errorf("NotFound = %d, want 1", stats.NotFound)
	}

	fresh, err := Run(context.Background(), st, clients, now, 24, 3)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if fresh.Total != 0 {
		t.Errorf("second run Total = %d, want 0 (not_found within negative TTL is skipped)", fresh.Total)
	}
}
