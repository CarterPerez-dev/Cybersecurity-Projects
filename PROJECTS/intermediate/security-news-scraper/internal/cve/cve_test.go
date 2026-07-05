// ©AngelaMos | 2026
// cve_test.go

package cve

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func fileServer(t *testing.T, path string) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func jsonServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExtract(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"See CVE-2021-44228 for details"}, []string{"CVE-2021-44228"}},
		{[]string{"cve-2021-44228 lowercase"}, []string{"CVE-2021-44228"}},
		{[]string{"CVE-2021-44228 and CVE-2021-44228 again"}, []string{"CVE-2021-44228"}},
		{[]string{"CVE-2026-1 too short", "CVE-2026-12345 ok"}, []string{"CVE-2026-12345"}},
		{[]string{"CVE-2021-45046, CVE-2021-44228"}, []string{"CVE-2021-44228", "CVE-2021-45046"}},
		{[]string{"no identifiers here"}, nil},
	}
	for _, tc := range cases {
		if got := Extract(tc.in...); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Extract(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNVDParsesLog4Shell(t *testing.T) {
	srv := fileServer(t, "../../testdata/nvd/CVE-2021-44228.json")
	c := NewNVDClient(srv.Client(), srv.URL, "")

	res, err := c.Fetch(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.Found {
		t.Fatal("expected Found")
	}
	if res.CVSSScore == nil || *res.CVSSScore != 10.0 {
		t.Errorf("cvss score = %v, want 10.0", res.CVSSScore)
	}
	if res.CVSSSeverity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", res.CVSSSeverity)
	}
	if res.CVSSVersion != "3.1" {
		t.Errorf("version = %q, want 3.1", res.CVSSVersion)
	}
	if res.CWE != "CWE-20" {
		t.Errorf("cwe = %q, want CWE-20", res.CWE)
	}
	if res.Description == "" {
		t.Error("description empty")
	}
}

func TestNVDNotFound(t *testing.T) {
	srv := jsonServer(t, `{"totalResults":0,"vulnerabilities":[]}`)
	c := NewNVDClient(srv.Client(), srv.URL, "")
	res, err := c.Fetch(context.Background(), "CVE-2099-99999")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Found {
		t.Error("expected not found for totalResults 0")
	}
}

func TestNVDPrecedencePrefersV40(t *testing.T) {
	body := `{"totalResults":1,"vulnerabilities":[{"cve":{
		"id":"CVE-2026-1","descriptions":[{"lang":"en","value":"d"}],
		"metrics":{
			"cvssMetricV40":[{"cvssData":{"version":"4.0","baseScore":9.3,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/x"}}],
			"cvssMetricV31":[{"cvssData":{"version":"3.1","baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/y"}}]
		}}}]}`
	srv := jsonServer(t, body)
	c := NewNVDClient(srv.Client(), srv.URL, "")
	res, err := c.Fetch(context.Background(), "CVE-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.CVSSVersion != "4.0" || res.CVSSScore == nil || *res.CVSSScore != 9.3 {
		t.Errorf("expected v4.0/9.3, got %s/%v", res.CVSSVersion, res.CVSSScore)
	}
}

func TestNVDV2SeverityFromMetricLevel(t *testing.T) {
	body := `{"totalResults":1,"vulnerabilities":[{"cve":{
		"id":"CVE-2005-1","descriptions":[{"lang":"en","value":"d"}],
		"metrics":{"cvssMetricV2":[{"baseSeverity":"HIGH","cvssData":{"version":"2.0","baseScore":7.5,"vectorString":"AV:N"}}]}
		}}]}`
	srv := jsonServer(t, body)
	c := NewNVDClient(srv.Client(), srv.URL, "")
	res, err := c.Fetch(context.Background(), "CVE-2005-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.CVSSVersion != "2.0" || res.CVSSSeverity != "HIGH" {
		t.Errorf("v2 severity should fall back to metric level, got %s/%q", res.CVSSVersion, res.CVSSSeverity)
	}
}

func TestKEVParsesSample(t *testing.T) {
	srv := fileServer(t, "../../testdata/kev/kev-sample.json")
	c := NewKEVClient(srv.Client(), srv.URL)
	catalog, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	log4, ok := catalog.Lookup("CVE-2021-44228")
	if !ok {
		t.Fatal("Log4Shell should be in KEV")
	}
	if !log4.Ransomware {
		t.Error("Log4Shell knownRansomwareCampaignUse=Known should map to true")
	}
	unknown, ok := catalog.Lookup("CVE-2026-45659")
	if !ok || unknown.Ransomware {
		t.Error("Unknown ransomware entry should map to false")
	}
	if _, ok := catalog.Lookup("CVE-1999-0001"); ok {
		t.Error("absent CVE should not be a KEV member")
	}
}

func TestEPSSParsesQuotedStrings(t *testing.T) {
	srv := fileServer(t, "../../testdata/epss/CVE-2021-44228.json")
	c := NewEPSSClient(srv.Client(), srv.URL)
	scores, err := c.Fetch(context.Background(), []string{"CVE-2021-44228"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	s, ok := scores["CVE-2021-44228"]
	if !ok {
		t.Fatal("expected a score for Log4Shell")
	}
	if math.Abs(s.EPSS-0.99999) > 1e-5 {
		t.Errorf("epss = %v, want ~0.99999 (string must be ParseFloat'd, not zeroed)", s.EPSS)
	}
	if math.Abs(s.Percentile-1.0) > 1e-9 {
		t.Errorf("percentile = %v, want 1.0", s.Percentile)
	}
}

func TestChunk(t *testing.T) {
	got := chunk([]string{"a", "b", "c", "d", "e"}, 2)
	want := [][]string{{"a", "b"}, {"c", "d"}, {"e"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chunk = %v, want %v", got, want)
	}
	if chunk(nil, 2) != nil {
		t.Error("chunk(nil) should be nil")
	}
}

func TestNVDRetriesOn503(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := NewNVDClient(srv.Client(), srv.URL, "")
	c.limiter = rate.NewLimiter(rate.Inf, 1)
	c.backoffBase = time.Millisecond
	if _, err := c.Fetch(context.Background(), "CVE-2026-1"); err != nil {
		t.Fatalf("Fetch after retry: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (one 503, one 200)", calls)
	}
}
