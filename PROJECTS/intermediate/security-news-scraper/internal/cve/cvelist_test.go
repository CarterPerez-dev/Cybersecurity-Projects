// ©AngelaMos | 2026
// cvelist_test.go

package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCVEListParsesLog4Shell(t *testing.T) {
	body, err := os.ReadFile("../../testdata/cvelist/CVE-2021-44228.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client := NewCVEListClient(srv.Client(), srv.URL)
	res, err := client.Fetch(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.Found {
		t.Fatal("Found = false, want true")
	}
	if res.CVSSScore == nil || *res.CVSSScore != 10.0 {
		t.Errorf("CVSSScore = %v, want 10.0", res.CVSSScore)
	}
	if res.CVSSVersion != "3.1" || res.CVSSSeverity != "CRITICAL" {
		t.Errorf("cvss = %q/%q, want 3.1/CRITICAL", res.CVSSVersion, res.CVSSSeverity)
	}
	if res.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" {
		t.Errorf("vector = %q", res.CVSSVector)
	}
	if res.CWE != "CWE-502" {
		t.Errorf("CWE = %q, want CWE-502 (first problemType)", res.CWE)
	}
	if !strings.Contains(res.Description, "Log4j") {
		t.Errorf("description missing Log4j: %q", res.Description)
	}
	if res.Published == "" || res.Modified == "" {
		t.Errorf("published/modified empty: %q / %q", res.Published, res.Modified)
	}
}

func TestCVEListNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := NewCVEListClient(srv.Client(), srv.URL)
	res, err := client.Fetch(context.Background(), "CVE-2099-99999")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Found {
		t.Error("Found = true on 404, want false")
	}
}

func TestCVEListRecordURL(t *testing.T) {
	client := NewCVEListClient(http.DefaultClient, "https://example.com/cves")
	cases := map[string]string{
		"CVE-2021-44228": "https://example.com/cves/2021/44xxx/CVE-2021-44228.json",
		"CVE-2021-1234":  "https://example.com/cves/2021/1xxx/CVE-2021-1234.json",
		"CVE-2023-12345": "https://example.com/cves/2023/12xxx/CVE-2023-12345.json",
	}
	for id, want := range cases {
		got, err := client.recordURL(id)
		if err != nil {
			t.Errorf("recordURL(%q): %v", id, err)
			continue
		}
		if got != want {
			t.Errorf("recordURL(%q) = %q, want %q", id, got, want)
		}
	}
	if _, err := client.recordURL("not-a-cve"); err == nil {
		t.Error("expected error for malformed id")
	}
	if _, err := client.recordURL("CVE-2021-12"); err == nil {
		t.Error("expected error for a too-short cve number")
	}
}

func serveJSON(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCVEListCNAMetrics(t *testing.T) {
	srv := serveJSON(t, `{"cveMetadata":{"datePublished":"2020-01-01T00:00:00Z","dateUpdated":"2020-02-01T00:00:00Z"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"cna container path"}],"problemTypes":[{"descriptions":[{"lang":"en","cweId":"CWE-79"}]}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L"}}]}}}`)
	res, err := NewCVEListClient(srv.Client(), srv.URL).Fetch(context.Background(), "CVE-2020-0001")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.CVSSScore == nil || *res.CVSSScore != 7.5 || res.CVSSVersion != "3.1" || res.CVSSSeverity != "HIGH" {
		t.Errorf("cna metrics = %v/%q/%q, want 7.5/3.1/HIGH", res.CVSSScore, res.CVSSVersion, res.CVSSSeverity)
	}
	if res.CWE != "CWE-79" {
		t.Errorf("CWE = %q, want CWE-79", res.CWE)
	}
}

func TestCVEListV2SeverityNotCritical(t *testing.T) {
	srv := serveJSON(t, `{"cveMetadata":{"datePublished":"2005-01-01T00:00:00Z","dateUpdated":"2005-01-01T00:00:00Z"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"v2 only"}],"metrics":[{"cvssV2_0":{"version":"2.0","baseScore":9.0,"vectorString":"AV:N/AC:L/Au:N/C:C/I:C/A:C"}}]}}}`)
	res, err := NewCVEListClient(srv.Client(), srv.URL).Fetch(context.Background(), "CVE-2005-0001")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.CVSSVersion != "2.0" || res.CVSSScore == nil || *res.CVSSScore != 9.0 {
		t.Errorf("v2 = %q/%v, want 2.0/9.0", res.CVSSVersion, res.CVSSScore)
	}
	if res.CVSSSeverity != "HIGH" {
		t.Errorf("v2 severity = %q, want HIGH (CVSS v2 has no CRITICAL tier)", res.CVSSSeverity)
	}
}

var _ CVESource = (*CVEListClient)(nil)
var _ CVESource = (*NVDClient)(nil)
