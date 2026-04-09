// ©AngelaMos | 2026
// nvd_test.go

package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNVDQuery(t *testing.T) {
	nvdFixture := `{
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2023-44487",
					"published": "2023-10-10T14:15:00.000",
					"descriptions": [
						{"lang": "en", "value": "HTTP/2 rapid reset attack"}
					],
					"metrics": {
						"cvssMetricV31": [
							{
								"cvssData": {
									"baseScore": 7.5,
									"baseSeverity": "HIGH"
								}
							}
						]
					}
				}
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.RawQuery, "virtualMatchString")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdFixture))
	}))
	defer server.Close()

	client := NewNVDClient(WithNVDBaseURL(server.URL))
	packages := []types.Package{
		{Name: "golang.org/x/net", Version: "v0.1.0", Ecosystem: types.EcosystemGo, PURL: "pkg:golang/golang.org/x/net@v0.1.0"},
	}

	matches, err := client.Query(context.Background(), packages)
	require.NoError(t, err)
	require.NotEmpty(t, matches)
	assert.Equal(t, "CVE-2023-44487", matches[0].Vulnerability.ID)
	assert.Equal(t, "nvd", matches[0].Vulnerability.Source)
	assert.Equal(t, 7.5, matches[0].Vulnerability.Score)
	assert.Equal(t, types.SeverityHigh, matches[0].Vulnerability.Severity)
}

func TestNVDAPIKeyHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-key-123", r.Header.Get("apiKey"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities": []}`))
	}))
	defer server.Close()

	client := NewNVDClient(WithNVDBaseURL(server.URL), WithNVDAPIKey("test-key-123"))
	packages := []types.Package{
		{Name: "test-pkg", Ecosystem: types.EcosystemNode, PURL: "pkg:npm/test-pkg@1.0.0"},
	}
	_, err := client.Query(context.Background(), packages)
	require.NoError(t, err)
}

func TestNVDEmptyPackages(t *testing.T) {
	client := NewNVDClient()
	matches, err := client.Query(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestNVDSource(t *testing.T) {
	client := NewNVDClient()
	assert.Equal(t, "nvd", client.Source())
}

func TestNVDBuildCPEString(t *testing.T) {
	tests := []struct {
		name     string
		pkg      types.Package
		contains string
	}{
		{
			name:     "go module",
			pkg:      types.Package{Name: "golang.org/x/net", Version: "v0.1.0", Ecosystem: types.EcosystemGo},
			contains: "cpe:2.3:a:*:net:0.1.0",
		},
		{
			name:     "npm package",
			pkg:      types.Package{Name: "express", Version: "4.18.2", Ecosystem: types.EcosystemNode},
			contains: "cpe:2.3:a:*:express:4.18.2",
		},
		{
			name:     "pypi package",
			pkg:      types.Package{Name: "requests", Version: "2.31.0", Ecosystem: types.EcosystemPython},
			contains: "cpe:2.3:a:*:requests:2.31.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildCPEString(tt.pkg)
			assert.Contains(t, cpe, tt.contains)
		})
	}
}
