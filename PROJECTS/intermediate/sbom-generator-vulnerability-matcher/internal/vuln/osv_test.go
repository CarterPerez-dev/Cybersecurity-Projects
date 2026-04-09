// ©AngelaMos | 2026
// osv_test.go

package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixtureDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "vuln-responses")
}

func TestOSVQueryBatch(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join(fixtureDir(t), "osv-batch.json"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/querybatch", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	client := NewOSVClient(WithOSVBaseURL(server.URL))

	packages := []types.Package{
		{Name: "golang.org/x/net", Version: "v0.1.0", PURL: "pkg:golang/golang.org/x/net@v0.1.0"},
	}

	matches, err := client.Query(context.Background(), packages)
	require.NoError(t, err)
	require.NotEmpty(t, matches)
	assert.Equal(t, "osv", matches[0].Vulnerability.Source)
	assert.Equal(t, "GO-2023-2102", matches[0].Vulnerability.ID)
}

func TestOSVMatchHasFixVersion(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join(fixtureDir(t), "osv-batch.json"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	client := NewOSVClient(WithOSVBaseURL(server.URL))
	packages := []types.Package{
		{Name: "golang.org/x/net", Version: "v0.1.0", PURL: "pkg:golang/golang.org/x/net@v0.1.0"},
	}

	matches, err := client.Query(context.Background(), packages)
	require.NoError(t, err)
	require.NotEmpty(t, matches)
	assert.Equal(t, "0.17.0", matches[0].Vulnerability.FixVersion)
}

func TestOSVMatchHasCVSSScore(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join(fixtureDir(t), "osv-batch.json"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()

	client := NewOSVClient(WithOSVBaseURL(server.URL))
	packages := []types.Package{
		{Name: "golang.org/x/net", Version: "v0.1.0", PURL: "pkg:golang/golang.org/x/net@v0.1.0"},
	}

	matches, err := client.Query(context.Background(), packages)
	require.NoError(t, err)
	require.NotEmpty(t, matches)
	assert.Equal(t, 7.5, matches[0].Vulnerability.Score)
}

func TestOSVEmptyPackages(t *testing.T) {
	client := NewOSVClient()
	matches, err := client.Query(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestOSVSource(t *testing.T) {
	client := NewOSVClient()
	assert.Equal(t, "osv", client.Source())
}

func TestOSVCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results": []}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewOSVClient(WithOSVBaseURL(server.URL))
	packages := []types.Package{
		{Name: "test", PURL: "pkg:test/test@1.0.0"},
	}

	_, err := client.Query(ctx, packages)
	assert.Error(t, err)
}
