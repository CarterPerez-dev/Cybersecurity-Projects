// ©AngelaMos | 2026
// client_test.go

package hibp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSha1Hash(t *testing.T) {
	t.Parallel()
	got := sha1Hash("password")
	assert.Equal(t,
		"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
		got,
	)
}

func TestClientCheckBreached(t *testing.T) {
	t.Parallel()

	hash := sha1Hash("password")
	prefix := hash[:5]
	suffix := hash[5:]

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/range/"+prefix, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf( //nolint:errcheck
				w,
				"%s:3861493\n",
				suffix,
			)
			fmt.Fprintf( //nolint:errcheck
				w,
				"0000000000000000000000000000DEAD0:0\n",
			)
		}),
	)
	defer server.Close()

	client := NewClient()
	client.baseURL = server.URL + "/range/"

	result, err := client.Check(context.Background(), "password")
	require.NoError(t, err)
	assert.True(t, result.Breached)
	assert.Equal(t, 3861493, result.Count)
}

func TestClientCheckClean(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, //nolint:errcheck
				"0000000000000000000000000000AAAA0:5\n")
			fmt.Fprintf( //nolint:errcheck
				w,
				"0000000000000000000000000000BBBB0:2\n",
			)
		}),
	)
	defer server.Close()

	client := NewClient()
	client.baseURL = server.URL + "/range/"

	result, err := client.Check(
		context.Background(), "unique_password_not_in_breach",
	)
	require.NoError(t, err)
	assert.False(t, result.Breached)
	assert.Equal(t, 0, result.Count)
}

func TestClientCachesResults(t *testing.T) {
	t.Parallel()

	callCount := 0
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			hash := sha1Hash("cached_secret")
			suffix := hash[5:]
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "%s:42\n", suffix) //nolint:errcheck
		}),
	)
	defer server.Close()

	client := NewClient()
	client.baseURL = server.URL + "/range/"

	result1, err := client.Check(
		context.Background(), "cached_secret",
	)
	require.NoError(t, err)
	assert.True(t, result1.Breached)

	result2, err := client.Check(
		context.Background(), "cached_secret",
	)
	require.NoError(t, err)
	assert.True(t, result2.Breached)
	assert.Equal(t, 42, result2.Count)
	assert.Equal(t, 1, callCount)
}

func TestClientHandlesServerError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}),
	)
	defer server.Close()

	client := NewClient()
	client.baseURL = server.URL + "/range/"

	_, err := client.Check(context.Background(), "test")
	assert.Error(t, err)
}

func TestClientRetries429(t *testing.T) {
	t.Parallel()

	hash := sha1Hash("retryable")
	suffix := hash[5:]

	attempts := 0
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "%s:10\n", suffix) //nolint:errcheck
		}),
	)
	defer server.Close()

	client := NewClient()
	client.baseURL = server.URL + "/range/"

	result, err := client.Check(context.Background(), "retryable")
	require.NoError(t, err)
	assert.True(t, result.Breached)
	assert.Equal(t, 10, result.Count)
	assert.Equal(t, 3, attempts)
}

func TestClientRetries429Exhausted(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}),
	)
	defer server.Close()

	client := NewClient()
	client.baseURL = server.URL + "/range/"

	_, err := client.Check(context.Background(), "always429")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retries exhausted")
}

func TestClientContextCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "AAAA0:1\n") //nolint:errcheck
		}),
	)
	defer server.Close()

	client := NewClient()
	client.baseURL = server.URL + "/range/"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.Check(ctx, "test")
	assert.Error(t, err)
}
