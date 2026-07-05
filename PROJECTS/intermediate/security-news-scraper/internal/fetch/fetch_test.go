// ©AngelaMos | 2026
// fetch_test.go

package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testClient() *Client {
	c := New(Options{
		UserAgent:    "nadezhda-test/1.0",
		PerHostRate:  1e6,
		PerHostBurst: 1,
		Timeout:      5 * time.Second,
		MaxRetries:   3,
	})
	c.backoffBase = time.Millisecond
	return c
}

func TestFetchOKCapturesValidators(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerETag, `"v1"`)
		w.Header().Set(headerLastModified, "Wed, 01 Jul 2026 00:00:00 GMT")
		_, _ = w.Write([]byte("<rss></rss>"))
	}))
	defer srv.Close()

	res, err := testClient().Fetch(context.Background(), Request{URL: srv.URL + "/feed"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", res.Status)
	}
	if string(res.Body) != "<rss></rss>" {
		t.Errorf("body = %q", res.Body)
	}
	if res.ETag != `"v1"` {
		t.Errorf("etag = %q, want \"v1\"", res.ETag)
	}
	if res.LastModified == "" {
		t.Error("last-modified not captured")
	}
}

func TestFetchConditionalGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerIfNoneMatch) == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set(headerETag, `"v1"`)
		_, _ = w.Write([]byte("body"))
	}))
	defer srv.Close()

	c := testClient()
	first, err := c.Fetch(context.Background(), Request{URL: srv.URL + "/feed"})
	if err != nil || first.Status != http.StatusOK {
		t.Fatalf("first fetch: status=%d err=%v", first.Status, err)
	}

	second, err := c.Fetch(context.Background(), Request{URL: srv.URL + "/feed", ETag: first.ETag})
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if !second.NotModified {
		t.Error("expected NotModified on matching ETag")
	}
	if second.ETag != `"v1"` {
		t.Errorf("304 should retain etag, got %q", second.ETag)
	}
}

func TestFetchRetriesServerError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := testClient().Fetch(context.Background(), Request{URL: srv.URL + "/feed"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != "ok" {
		t.Errorf("body = %q, want ok", res.Body)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 (one 500, one 200)", calls.Load())
	}
}

func TestFetchDoesNotRetryClientError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := testClient().Fetch(context.Background(), Request{URL: srv.URL + "/feed"})
	if err == nil {
		t.Fatal("expected error on 404")
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (no retry on 4xx)", calls.Load())
	}
}

func TestFetch429IsRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := testClient().Fetch(context.Background(), Request{URL: srv.URL + "/feed"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != "ok" || calls.Load() != 2 {
		t.Errorf("body=%q calls=%d, want ok/2", res.Body, calls.Load())
	}
}

func TestFetchTimeoutNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	c := New(Options{
		UserAgent: "nadezhda-test/1.0", PerHostRate: 1e6, PerHostBurst: 1,
		Timeout: 15 * time.Millisecond, MaxRetries: 3,
	})
	c.backoffBase = time.Millisecond

	_, err := c.Fetch(context.Background(), Request{URL: srv.URL + "/feed"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (timeout must not be retried)", calls.Load())
	}
}

func TestRetryAfterParsing(t *testing.T) {
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", 0},
		{"5", 5 * time.Second},
		{"0", 0},
		{"-3", 0},
		{"9999", maxRetryAfter},
		{"garbage", 0},
	}
	for _, tc := range cases {
		resp := &http.Response{Header: http.Header{}}
		if tc.header != "" {
			resp.Header.Set(headerRetryAfter, tc.header)
		}
		if got := retryAfter(resp); got != tc.want {
			t.Errorf("retryAfter(%q) = %s, want %s", tc.header, got, tc.want)
		}
	}
}

func TestFeedFetchIgnoresRobots(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == robotsPath {
			t.Error("Fetch must not request robots.txt on the feed path")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
			return
		}
		_, _ = w.Write([]byte("feed body"))
	}))
	defer srv.Close()

	res, err := testClient().Fetch(context.Background(), Request{URL: srv.URL + "/feed"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != "feed body" {
		t.Errorf("body = %q, want feed body", res.Body)
	}
}

func TestAllowedRespectsDisallow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == robotsPath {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /article\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ok, err := testClient().Allowed(context.Background(), srv.URL+"/article/123")
	if err != nil {
		t.Fatalf("Allowed: %v", err)
	}
	if ok {
		t.Error("expected disallowed for /article path")
	}
}

func TestAllowedPermitsOtherPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == robotsPath {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ok, err := testClient().Allowed(context.Background(), srv.URL+"/article/123")
	if err != nil {
		t.Fatalf("Allowed: %v", err)
	}
	if !ok {
		t.Error("expected allowed for non-admin path")
	}
}
