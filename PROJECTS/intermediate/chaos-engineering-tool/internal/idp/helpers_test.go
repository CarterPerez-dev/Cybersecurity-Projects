// ©AngelaMos | 2026
// helpers_test.go

package idp

import (
	"context"
	"net/http"
	"testing"
	"time"
)

const helperTimeout = 10 * time.Second

func listening(t *testing.T) *Provider {
	t.Helper()

	p, err := New(Config{})
	if err != nil {
		t.Fatalf("build a provider: %v", err)
	}

	if err := p.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("bind a provider: %v", err)
	}

	t.Cleanup(func() { _ = p.Close() })

	return p
}

func httpClient() *http.Client {
	return &http.Client{Timeout: helperTimeout}
}

func (p *Provider) active(t *testing.T, credential string) bool {
	t.Helper()

	addr, err := p.Addr()
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	body, err := fetchIntrospection(
		context.Background(),
		httpClient(),
		p.introspectURL("http://"+addr, credential),
	)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}

	return body.Active
}
