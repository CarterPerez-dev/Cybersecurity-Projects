// ©AngelaMos | 2026
// http.go

package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	headerAccept = "Accept"
	acceptJSON   = "application/json"
	maxJSONBytes = 32 << 20
)

type statusError struct {
	code int
	url  string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("cve: GET %s: status %d", e.url, e.code)
}

func getJSON(ctx context.Context, client *http.Client, url string, header http.Header, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("cve: build request %s: %w", url, err)
	}
	req.Header.Set(headerAccept, acceptJSON)
	for key, values := range header {
		req.Header[key] = values
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cve: GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxJSONBytes))
		return &statusError{code: resp.StatusCode, url: url}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes)).Decode(out); err != nil {
		return fmt.Errorf("cve: decode %s: %w", url, err)
	}
	return nil
}
