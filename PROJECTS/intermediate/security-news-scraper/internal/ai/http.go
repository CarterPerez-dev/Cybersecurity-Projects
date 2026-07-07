// ©AngelaMos | 2026
// http.go

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	headerContentType = "Content-Type"
	mimeJSON          = "application/json"
	errBodyLimit      = 300
)

type statusError struct {
	code int
	url  string
	body string
}

func (e *statusError) Error() string {
	body := e.body
	if len(body) > errBodyLimit {
		body = strings.ToValidUTF8(body[:errBodyLimit], "") + "..."
	}
	return fmt.Sprintf("ai: POST %s: status %d: %s", e.url, e.code, body)
}

func postJSON(ctx context.Context, client *http.Client, url string, header http.Header, reqBody, out any) error {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("ai: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("ai: build request %s: %w", url, err)
	}
	req.Header.Set(headerContentType, mimeJSON)
	for key, values := range header {
		req.Header[key] = values
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ai: POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBytes))
	if err != nil {
		return fmt.Errorf("ai: read %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return &statusError{code: resp.StatusCode, url: url, body: string(data)}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("ai: decode %s: %w", url, err)
	}
	return nil
}
