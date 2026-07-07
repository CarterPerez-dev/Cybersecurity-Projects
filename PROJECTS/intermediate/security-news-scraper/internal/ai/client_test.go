// ©AngelaMos | 2026
// client_test.go

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const ideationJSON = `{"summary":"s","why":"w","angles":["a","b","c"],"format":"video"}`

func TestOpenAICompatGenerate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer k" {
			t.Errorf("Authorization = %q, want Bearer k", got)
		}
		body, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": ideationJSON}}},
		})
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newOpenAICompat("openai", srv.Client(), srv.URL, "gpt-4o-mini", "k")
	res, err := c.Generate(context.Background(), IdeationRequest{Titles: []string{"t"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.Summary != "s" || res.Format != FormatVideo || len(res.Angles) != 3 {
		t.Errorf("got %+v", res)
	}
	if c.Name() != "openai" {
		t.Errorf("Name = %q", c.Name())
	}
}

func TestOpenAICompatNoKeyNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty (qwen has no key)", got)
		}
		body, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": ideationJSON}}},
		})
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newOpenAICompat("qwen", srv.Client(), srv.URL, "qwen2.5:7b", "")
	if _, err := c.Generate(context.Background(), IdeationRequest{Titles: []string{"t"}}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
}

func TestOpenAICompatNoChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()

	c := newOpenAICompat("openai", srv.Client(), srv.URL, "m", "k")
	if _, err := c.Generate(context.Background(), IdeationRequest{}); err == nil {
		t.Error("expected error on empty choices")
	}
}

func TestOpenAICompatStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad key"}`))
	}))
	defer srv.Close()

	c := newOpenAICompat("openai", srv.Client(), srv.URL, "m", "k")
	if _, err := c.Generate(context.Background(), IdeationRequest{}); err == nil {
		t.Error("expected error on 401")
	}
}

func TestAnthropicGenerate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "k" {
			t.Errorf("x-api-key = %q, want k", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Errorf("anthropic-version = %q, want 2023-06-01", got)
		}
		body, _ := json.Marshal(map[string]any{
			"stop_reason": "end_turn",
			"content":     []map[string]any{{"type": "text", "text": ideationJSON}},
		})
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newAnthropic(srv.Client(), srv.URL, "claude-sonnet-4-6", "k")
	res, err := c.Generate(context.Background(), IdeationRequest{Titles: []string{"t"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.Summary != "s" || res.Format != FormatVideo {
		t.Errorf("got %+v", res)
	}
	if c.Name() != ProviderAnthropic {
		t.Errorf("Name = %q", c.Name())
	}
}

func TestAnthropicRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"stop_reason":"refusal","content":[]}`))
	}))
	defer srv.Close()

	c := newAnthropic(srv.Client(), srv.URL, "claude-sonnet-4-6", "k")
	_, err := c.Generate(context.Background(), IdeationRequest{})
	if !errors.Is(err, ErrRefused) {
		t.Errorf("err = %v, want ErrRefused", err)
	}
}
