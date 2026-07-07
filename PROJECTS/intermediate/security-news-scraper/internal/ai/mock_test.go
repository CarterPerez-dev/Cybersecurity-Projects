// ©AngelaMos | 2026
// mock_test.go

package ai

import (
	"context"
	"testing"
)

func TestMockProvider(t *testing.T) {
	want := IdeationResult{Summary: "s", Angles: []string{"a"}, Format: FormatBlog}
	m := &MockProvider{ProviderName: "mock", Result: want}
	if m.Name() != "mock" {
		t.Errorf("Name = %q, want mock", m.Name())
	}
	got, err := m.Generate(context.Background(), IdeationRequest{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got.Summary != "s" || len(got.Angles) != 1 {
		t.Errorf("result = %+v", got)
	}
	if m.Calls != 1 {
		t.Errorf("Calls = %d, want 1", m.Calls)
	}

	sentinel := context.Canceled
	me := &MockProvider{Err: sentinel}
	if me.Name() != "mock" {
		t.Errorf("default Name = %q, want mock", me.Name())
	}
	if _, err := me.Generate(context.Background(), IdeationRequest{}); err != sentinel {
		t.Errorf("err = %v, want the injected sentinel", err)
	}
}
