// ©AngelaMos | 2026
// mock.go

package ai

import "context"

type MockProvider struct {
	ProviderName string
	Result       IdeationResult
	Err          error
	Calls        int
}

func (m *MockProvider) Name() string {
	if m.ProviderName == "" {
		return "mock"
	}
	return m.ProviderName
}

func (m *MockProvider) Generate(ctx context.Context, req IdeationRequest) (IdeationResult, error) {
	m.Calls++
	return m.Result, m.Err
}
