// ©AngelaMos | 2026
// factory_test.go

package ai

import (
	"testing"

	"github.com/CarterPerez-dev/nadezhda/internal/config"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

func TestFactoryProviders(t *testing.T) {
	base := config.Default().AI

	t.Setenv(envOpenAIKey, "")
	t.Setenv(envGeminiKey, "")
	t.Setenv(envAnthropicKey, "")

	base.Provider = ProviderQwen
	p, err := Factory(base)
	if err != nil || p.Name() != ProviderQwen {
		t.Fatalf("qwen: p=%v err=%v", p, err)
	}

	base.Provider = ProviderOpenAI
	if _, err := Factory(base); err == nil {
		t.Error("openai without key should error")
	}
	t.Setenv(envOpenAIKey, "k")
	if p, err := Factory(base); err != nil || p.Name() != ProviderOpenAI {
		t.Errorf("openai: p=%v err=%v", p, err)
	}

	base.Provider = ProviderGemini
	if _, err := Factory(base); err == nil {
		t.Error("gemini without key should error")
	}
	t.Setenv(envGeminiKey, "k")
	if p, err := Factory(base); err != nil || p.Name() != ProviderGemini {
		t.Errorf("gemini: p=%v err=%v", p, err)
	}

	base.Provider = ProviderAnthropic
	if _, err := Factory(base); err == nil {
		t.Error("anthropic without key should error")
	}
	t.Setenv(envAnthropicKey, "k")
	if p, err := Factory(base); err != nil || p.Name() != ProviderAnthropic {
		t.Errorf("anthropic: p=%v err=%v", p, err)
	}

	base.Provider = "nope"
	if _, err := Factory(base); err == nil {
		t.Error("unknown provider should error")
	}
}

func TestRequestFromCluster(t *testing.T) {
	cvss := 9.8
	epss := 0.5
	c := store.DigestCluster{
		Size:      3,
		FirstSeen: 0,
		LastSeen:  6 * secondsPerHour,
		Articles: []store.DigestArticle{
			{Title: "A", SourceName: "krebs"},
			{Title: "A", SourceName: "krebs"},
			{Title: "B", SourceName: "register"},
		},
		CVEs: []store.DigestCVE{{ID: "CVE-2025-1", CVSSScore: &cvss, EPSS: &epss, IsKEV: true}},
	}
	req := RequestFromCluster(c)
	if len(req.Titles) != 2 || len(req.Sources) != 2 {
		t.Errorf("dedup failed: titles=%v sources=%v", req.Titles, req.Sources)
	}
	if req.SpanHours != 6 || req.ClusterSize != 3 {
		t.Errorf("span=%d size=%d", req.SpanHours, req.ClusterSize)
	}
	if len(req.CVEs) != 1 || !req.CVEs[0].KEV || req.CVEs[0].CVSS == nil {
		t.Errorf("cve mapping: %+v", req.CVEs)
	}
}
