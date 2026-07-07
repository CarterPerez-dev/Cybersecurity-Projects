// ©AngelaMos | 2026
// provider.go

package ai

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/CarterPerez-dev/nadezhda/internal/config"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const (
	ProviderQwen      = "qwen"
	ProviderOpenAI    = "openai"
	ProviderGemini    = "gemini"
	ProviderAnthropic = "anthropic"

	FormatBlog       = "blog"
	FormatNewsletter = "newsletter"
	FormatVideo      = "video"

	envOpenAIKey    = "OPENAI_API_KEY"
	envGeminiKey    = "GEMINI_API_KEY"
	envAnthropicKey = "ANTHROPIC_API_KEY"

	requestTimeout   = 120 * time.Second
	defaultMaxTokens = 2048
	maxJSONBytes     = 4 << 20
	secondsPerHour   = 3600
)

var ErrRefused = errors.New("ai: provider declined to generate for this item")

type CVEContext struct {
	ID   string
	CVSS *float64
	KEV  bool
	EPSS *float64
}

type IdeationRequest struct {
	Titles      []string
	Sources     []string
	CVEs        []CVEContext
	ClusterSize int
	SpanHours   int
}

type IdeationResult struct {
	Summary string   `json:"summary"`
	Why     string   `json:"why"`
	Angles  []string `json:"angles"`
	Format  string   `json:"format"`
}

type Provider interface {
	Name() string
	Generate(ctx context.Context, req IdeationRequest) (IdeationResult, error)
}

func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func Factory(cfg config.AI) (Provider, error) {
	client := &http.Client{Timeout: requestTimeout, CheckRedirect: noRedirect}
	switch cfg.Provider {
	case ProviderQwen:
		return newOpenAICompat(ProviderQwen, client, cfg.Qwen.BaseURL, cfg.Qwen.Model, ""), nil
	case ProviderOpenAI:
		key := os.Getenv(envOpenAIKey)
		if key == "" {
			return nil, fmt.Errorf("ai: provider %q requires %s in the environment", ProviderOpenAI, envOpenAIKey)
		}
		return newOpenAICompat(ProviderOpenAI, client, cfg.OpenAI.BaseURL, cfg.OpenAI.Model, key), nil
	case ProviderGemini:
		key := os.Getenv(envGeminiKey)
		if key == "" {
			return nil, fmt.Errorf("ai: provider %q requires %s in the environment", ProviderGemini, envGeminiKey)
		}
		return newOpenAICompat(ProviderGemini, client, cfg.Gemini.BaseURL, cfg.Gemini.Model, key), nil
	case ProviderAnthropic:
		key := os.Getenv(envAnthropicKey)
		if key == "" {
			return nil, fmt.Errorf("ai: provider %q requires %s in the environment", ProviderAnthropic, envAnthropicKey)
		}
		return newAnthropic(client, cfg.Anthropic.BaseURL, cfg.Anthropic.Model, key), nil
	default:
		return nil, fmt.Errorf("ai: unknown provider %q", cfg.Provider)
	}
}

func RequestFromCluster(c store.DigestCluster) IdeationRequest {
	req := IdeationRequest{ClusterSize: c.Size}
	if c.LastSeen > c.FirstSeen {
		req.SpanHours = int((c.LastSeen - c.FirstSeen) / secondsPerHour)
	}
	seenTitle := make(map[string]bool)
	seenSource := make(map[string]bool)
	for _, a := range c.Articles {
		if a.Title != "" && !seenTitle[a.Title] {
			seenTitle[a.Title] = true
			req.Titles = append(req.Titles, a.Title)
		}
		if a.SourceName != "" && !seenSource[a.SourceName] {
			seenSource[a.SourceName] = true
			req.Sources = append(req.Sources, a.SourceName)
		}
	}
	for _, v := range c.CVEs {
		req.CVEs = append(req.CVEs, CVEContext{ID: v.ID, CVSS: v.CVSSScore, KEV: v.IsKEV, EPSS: v.EPSS})
	}
	return req
}

var (
	_ Provider = (*openAICompat)(nil)
	_ Provider = (*anthropicClient)(nil)
	_ Provider = (*MockProvider)(nil)
)
