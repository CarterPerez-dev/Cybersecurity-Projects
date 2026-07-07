// ©AngelaMos | 2026
// anthropic.go

package ai

import (
	"context"
	"net/http"
	"strings"
)

const (
	anthropicMessagesPath = "/messages"
	anthropicVersion      = "2023-06-01"
	headerAPIKey          = "x-api-key"
	headerAnthropicVer    = "anthropic-version"
	stopReasonRefusal     = "refusal"
	contentTypeText       = "text"
)

type anthropicClient struct {
	http    *http.Client
	baseURL string
	model   string
	apiKey  string
}

func newAnthropic(client *http.Client, baseURL, model, apiKey string) *anthropicClient {
	return &anthropicClient{
		http:    client,
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		apiKey:  apiKey,
	}
}

func (c *anthropicClient) Name() string { return ProviderAnthropic }

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicResponse struct {
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func (c *anthropicClient) Generate(ctx context.Context, req IdeationRequest) (IdeationResult, error) {
	system, user := buildPrompt(req)
	body := anthropicRequest{
		Model:     c.model,
		MaxTokens: defaultMaxTokens,
		System:    system,
		Messages:  []anthropicMessage{{Role: roleUser, Content: user}},
	}
	header := http.Header{}
	header.Set(headerAPIKey, c.apiKey)
	header.Set(headerAnthropicVer, anthropicVersion)
	var resp anthropicResponse
	if err := postJSON(ctx, c.http, c.baseURL+anthropicMessagesPath, header, body, &resp); err != nil {
		return IdeationResult{}, err
	}
	if resp.StopReason == stopReasonRefusal {
		return IdeationResult{}, ErrRefused
	}
	var text strings.Builder
	for _, block := range resp.Content {
		if block.Type == contentTypeText {
			text.WriteString(block.Text)
		}
	}
	return parseResult(text.String())
}
