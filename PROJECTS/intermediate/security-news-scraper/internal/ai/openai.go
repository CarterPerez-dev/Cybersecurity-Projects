// ©AngelaMos | 2026
// openai.go

package ai

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const (
	openAIChatPath = "/chat/completions"
	roleSystem     = "system"
	roleUser       = "user"
	headerAuth     = "Authorization"
	bearerPrefix   = "Bearer "
)

type openAICompat struct {
	name    string
	http    *http.Client
	baseURL string
	model   string
	apiKey  string
}

func newOpenAICompat(name string, client *http.Client, baseURL, model, apiKey string) *openAICompat {
	return &openAICompat{
		name:    name,
		http:    client,
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		apiKey:  apiKey,
	}
}

func (c *openAICompat) Name() string { return c.name }

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
}

func (c *openAICompat) Generate(ctx context.Context, req IdeationRequest) (IdeationResult, error) {
	system, user := buildPrompt(req)
	body := openAIRequest{
		Model: c.model,
		Messages: []openAIMessage{
			{Role: roleSystem, Content: system},
			{Role: roleUser, Content: user},
		},
	}
	header := http.Header{}
	if c.apiKey != "" {
		header.Set(headerAuth, bearerPrefix+c.apiKey)
	}
	var resp openAIResponse
	if err := postJSON(ctx, c.http, c.baseURL+openAIChatPath, header, body, &resp); err != nil {
		return IdeationResult{}, err
	}
	if len(resp.Choices) == 0 {
		return IdeationResult{}, fmt.Errorf("ai: %s returned no choices", c.name)
	}
	return parseResult(resp.Choices[0].Message.Content)
}
