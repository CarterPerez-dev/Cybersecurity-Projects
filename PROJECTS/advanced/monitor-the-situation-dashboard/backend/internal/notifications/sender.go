// ©AngelaMos | 2026
// sender.go

package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	telegramAPIBase = "https://api.telegram.org"
	senderTimeout   = 10 * time.Second
	testMessage     = "Monitor the Situation — test notification. Channel configured successfully."
	fieldText       = "text"
)

type Sender struct {
	client *http.Client
}

func NewSender() *Sender {
	return &Sender{
		client: &http.Client{Timeout: senderTimeout},
	}
}

func (s *Sender) TestTelegram(
	ctx context.Context,
	botToken string,
	chatID int64,
) error {
	return s.sendTelegram(ctx, botToken, chatID, testMessage)
}

// SendTelegram is the exported version used by the alerts engine.
func (s *Sender) SendTelegram(
	ctx context.Context,
	botToken string,
	chatID int64,
	text string,
) error {
	return s.sendTelegram(ctx, botToken, chatID, text)
}

// SendSlack posts a plain-text message to a Slack incoming-webhook URL.
func (s *Sender) SendSlack(ctx context.Context, webhookURL, text string) error {
	payload, err := json.Marshal(map[string]string{fieldText: text})
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}
	return s.postWebhook(ctx, webhookURL, payload)
}

// SendDiscord posts a plain-text message to a Discord webhook URL.
func (s *Sender) SendDiscord(
	ctx context.Context,
	webhookURL, text string,
) error {
	payload, err := json.Marshal(map[string]string{"content": text})
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}
	return s.postWebhook(ctx, webhookURL, payload)
}

func (s *Sender) sendTelegram(
	ctx context.Context,
	botToken string,
	chatID int64,
	text string,
) error {
	url := fmt.Sprintf("%s/bot%s/sendMessage", telegramAPIBase, botToken)

	payload, err := json.Marshal(map[string]any{
		"chat_id": chatID,
		fieldText: text,
	})
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, url, bytes.NewReader(payload),
	)
	if err != nil {
		return fmt.Errorf("create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"telegram sendMessage: unexpected status %d",
			resp.StatusCode,
		)
	}
	return nil
}

func (s *Sender) SetTelegramWebhook(
	ctx context.Context,
	botToken, webhookURL, secretToken string,
) error {
	url := fmt.Sprintf("%s/bot%s/setWebhook", telegramAPIBase, botToken)

	payload, err := json.Marshal(map[string]any{
		"url":                  webhookURL,
		"secret_token":         secretToken,
		"allowed_updates":      []string{"message"},
		"drop_pending_updates": true,
	})
	if err != nil {
		return fmt.Errorf("marshal setWebhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, url, bytes.NewReader(payload),
	)
	if err != nil {
		return fmt.Errorf("create setWebhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("setWebhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"setWebhook: unexpected status %d",
			resp.StatusCode,
		)
	}
	return nil
}

func (s *Sender) DeleteTelegramWebhook(
	ctx context.Context,
	botToken string,
) error {
	url := fmt.Sprintf(
		"%s/bot%s/deleteWebhook",
		telegramAPIBase,
		botToken,
	)

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, url, http.NoBody,
	)
	if err != nil {
		return fmt.Errorf("create deleteWebhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("deleteWebhook: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func (s *Sender) TestSlack(ctx context.Context, webhookURL string) error {
	payload, err := json.Marshal(map[string]string{
		fieldText: testMessage,
	})
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	return s.postWebhook(ctx, webhookURL, payload)
}

func (s *Sender) TestDiscord(ctx context.Context, webhookURL string) error {
	payload, err := json.Marshal(map[string]string{
		"content": testMessage,
	})
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	return s.postWebhook(ctx, webhookURL, payload)
}

func (s *Sender) postWebhook(
	ctx context.Context,
	webhookURL string,
	payload []byte,
) error {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, webhookURL, bytes.NewReader(payload),
	)
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf(
			"webhook: unexpected status %d",
			resp.StatusCode,
		)
	}
	return nil
}
