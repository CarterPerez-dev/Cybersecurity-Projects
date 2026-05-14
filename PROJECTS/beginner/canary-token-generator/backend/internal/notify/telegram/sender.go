// ©AngelaMos | 2026
// sender.go

package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
)

const (
	Channel = "telegram"

	defaultAPIBase         = "https://api.telegram.org"
	defaultMaxTries        = 3
	defaultMaxElapsed      = 30 * time.Second
	defaultInitialInterval = 500 * time.Millisecond
	defaultOverallTimeout  = 10 * time.Second
	defaultDialTimeout     = 5 * time.Second

	uaTruncateRunes = 80

	parseModeMarkdownV2 = "MarkdownV2"
	contentTypeJSON     = "application/json"

	v2SpecialChars = "_*[]()~`>#+-=|{}.!"
)

var (
	ErrChannelNotConfigured = errors.New(
		"telegram: bot token or chat id not configured",
	)
	ErrTelegramAPI = errors.New("telegram: api error")
)

type Config struct {
	APIBase         string
	ManageURL       string
	HTTPClient      *http.Client
	MaxTries        uint
	MaxElapsed      time.Duration
	InitialInterval time.Duration
}

type Option func(*Config)

func WithMaxTries(n uint) Option {
	return func(c *Config) { c.MaxTries = n }
}

func WithMaxElapsed(d time.Duration) Option {
	return func(c *Config) { c.MaxElapsed = d }
}

func WithInitialInterval(d time.Duration) Option {
	return func(c *Config) { c.InitialInterval = d }
}

func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) { c.HTTPClient = client }
}

type Sender struct {
	apiBase         string
	manageURL       string
	httpClient      *http.Client
	maxTries        uint
	maxElapsed      time.Duration
	initialInterval time.Duration
}

func NewSender(cfg Config, opts ...Option) *Sender {
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.APIBase == "" {
		cfg.APIBase = defaultAPIBase
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultHTTPClient()
	}
	if cfg.MaxTries == 0 {
		cfg.MaxTries = defaultMaxTries
	}
	if cfg.MaxElapsed == 0 {
		cfg.MaxElapsed = defaultMaxElapsed
	}
	if cfg.InitialInterval == 0 {
		cfg.InitialInterval = defaultInitialInterval
	}
	return &Sender{
		apiBase:         strings.TrimRight(cfg.APIBase, "/"),
		manageURL:       strings.TrimRight(cfg.ManageURL, "/"),
		httpClient:      cfg.HTTPClient,
		maxTries:        cfg.MaxTries,
		maxElapsed:      cfg.MaxElapsed,
		initialInterval: cfg.InitialInterval,
	}
}

func defaultHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: defaultDialTimeout}
	return &http.Client{
		Timeout: defaultOverallTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   defaultDialTimeout,
			ResponseHeaderTimeout: defaultOverallTimeout,
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       30 * time.Second,
		},
	}
}

func (s *Sender) Channel() string { return Channel }

func (s *Sender) Send(
	ctx context.Context,
	info event.NotifyInfo,
	evt *event.Event,
) error {
	if info.TelegramBot == "" || info.TelegramChat == "" {
		return ErrChannelNotConfigured
	}
	endpoint := s.apiBase + "/bot" + info.TelegramBot + "/sendMessage"
	body, err := json.Marshal(map[string]string{
		"chat_id":    info.TelegramChat,
		"text":       buildMessage(info, evt, s.manageURL),
		"parse_mode": parseModeMarkdownV2,
	})
	if err != nil {
		return fmt.Errorf("telegram: marshal body: %w", err)
	}

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = s.initialInterval
	expBackoff.MaxInterval = 5 * time.Second

	_, err = backoff.Retry(
		ctx,
		func() (struct{}, error) {
			return struct{}{}, s.doRequest(ctx, endpoint, body)
		},
		backoff.WithBackOff(expBackoff),
		backoff.WithMaxTries(s.maxTries),
		backoff.WithMaxElapsedTime(s.maxElapsed),
	)
	return err
}

func (s *Sender) doRequest(
	ctx context.Context,
	endpoint string,
	body []byte,
) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return backoff.Permanent(
			fmt.Errorf("telegram: build request: %w", err),
		)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram: do request: %w", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			slog.WarnContext(ctx, "telegram: close body",
				"error", cErr)
		}
	}()

	respBody, rErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if rErr != nil {
		slog.WarnContext(ctx, "telegram: read body", "error", rErr)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return backoff.Permanent(fmt.Errorf(
			"%w: status=%d body=%s",
			ErrTelegramAPI, resp.StatusCode, string(respBody),
		))
	default:
		return fmt.Errorf(
			"%w: status=%d body=%s",
			ErrTelegramAPI, resp.StatusCode, string(respBody),
		)
	}
}

func buildMessage(
	info event.NotifyInfo,
	evt *event.Event,
	manageURL string,
) string {
	var b strings.Builder
	b.WriteString("🚨 *Canary triggered:* ")
	b.WriteString(EscapeMD(info.Memo))
	b.WriteString("\n\n*Type:* ")
	b.WriteString(EscapeMD(info.Type))
	b.WriteString("\n*From:* ")
	b.WriteString(EscapeMD(evt.SourceIP))
	if loc := formatGeo(evt); loc != "" {
		b.WriteString(" ")
		b.WriteString(loc)
	}
	b.WriteString("\n*Time:* ")
	b.WriteString(EscapeMD(evt.TriggeredAt.UTC().Format(time.RFC3339)))
	if evt.UserAgent != nil && *evt.UserAgent != "" {
		b.WriteString("\n*UA:* ")
		b.WriteString(EscapeMD(truncateRunes(*evt.UserAgent, uaTruncateRunes)))
	}
	if manageURL != "" && info.ManageID != "" {
		b.WriteString("\n\n[View full event timeline](")
		b.WriteString(manageURL + "/m/" + info.ManageID)
		b.WriteString(")")
	}
	return b.String()
}

func formatGeo(evt *event.Event) string {
	city := derefStr(evt.GeoCity)
	country := derefStr(evt.GeoCountry)
	asnOrg := derefStr(evt.GeoASNOrg)

	var parens string
	switch {
	case city != "" && country != "":
		parens = `\(` + EscapeMD(city) + ", " + EscapeMD(country) + `\)`
	case country != "":
		parens = `\(` + EscapeMD(country) + `\)`
	case city != "":
		parens = `\(` + EscapeMD(city) + `\)`
	}
	if parens == "" && asnOrg == "" {
		return ""
	}
	if asnOrg == "" {
		return parens
	}
	if parens == "" {
		return "— " + EscapeMD(asnOrg)
	}
	return parens + " — " + EscapeMD(asnOrg)
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

func EscapeMD(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if strings.ContainsRune(v2SpecialChars, r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
