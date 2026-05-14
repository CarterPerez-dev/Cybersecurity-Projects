// ©AngelaMos | 2026
// dto.go

package admin

import (
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
)

type Stats struct {
	TokensCount    int64                `json:"tokens_count"`
	EventsCount    int64                `json:"events_count"`
	ByType         []token.TypeCount    `json:"by_type"`
	ByAlertChannel []token.ChannelCount `json:"by_alert_channel"`
}

type TokenListPage struct {
	NextOffset int  `json:"next_offset"`
	HasMore    bool `json:"has_more"`
}

type TokenListResponse struct {
	Tokens []token.Response `json:"tokens"`
	Total  int64            `json:"total"`
	Page   TokenListPage    `json:"page"`
}
