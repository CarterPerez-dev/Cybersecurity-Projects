// ©AngelaMos | 2026
// handler.go

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
)

const (
	urlParamID = "id"

	queryParamOffset = "offset"
	queryParamLimit  = "limit"

	defaultPageSize = 50
	maxPageSize     = 100

	headerContentType = "Content-Type"
	contentTypeJSON   = "application/json"

	errorCodeNotFound      = "NOT_FOUND"
	errorCodeBadParam      = "BAD_PARAM"
	errorCodeInternalError = "INTERNAL_ERROR"

	respMessageNotFound      = "not found"
	respMessageBadOffset     = "invalid offset"
	respMessageInternalError = "internal server error"
)

type TokenRepository interface {
	ListAll(ctx context.Context, opts token.ListOptions) ([]token.Token, error)
	CountAll(ctx context.Context) (int64, error)
	CountByType(ctx context.Context) ([]token.TypeCount, error)
	CountByAlertChannel(ctx context.Context) ([]token.ChannelCount, error)
	SetEnabled(ctx context.Context, id string, enabled bool) error
}

type EventRepository interface {
	CountAll(ctx context.Context) (int64, error)
}

type URLBuilder interface {
	TriggerURL(id string) string
	ManageURL(manageID string) string
}

type Handler struct {
	tokens TokenRepository
	events EventRepository
	urls   URLBuilder
	logger *slog.Logger
}

func NewHandler(
	tokens TokenRepository,
	events EventRepository,
	urls URLBuilder,
	logger *slog.Logger,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		tokens: tokens,
		events: events,
		urls:   urls,
		logger: logger,
	}
}

func (h *Handler) Register(r chi.Router) {
	r.Get("/stats", h.GetStats)
	r.Get("/tokens", h.ListTokens)
	r.Post("/tokens/{"+urlParamID+"}/disable", h.DisableToken)
}

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tokensCount, err := h.tokens.CountAll(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "admin: count tokens", "error", err)
		h.writeInternal(w)
		return
	}
	eventsCount, err := h.events.CountAll(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "admin: count events", "error", err)
		h.writeInternal(w)
		return
	}
	byType, err := h.tokens.CountByType(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "admin: count by type", "error", err)
		h.writeInternal(w)
		return
	}
	byChannel, err := h.tokens.CountByAlertChannel(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "admin: count by channel", "error", err)
		h.writeInternal(w)
		return
	}

	stats := Stats{
		TokensCount:    tokensCount,
		EventsCount:    eventsCount,
		ByType:         byType,
		ByAlertChannel: byChannel,
	}
	h.writeJSON(w, http.StatusOK, envelopeData(stats))
}

func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	offset, err := parseOffset(r.URL.Query().Get(queryParamOffset))
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, envelopeError(
			errorCodeBadParam, respMessageBadOffset,
		))
		return
	}
	limit := parseLimit(r.URL.Query().Get(queryParamLimit))

	rows, err := h.tokens.ListAll(ctx, token.ListOptions{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "admin: list tokens", "error", err)
		h.writeInternal(w)
		return
	}

	total, err := h.tokens.CountAll(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "admin: count tokens", "error", err)
		h.writeInternal(w)
		return
	}

	out := make([]token.Response, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].ToResponse(
			h.urls.TriggerURL(rows[i].ID),
			h.urls.ManageURL(rows[i].ManageID),
		))
	}

	next := offset + len(rows)
	hasMore := int64(next) < total

	resp := TokenListResponse{
		Tokens: out,
		Total:  total,
		Page: TokenListPage{
			NextOffset: next,
			HasMore:    hasMore,
		},
	}
	h.writeJSON(w, http.StatusOK, envelopeData(resp))
}

func (h *Handler) DisableToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, urlParamID)
	if id == "" {
		h.writeJSON(w, http.StatusNotFound, envelopeError(
			errorCodeNotFound, respMessageNotFound,
		))
		return
	}

	if err := h.tokens.SetEnabled(r.Context(), id, false); err != nil {
		if errors.Is(err, token.ErrNotFound) {
			h.writeJSON(w, http.StatusNotFound, envelopeError(
				errorCodeNotFound, respMessageNotFound,
			))
			return
		}
		h.logger.ErrorContext(r.Context(), "admin: disable token",
			"error", err, "token_id", id)
		h.writeInternal(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseOffset(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0, errors.New("invalid offset")
	}
	return v, nil
}

func parseLimit(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultPageSize
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return defaultPageSize
	}
	if v > maxPageSize {
		return maxPageSize
	}
	return v
}

func (h *Handler) writeJSON(
	w http.ResponseWriter,
	status int,
	body any,
) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger.Warn("write json response", "error", err)
	}
}

func (h *Handler) writeInternal(w http.ResponseWriter) {
	h.writeJSON(w, http.StatusInternalServerError, envelopeError(
		errorCodeInternalError, respMessageInternalError,
	))
}

func envelopeData(data any) map[string]any {
	return map[string]any{"success": true, "data": data}
}

func envelopeError(code, message string) map[string]any {
	return map[string]any{
		"success": false,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
}
