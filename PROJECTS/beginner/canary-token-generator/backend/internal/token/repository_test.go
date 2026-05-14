// ©AngelaMos | 2026
// repository_test.go

//go:build integration

package token_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/testutil"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
)

func newRepo(t *testing.T) *token.Repository {
	t.Helper()
	db := sqlx.NewDb(testutil.NewTestDB(t), "pgx")
	return token.NewRepository(db)
}

func sampleWebhookToken(id string) *token.Token {
	return &token.Token{
		ID:           id,
		ManageID:     uuid.New().String(),
		Type:         token.TypeWebbug,
		Memo:         "test webbug",
		AlertChannel: token.ChannelWebhook,
		WebhookURL:   testutil.Ptr("https://example.com/hook"),
		CreatedIP:    "203.0.113.10",
		CreatedFP:    "0123456789abcdef",
		Metadata:     json.RawMessage(`{}`),
		Enabled:      true,
	}
}

func sampleTelegramToken(id string) *token.Token {
	return &token.Token{
		ID:           id,
		ManageID:     uuid.New().String(),
		Type:         token.TypeDocx,
		Memo:         "Q4 bonuses",
		Filename:     testutil.Ptr("Q4_Bonuses_2024.docx"),
		AlertChannel: token.ChannelTelegram,
		TelegramBot:  testutil.Ptr("123456:ABCDEF"),
		TelegramChat: testutil.Ptr("-1001234567890"),
		CreatedIP:    "198.51.100.5",
		CreatedFP:    "fedcba9876543210",
		Metadata:     json.RawMessage(`{"include_keys":["aws"]}`),
		Enabled:      true,
	}
}

func TestRepository_InsertAndGetByID(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	tok := sampleWebhookToken("abcdef0123ko")
	require.NoError(t, repo.Insert(ctx, tok))
	require.False(t, tok.CreatedAt.IsZero(), "Insert should populate created_at via RETURNING")

	got, err := repo.GetByID(ctx, tok.ID)
	require.NoError(t, err)

	require.Equal(t, tok.ID, got.ID)
	require.Equal(t, tok.ManageID, got.ManageID)
	require.Equal(t, tok.Type, got.Type)
	require.Equal(t, tok.AlertChannel, got.AlertChannel)
	require.Equal(t, tok.Memo, got.Memo)
	require.NotNil(t, got.WebhookURL)
	require.Equal(t, "https://example.com/hook", *got.WebhookURL)
	require.True(t, got.Enabled)
	require.Equal(t, int64(0), got.TriggerCount)
}

func TestRepository_GetByID_NotFound(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)

	_, err := repo.GetByID(context.Background(), "doesnotexist")
	require.ErrorIs(t, err, token.ErrNotFound)
}

func TestRepository_GetByManageID(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	tok := sampleTelegramToken("mngabcdef012")
	require.NoError(t, repo.Insert(ctx, tok))

	got, err := repo.GetByManageID(ctx, tok.ManageID)
	require.NoError(t, err)

	require.Equal(t, tok.ID, got.ID)
	require.Equal(t, token.ChannelTelegram, got.AlertChannel)
	require.NotNil(t, got.TelegramBot)
	require.Equal(t, "123456:ABCDEF", *got.TelegramBot)
}

func TestRepository_GetByManageID_NotFound(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)

	_, err := repo.GetByManageID(context.Background(), uuid.New().String())
	require.ErrorIs(t, err, token.ErrNotFound)
}

func TestRepository_DeleteByManageID(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	tok := sampleWebhookToken("delok0123abc")
	require.NoError(t, repo.Insert(ctx, tok))

	require.NoError(t, repo.DeleteByManageID(ctx, tok.ManageID))

	_, err := repo.GetByID(ctx, tok.ID)
	require.ErrorIs(t, err, token.ErrNotFound)
}

func TestRepository_DeleteByManageID_NotFound(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)

	err := repo.DeleteByManageID(context.Background(), uuid.New().String())
	require.True(t, errors.Is(err, token.ErrNotFound))
}

func TestRepository_IncrementTriggerCount(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	tok := sampleWebhookToken("trgcount001a")
	require.NoError(t, repo.Insert(ctx, tok))

	require.NoError(t, repo.IncrementTriggerCount(ctx, tok.ID))
	require.NoError(t, repo.IncrementTriggerCount(ctx, tok.ID))

	got, err := repo.GetByID(ctx, tok.ID)
	require.NoError(t, err)
	require.Equal(t, int64(2), got.TriggerCount)
	require.NotNil(t, got.LastTriggered)
}

func TestRepository_SetEnabled(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	tok := sampleWebhookToken("setenab0001a")
	require.NoError(t, repo.Insert(ctx, tok))

	require.NoError(t, repo.SetEnabled(ctx, tok.ID, false))

	got, err := repo.GetByID(ctx, tok.ID)
	require.NoError(t, err)
	require.False(t, got.Enabled)

	require.NoError(t, repo.SetEnabled(ctx, tok.ID, true))
	got, err = repo.GetByID(ctx, tok.ID)
	require.NoError(t, err)
	require.True(t, got.Enabled)
}

func TestRepository_SetEnabled_NotFound(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)

	err := repo.SetEnabled(context.Background(), "nonexistent", false)
	require.ErrorIs(t, err, token.ErrNotFound)
}

func TestRepository_ListAll(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	for _, id := range []string{"lstaaaaaaaa1", "lstbbbbbbbb2", "lstcccccccc3"} {
		tok := sampleWebhookToken(id)
		tok.Memo = "list-test-" + id
		require.NoError(t, repo.Insert(ctx, tok))
	}

	got, err := repo.ListAll(ctx, token.ListOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, got, 3)

	count, err := repo.CountAll(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(3), count)
}

func TestRepository_CountByType(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	webbug := sampleWebhookToken("cntbytype01a")
	webbug.Type = token.TypeWebbug
	require.NoError(t, repo.Insert(ctx, webbug))

	webbug2 := sampleWebhookToken("cntbytype01b")
	webbug2.Type = token.TypeWebbug
	require.NoError(t, repo.Insert(ctx, webbug2))

	docx := sampleTelegramToken("cntbytype02a")
	docx.Type = token.TypeDocx
	require.NoError(t, repo.Insert(ctx, docx))

	rows, err := repo.CountByType(ctx)
	require.NoError(t, err)

	got := map[token.Type]int64{}
	for _, r := range rows {
		got[r.Type] = r.Count
	}
	require.GreaterOrEqual(t, got[token.TypeWebbug], int64(2))
	require.GreaterOrEqual(t, got[token.TypeDocx], int64(1))
}

func TestRepository_CountByAlertChannel(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	wh := sampleWebhookToken("cntbychan01a")
	require.NoError(t, repo.Insert(ctx, wh))

	tg := sampleTelegramToken("cntbychan02a")
	require.NoError(t, repo.Insert(ctx, tg))

	rows, err := repo.CountByAlertChannel(ctx)
	require.NoError(t, err)

	got := map[token.AlertChannel]int64{}
	for _, r := range rows {
		got[r.Channel] = r.Count
	}
	require.GreaterOrEqual(t, got[token.ChannelWebhook], int64(1))
	require.GreaterOrEqual(t, got[token.ChannelTelegram], int64(1))
}

func TestRepository_TypeAndChannelValidation(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)

	bad := sampleWebhookToken("badtypee0001")
	bad.Type = "invalid_type"

	err := repo.Insert(context.Background(), bad)
	require.Error(t, err, "DB CHECK should reject invalid type")
}
