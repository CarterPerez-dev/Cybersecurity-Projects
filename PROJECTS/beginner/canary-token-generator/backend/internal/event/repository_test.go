// ©AngelaMos | 2026
// repository_test.go

//go:build integration

package event_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/testutil"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
)

func newRepos(t *testing.T) (*sqlx.DB, *token.Repository, *event.Repository) {
	t.Helper()
	db := sqlx.NewDb(testutil.NewTestDB(t), "pgx")
	return db, token.NewRepository(db), event.NewRepository(db)
}

func seedToken(t *testing.T, repo *token.Repository, id string) *token.Token {
	t.Helper()
	tok := &token.Token{
		ID:           id,
		ManageID:     uuid.New().String(),
		Type:         token.TypeWebbug,
		Memo:         "event-test",
		AlertChannel: token.ChannelWebhook,
		WebhookURL:   testutil.Ptr("https://example.com/hook"),
		CreatedIP:    "203.0.113.1",
		CreatedFP:    "abcdef0123456789",
		Metadata:     json.RawMessage(`{}`),
		Enabled:      true,
	}
	require.NoError(t, repo.Insert(context.Background(), tok))
	return tok
}

func TestRepository_InsertAndCount(t *testing.T) {
	t.Parallel()
	_, tokRepo, evtRepo := newRepos(t)
	ctx := context.Background()

	tok := seedToken(t, tokRepo, "evtinsert001")

	for range 3 {
		e := &event.Event{
			TokenID:  tok.ID,
			SourceIP: "203.0.113.45",
		}
		require.NoError(t, evtRepo.Insert(ctx, e))
		require.NotZero(t, e.ID)
		require.False(t, e.TriggeredAt.IsZero())
		require.Equal(t, event.NotifyPending, e.NotifyStatus)
	}

	count, err := evtRepo.CountByToken(ctx, tok.ID)
	require.NoError(t, err)
	require.Equal(t, int64(3), count)
}

func TestRepository_ListByToken_CursorPagination(t *testing.T) {
	t.Parallel()
	_, tokRepo, evtRepo := newRepos(t)
	ctx := context.Background()

	tok := seedToken(t, tokRepo, "evtcursor001")

	for i := range 5 {
		e := &event.Event{
			TokenID:   tok.ID,
			SourceIP:  "203.0.113.45",
			UserAgent: testutil.Ptr(string(rune('A' + i))),
		}
		require.NoError(t, evtRepo.Insert(ctx, e))
	}

	page1, err := evtRepo.ListByToken(ctx, tok.ID, event.ListOptions{Limit: 2})
	require.NoError(t, err)
	require.Len(t, page1.Events, 2)
	require.True(t, page1.HasMore)
	require.NotZero(t, page1.NextCursor)
	require.Equal(t, "E", *page1.Events[0].UserAgent, "newest first")

	page2, err := evtRepo.ListByToken(ctx, tok.ID, event.ListOptions{
		Cursor: page1.NextCursor, Limit: 2,
	})
	require.NoError(t, err)
	require.Len(t, page2.Events, 2)
	require.True(t, page2.HasMore)

	page3, err := evtRepo.ListByToken(ctx, tok.ID, event.ListOptions{
		Cursor: page2.NextCursor, Limit: 2,
	})
	require.NoError(t, err)
	require.Len(t, page3.Events, 1)
	require.False(t, page3.HasMore)
	require.Zero(t, page3.NextCursor)
}

func TestRepository_FKCascade(t *testing.T) {
	t.Parallel()
	_, tokRepo, evtRepo := newRepos(t)
	ctx := context.Background()

	tok := seedToken(t, tokRepo, "evtcascade01")

	for range 3 {
		e := &event.Event{TokenID: tok.ID, SourceIP: "203.0.113.45"}
		require.NoError(t, evtRepo.Insert(ctx, e))
	}

	require.NoError(t, tokRepo.DeleteByManageID(ctx, tok.ManageID))

	count, err := evtRepo.CountByToken(ctx, tok.ID)
	require.NoError(t, err)
	require.Equal(t, int64(0), count, "cascade delete should remove all events")
}

func TestRepository_CountAll(t *testing.T) {
	t.Parallel()
	_, tokRepo, evtRepo := newRepos(t)
	ctx := context.Background()

	tok := seedToken(t, tokRepo, "evtcntallall")

	base, err := evtRepo.CountAll(ctx)
	require.NoError(t, err)

	for range 4 {
		require.NoError(t, evtRepo.Insert(ctx, &event.Event{
			TokenID:  tok.ID,
			SourceIP: "203.0.113.99",
		}))
	}

	got, err := evtRepo.CountAll(ctx)
	require.NoError(t, err)
	require.Equal(t, base+4, got)
}

func TestRepository_AttachFingerprint(t *testing.T) {
	t.Parallel()
	_, tokRepo, evtRepo := newRepos(t)
	ctx := context.Background()

	tok := seedToken(t, tokRepo, "evtfprint001")

	e := &event.Event{
		TokenID:  tok.ID,
		SourceIP: "203.0.113.45",
		Extra:    json.RawMessage(`{"initial":"value"}`),
	}
	require.NoError(t, evtRepo.Insert(ctx, e))

	fp := json.RawMessage(`{"screen":"1920x1080","tz":"America/Los_Angeles"}`)
	require.NoError(t, evtRepo.AttachFingerprint(ctx, tok.ID, "203.0.113.45", fp, 30*time.Second))

	got, err := evtRepo.GetByID(ctx, e.ID)
	require.NoError(t, err)

	var merged map[string]any
	require.NoError(t, json.Unmarshal(got.Extra, &merged))
	require.Equal(t, "value", merged["initial"])
	require.Equal(t, "1920x1080", merged["screen"])
	require.Equal(t, "America/Los_Angeles", merged["tz"])
}

func TestRepository_AttachFingerprint_NoMatch(t *testing.T) {
	t.Parallel()
	_, tokRepo, evtRepo := newRepos(t)
	ctx := context.Background()

	tok := seedToken(t, tokRepo, "evtfpnomtch1")

	fp := json.RawMessage(`{"screen":"1024x768"}`)
	err := evtRepo.AttachFingerprint(ctx, tok.ID, "203.0.113.45", fp, 30*time.Second)
	require.ErrorIs(t, err, event.ErrNotFound)
}

func TestRepository_UpdateNotifyStatus(t *testing.T) {
	t.Parallel()
	_, tokRepo, evtRepo := newRepos(t)
	ctx := context.Background()

	tok := seedToken(t, tokRepo, "evtnotify001")

	e := &event.Event{TokenID: tok.ID, SourceIP: "203.0.113.45"}
	require.NoError(t, evtRepo.Insert(ctx, e))
	require.Equal(t, event.NotifyPending, e.NotifyStatus)

	now := time.Now()
	require.NoError(t, evtRepo.UpdateNotifyStatus(ctx, e.ID, event.NotifySent, &now))

	got, err := evtRepo.GetByID(ctx, e.ID)
	require.NoError(t, err)
	require.Equal(t, event.NotifySent, got.NotifyStatus)
	require.NotNil(t, got.NotifiedAt)
}

func TestRepository_PruneToLimit(t *testing.T) {
	t.Parallel()
	_, tokRepo, evtRepo := newRepos(t)
	ctx := context.Background()

	tokA := seedToken(t, tokRepo, "evtpruneaaa1")
	tokB := seedToken(t, tokRepo, "evtprunebbb1")

	for range 5 {
		require.NoError(t, evtRepo.Insert(ctx, &event.Event{TokenID: tokA.ID, SourceIP: "203.0.113.10"}))
	}
	for range 7 {
		require.NoError(t, evtRepo.Insert(ctx, &event.Event{TokenID: tokB.ID, SourceIP: "203.0.113.20"}))
	}

	deleted, err := evtRepo.PruneToLimit(ctx, 3)
	require.NoError(t, err)
	require.Equal(t, int64((5-3)+(7-3)), deleted, "should delete 2 from A and 4 from B")

	cntA, err := evtRepo.CountByToken(ctx, tokA.ID)
	require.NoError(t, err)
	require.Equal(t, int64(3), cntA)

	cntB, err := evtRepo.CountByToken(ctx, tokB.ID)
	require.NoError(t, err)
	require.Equal(t, int64(3), cntB)
}

func TestRepository_PruneToLimit_KeepsNewest(t *testing.T) {
	t.Parallel()
	_, tokRepo, evtRepo := newRepos(t)
	ctx := context.Background()

	tok := seedToken(t, tokRepo, "evtprunekeep")

	var ids []int64
	for i := range 5 {
		e := &event.Event{TokenID: tok.ID, SourceIP: "203.0.113.45", UserAgent: testutil.Ptr(string(rune('A' + i)))}
		require.NoError(t, evtRepo.Insert(ctx, e))
		ids = append(ids, e.ID)
		time.Sleep(2 * time.Millisecond)
	}

	_, err := evtRepo.PruneToLimit(ctx, 2)
	require.NoError(t, err)

	cnt, err := evtRepo.CountByToken(ctx, tok.ID)
	require.NoError(t, err)
	require.Equal(t, int64(2), cnt)

	_, err = evtRepo.GetByID(ctx, ids[4])
	require.NoError(t, err, "newest should be kept")
	_, err = evtRepo.GetByID(ctx, ids[3])
	require.NoError(t, err, "second-newest should be kept")
	_, err = evtRepo.GetByID(ctx, ids[0])
	require.ErrorIs(t, err, event.ErrNotFound, "oldest should be deleted")
}

func TestRepository_PruneToLimit_RejectsZero(t *testing.T) {
	t.Parallel()
	_, _, evtRepo := newRepos(t)

	_, err := evtRepo.PruneToLimit(context.Background(), 0)
	require.Error(t, err)
}
