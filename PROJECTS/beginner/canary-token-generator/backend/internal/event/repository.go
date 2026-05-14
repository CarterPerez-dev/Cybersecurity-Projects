// ©AngelaMos | 2026
// repository.go

package event

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jmoiron/sqlx"
)

var ErrNotFound = errors.New("event not found")

const defaultListLimit = 20

type Repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

const insertSQL = `
INSERT INTO events (
    token_id, source_ip, user_agent, referer,
    geo_country, geo_region, geo_city, geo_asn, geo_asn_org,
    extra, notify_status
) VALUES (
    :token_id, :source_ip, :user_agent, :referer,
    :geo_country, :geo_region, :geo_city, :geo_asn, :geo_asn_org,
    :extra, :notify_status
)
RETURNING id, triggered_at`

func (r *Repository) Insert(ctx context.Context, e *Event) error {
	if e.NotifyStatus == "" {
		e.NotifyStatus = NotifyPending
	}
	if len(e.Extra) == 0 {
		e.Extra = json.RawMessage(`{}`)
	}

	stmt, err := r.db.PrepareNamedContext(ctx, insertSQL)
	if err != nil {
		return fmt.Errorf("prepare insert event: %w", err)
	}
	defer func() {
		if cerr := stmt.Close(); cerr != nil {
			slog.WarnContext(ctx, "close prepared stmt",
				"op", "insert_event", "error", cerr)
		}
	}()

	if err := stmt.GetContext(ctx, e, e); err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

const selectColumns = `
    id, token_id, triggered_at,
    source_ip, user_agent, referer,
    geo_country, geo_region, geo_city, geo_asn, geo_asn_org,
    extra, notify_status, notified_at`

type ListOptions struct {
	Cursor int64
	Limit  int
}

type ListResult struct {
	Events     []Event
	NextCursor int64
	HasMore    bool
}

func (r *Repository) ListByToken(
	ctx context.Context, tokenID string, opts ListOptions,
) (ListResult, error) {
	if opts.Limit <= 0 {
		opts.Limit = defaultListLimit
	}

	q := `SELECT ` + selectColumns + `
            FROM events
           WHERE token_id = $1
             AND ($2 = 0 OR id < $2)
           ORDER BY id DESC
           LIMIT $3`

	var events []Event
	err := r.db.SelectContext(
		ctx,
		&events,
		q,
		tokenID,
		opts.Cursor,
		opts.Limit+1,
	)
	if err != nil {
		return ListResult{}, fmt.Errorf("list events: %w", err)
	}

	hasMore := len(events) > opts.Limit
	if hasMore {
		events = events[:opts.Limit]
	}

	var next int64
	if hasMore && len(events) > 0 {
		next = events[len(events)-1].ID
	}

	return ListResult{
		Events:     events,
		NextCursor: next,
		HasMore:    hasMore,
	}, nil
}

func (r *Repository) CountByToken(
	ctx context.Context,
	tokenID string,
) (int64, error) {
	var n int64
	err := r.db.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM events WHERE token_id = $1`, tokenID)
	if err != nil {
		return 0, fmt.Errorf("count events: %w", err)
	}
	return n, nil
}

func (r *Repository) CountAll(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.GetContext(
		ctx,
		&n,
		`SELECT COUNT(*) FROM events`,
	); err != nil {
		return 0, fmt.Errorf("count events: %w", err)
	}
	return n, nil
}

func (r *Repository) AttachFingerprint(
	ctx context.Context,
	tokenID, sourceIP string,
	fingerprint json.RawMessage,
	window time.Duration,
) error {
	q := `
UPDATE events
   SET extra = extra || $3::jsonb
 WHERE id = (
     SELECT id FROM events
      WHERE token_id = $1
        AND source_ip = $2::inet
        AND triggered_at >= NOW() - $4::interval
      ORDER BY id DESC
      LIMIT 1
 )`
	res, err := r.db.ExecContext(
		ctx,
		q,
		tokenID,
		sourceIP,
		[]byte(fingerprint),
		fmt.Sprintf("%d milliseconds", window.Milliseconds()),
	)
	if err != nil {
		return fmt.Errorf("attach fingerprint: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) UpdateNotifyStatus(
	ctx context.Context, eventID int64, status NotifyStatus, sentAt *time.Time,
) error {
	q := `
UPDATE events
   SET notify_status = $2, notified_at = $3
 WHERE id = $1`
	res, err := r.db.ExecContext(ctx, q, eventID, status, sentAt)
	if err != nil {
		return fmt.Errorf("update notify status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) PruneToLimit(
	ctx context.Context,
	perTokenLimit int,
) (int64, error) {
	if perTokenLimit <= 0 {
		return 0, errors.New("perTokenLimit must be positive")
	}
	q := `
WITH ranked AS (
    SELECT id,
           row_number() OVER (PARTITION BY token_id ORDER BY triggered_at DESC) AS rn
      FROM events
)
DELETE FROM events
 WHERE id IN (SELECT id FROM ranked WHERE rn > $1)`
	res, err := r.db.ExecContext(ctx, q, perTokenLimit)
	if err != nil {
		return 0, fmt.Errorf("prune events: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

func (r *Repository) GetByID(ctx context.Context, id int64) (*Event, error) {
	var e Event
	q := `SELECT ` + selectColumns + ` FROM events WHERE id = $1`
	err := r.db.GetContext(ctx, &e, q, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get event by id: %w", err)
	}
	return &e, nil
}
