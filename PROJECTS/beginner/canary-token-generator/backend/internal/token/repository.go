// ©AngelaMos | 2026
// repository.go

package token

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jmoiron/sqlx"
)

var ErrNotFound = errors.New("token not found")

const defaultListLimit = 50

type Repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

const insertSQL = `
INSERT INTO tokens (
    id, manage_id, type, memo, filename,
    alert_channel, telegram_bot, telegram_chat, webhook_url,
    created_ip, created_fp, metadata, enabled
) VALUES (
    :id, :manage_id, :type, :memo, :filename,
    :alert_channel, :telegram_bot, :telegram_chat, :webhook_url,
    :created_ip, :created_fp, :metadata, :enabled
)
RETURNING created_at, trigger_count, last_triggered`

func (r *Repository) Insert(ctx context.Context, t *Token) error {
	stmt, err := r.db.PrepareNamedContext(ctx, insertSQL)
	if err != nil {
		return fmt.Errorf("prepare insert token: %w", err)
	}
	defer func() {
		if cerr := stmt.Close(); cerr != nil {
			slog.WarnContext(ctx, "close prepared stmt",
				"op", "insert_token", "error", cerr)
		}
	}()

	if err := stmt.GetContext(ctx, t, t); err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

const selectColumns = `
    id, manage_id, type, memo, filename,
    alert_channel, telegram_bot, telegram_chat, webhook_url,
    created_at, created_ip, created_fp, enabled,
    trigger_count, last_triggered, metadata`

func (r *Repository) GetByID(ctx context.Context, id string) (*Token, error) {
	var t Token
	q := `SELECT ` + selectColumns + ` FROM tokens WHERE id = $1`
	err := r.db.GetContext(ctx, &t, q, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get token by id: %w", err)
	}
	return &t, nil
}

func (r *Repository) GetByManageID(
	ctx context.Context,
	manageID string,
) (*Token, error) {
	var t Token
	q := `SELECT ` + selectColumns + ` FROM tokens WHERE manage_id = $1`
	err := r.db.GetContext(ctx, &t, q, manageID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get token by manage_id: %w", err)
	}
	return &t, nil
}

func (r *Repository) DeleteByManageID(
	ctx context.Context,
	manageID string,
) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE manage_id = $1`, manageID)
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
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

func (r *Repository) IncrementTriggerCount(
	ctx context.Context,
	id string,
) error {
	_, err := r.db.ExecContext(ctx, `
        UPDATE tokens
           SET trigger_count = trigger_count + 1,
               last_triggered = NOW()
         WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("increment trigger count: %w", err)
	}
	return nil
}

func (r *Repository) SetEnabled(
	ctx context.Context,
	id string,
	enabled bool,
) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE tokens SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return fmt.Errorf("set enabled: %w", err)
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

type ListOptions struct {
	Limit  int
	Offset int
}

func (r *Repository) ListAll(
	ctx context.Context,
	opts ListOptions,
) ([]Token, error) {
	if opts.Limit <= 0 {
		opts.Limit = defaultListLimit
	}
	q := `SELECT ` + selectColumns + ` FROM tokens
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2`
	var tokens []Token
	if err := r.db.SelectContext(
		ctx,
		&tokens,
		q,
		opts.Limit,
		opts.Offset,
	); err != nil {
		return nil, fmt.Errorf("list all tokens: %w", err)
	}
	return tokens, nil
}

func (r *Repository) CountAll(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.GetContext(
		ctx,
		&n,
		`SELECT COUNT(*) FROM tokens`,
	); err != nil {
		return 0, fmt.Errorf("count tokens: %w", err)
	}
	return n, nil
}

type TypeCount struct {
	Type  Type  `db:"type"  json:"type"`
	Count int64 `db:"count" json:"count"`
}

type ChannelCount struct {
	Channel AlertChannel `db:"alert_channel" json:"alert_channel"`
	Count   int64        `db:"count"         json:"count"`
}

func (r *Repository) CountByType(
	ctx context.Context,
) ([]TypeCount, error) {
	rows := []TypeCount{}
	q := `SELECT type, COUNT(*) AS count
	        FROM tokens
	       GROUP BY type
	       ORDER BY type`
	if err := r.db.SelectContext(ctx, &rows, q); err != nil {
		return nil, fmt.Errorf("count tokens by type: %w", err)
	}
	return rows, nil
}

func (r *Repository) CountByAlertChannel(
	ctx context.Context,
) ([]ChannelCount, error) {
	rows := []ChannelCount{}
	q := `SELECT alert_channel, COUNT(*) AS count
	        FROM tokens
	       GROUP BY alert_channel
	       ORDER BY alert_channel`
	if err := r.db.SelectContext(ctx, &rows, q); err != nil {
		return nil, fmt.Errorf("count tokens by channel: %w", err)
	}
	return rows, nil
}
