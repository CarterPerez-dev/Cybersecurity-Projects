// AngelaMos | 2026
// repository.go

package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/core"
)

type Repository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
	UpdatePassword(ctx context.Context, id, passwordHash string) error
	UpdateEmail(ctx context.Context, id, email string) error
	IncrementTokenVersion(ctx context.Context, id string) error
	SoftDelete(ctx context.Context, id string) error
	List(ctx context.Context, params ListUsersParams) ([]User, int, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
}

type repository struct {
	db core.DBTX
}

func NewRepository(db core.DBTX) Repository {
	return &repository{db: db}
}

func (r *repository) Create(ctx context.Context, user *User) error {
	query := `
		INSERT INTO users (id, email, password_hash, name, role, tier)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at, updated_at, token_version`

	err := r.db.GetContext(ctx, user, query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.Name,
		user.Role,
		user.Tier,
	)
	if err != nil {
		if isDuplicateKeyError(err) {
			return fmt.Errorf("create user: %w", core.ErrDuplicateKey)
		}
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

func (r *repository) GetByID(ctx context.Context, id string) (*User, error) {
	query := `
		SELECT id, email, password_hash, name, role, tier, token_version,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL`

	var user User
	err := r.db.GetContext(ctx, &user, query, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get user: %w", core.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	return &user, nil
}

func (r *repository) GetByEmail(
	ctx context.Context,
	email string,
) (*User, error) {
	query := `
		SELECT id, email, password_hash, name, role, tier, token_version,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL`

	var user User
	err := r.db.GetContext(ctx, &user, query, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get user by email: %w", core.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	return &user, nil
}

func (r *repository) Update(ctx context.Context, user *User) error {
	query := `
		UPDATE users
		SET name = $2, role = $3, tier = $4, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING updated_at`

	err := r.db.GetContext(ctx, &user.UpdatedAt, query,
		user.ID,
		user.Name,
		user.Role,
		user.Tier,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("update user: %w", core.ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	return nil
}

func (r *repository) UpdatePassword(
	ctx context.Context,
	id, passwordHash string,
) error {
	query := `
		UPDATE users
		SET password_hash = $2, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, id, passwordHash)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("update password: %w", core.ErrNotFound)
	}

	return nil
}

func (r *repository) UpdateEmail(ctx context.Context, id, email string) error {
	query := `
		UPDATE users
		SET email = $2, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, id, email)
	if err != nil {
		if isDuplicateKeyError(err) {
			return fmt.Errorf("update email: %w", core.ErrDuplicateKey)
		}
		return fmt.Errorf("update email: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update email: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("update email: %w", core.ErrNotFound)
	}
	return nil
}

func (r *repository) IncrementTokenVersion(
	ctx context.Context,
	id string,
) error {
	query := `
		UPDATE users
		SET token_version = token_version + 1, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("increment token version: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("increment token version: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("increment token version: %w", core.ErrNotFound)
	}

	return nil
}

func (r *repository) SoftDelete(ctx context.Context, id string) error {
	query := `
		UPDATE users
		SET deleted_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("delete user: %w", core.ErrNotFound)
	}

	return nil
}

func (r *repository) List(
	ctx context.Context,
	params ListUsersParams,
) ([]User, int, error) {
	params.Normalize()

	var conditions []string
	var args []any
	argIdx := 1

	conditions = append(conditions, "deleted_at IS NULL")

	if params.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(email ILIKE $%d OR name ILIKE $%d)", argIdx, argIdx,
		))
		args = append(args, "%"+escapeLike(params.Search)+"%")
		argIdx++
	}

	if params.Role != "" {
		conditions = append(conditions, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, params.Role)
		argIdx++
	}

	if params.Tier != "" {
		conditions = append(conditions, fmt.Sprintf("tier = $%d", argIdx))
		args = append(args, params.Tier)
		argIdx++
	}

	whereClause := strings.Join(conditions, " AND ")

	countQuery := fmt.Sprintf(
		"SELECT COUNT(*) FROM users WHERE %s",
		whereClause,
	)
	var total int
	if err := r.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT id, email, name, role, tier, token_version,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		whereClause, argIdx, argIdx+1)

	args = append(args, params.PageSize, params.Offset())

	var users []User
	if err := r.db.SelectContext(ctx, &users, query, args...); err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}

	return users, total, nil
}

func (r *repository) ExistsByEmail(
	ctx context.Context,
	email string,
) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`

	var exists bool
	if err := r.db.GetContext(ctx, &exists, query, email); err != nil {
		return false, fmt.Errorf("check email exists: %w", err)
	}

	return exists, nil
}

func isDuplicateKeyError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}
