/*
©AngelaMos | 2026
migrate.go

Database migration subcommands using goose

Provides up, down, and status subcommands to manage the PostgreSQL
schema lifecycle. Migrations are loaded from the migrations directory
specified in the configuration file.
*/

package cli

import (
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/spf13/cobra"
)

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
	}

	cmd.AddCommand(
		newMigrateUpCmd(),
		newMigrateDownCmd(),
		newMigrateStatusCmd(),
	)

	return cmd
}

func newMigrateUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Apply all pending migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDB(func(db *sql.DB, dir string) error {
				return goose.Up(db, dir)
			})
		},
	}
}

func newMigrateDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Roll back the last migration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDB(func(db *sql.DB, dir string) error {
				return goose.Down(db, dir)
			})
		},
	}
}

func newMigrateStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDB(func(db *sql.DB, dir string) error {
				return goose.Status(db, dir)
			})
		},
	}
}

func withDB(
	fn func(db *sql.DB, dir string) error,
) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	db, err := sql.Open("pgx", cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting dialect: %w", err)
	}

	return fn(db, cfg.Database.MigrationsPath)
}
