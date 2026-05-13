// ©AngelaMos | 2026
// main.go

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/config"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/core"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/health"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/server"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/mysql"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/registry"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/turnstile"
)

const (
	drainDelay         = 5 * time.Second
	shutdownGraceExtra = 5 * time.Second
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		slog.Error("application error", "error", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	logger := setupLogger(cfg.Log)
	slog.SetDefault(logger)
	logger.Info("starting canary-token-generator",
		"version", cfg.App.Version,
		"environment", cfg.App.Environment,
	)

	telemetry := initTelemetry(ctx, cfg, logger)

	db, err := core.NewDatabase(ctx, cfg.Database)
	if err != nil {
		return err
	}
	logger.Info("database connected")

	if err = core.RunMigrations(db.SQLDB()); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	logger.Info("migrations applied")

	tokenRepo := token.NewRepository(db.DB)
	eventRepo := event.NewRepository(db.DB)

	rdb, err := core.NewRedis(ctx, cfg.Redis)
	if err != nil {
		return err
	}
	logger.Info("redis connected")

	genRegistry := registry.Build(registry.Config{BaseURL: cfg.Canary.BaseURL})
	tokenSvc := token.NewService(
		tokenRepo,
		registryAdapter{r: genRegistry},
		token.ServiceConfig{
			BaseURL:   cfg.Canary.BaseURL,
			ManageURL: cfg.Canary.ManageURL,
		},
	)

	verifier := turnstile.NewVerifier(
		turnstile.Config{SecretKey: cfg.Turnstile.SecretKey},
		rdb.Client,
	)

	healthH := health.NewHandler(db, rdb)
	tokenH := token.NewHandler(
		tokenSvc,
		&directEventRecorder{
			repo:   eventRepo,
			tokens: tokenRepo,
			logger: logger,
		},
		nil,
		logger,
	)

	srv := mountRouter(cfg, logger, rdb, healthH, tokenH, verifier)

	var wg sync.WaitGroup
	spawnMySQLListener(ctx, cfg, logger, &wg, tokenSvc, eventRepo, tokenRepo)

	errChan := make(chan error, 1)
	go func() { errChan <- srv.Start() }()

	select {
	case startErr := <-errChan:
		return startErr
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownErr := gracefulShutdown(cfg, logger, srv, telemetry, rdb, db)
	wg.Wait()
	return shutdownErr
}

func spawnMySQLListener(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	wg *sync.WaitGroup,
	tokenSvc *token.Service,
	eventRepo *event.Repository,
	tokenRepo *token.Repository,
) {
	if !cfg.MySQL.Enabled {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		handler := mysql.NewHandler(
			&mysqlTokenLookup{svc: tokenSvc},
			&mysqlEventRecorder{
				repo:   eventRepo,
				tokens: tokenRepo,
				logger: logger,
			},
		)
		if mErr := mysql.Run(ctx, cfg.MySQL.Addr, handler); mErr != nil {
			logger.Error("mysql server error", "error", mErr)
		}
	}()
}

func mountRouter(
	cfg *config.Config,
	logger *slog.Logger,
	rdb *core.Redis,
	healthH *health.Handler,
	tokenH *token.Handler,
	verifier *turnstile.Verifier,
) *server.Server {
	srv := server.New(server.Config{
		ServerConfig:  cfg.Server,
		HealthHandler: healthH,
		Logger:        logger,
	})
	r := srv.Router()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger(logger))
	r.Use(middleware.Recovery(logger))
	r.Use(middleware.SecurityHeaders(cfg.App.Environment == "production"))

	healthH.RegisterRoutes(r)
	tokenH.RegisterTriggerRoutes(r)

	r.Route("/api", func(api chi.Router) {
		api.Use(middleware.CORS(cfg.CORS))
		api.Use(
			middleware.NewRateLimiter(rdb.Client, middleware.RateLimitConfig{
				Limit: middleware.PerMinute(
					cfg.RateLimit.Requests,
					cfg.RateLimit.Burst,
				),
				KeyFunc:  middleware.KeyByFingerprint,
				FailOpen: true,
			}).Handler,
		)
		api.Get("/tokens/types", tokenH.GetTypes)
		api.With(middleware.TurnstileVerify(verifier)).
			Post("/tokens", tokenH.CreateToken)
	})

	return srv
}

func gracefulShutdown(
	cfg *config.Config,
	logger *slog.Logger,
	srv *server.Server,
	telemetry *core.Telemetry,
	rdb *core.Redis,
	db *core.Database,
) error {
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		cfg.Server.ShutdownTimeout+drainDelay+shutdownGraceExtra,
	)
	defer cancel()

	var errs []error
	if err := srv.Shutdown(shutdownCtx, drainDelay); err != nil {
		logger.Error("server shutdown error", "error", err)
		errs = append(errs, fmt.Errorf("server shutdown: %w", err))
	}
	if telemetry != nil {
		if err := telemetry.Shutdown(shutdownCtx); err != nil {
			logger.Error("telemetry shutdown error", "error", err)
			errs = append(errs, fmt.Errorf("telemetry shutdown: %w", err))
		}
	}
	if err := rdb.Close(); err != nil {
		logger.Error("redis close error", "error", err)
		errs = append(errs, fmt.Errorf("redis close: %w", err))
	}
	if err := db.Close(); err != nil {
		logger.Error("database close error", "error", err)
		errs = append(errs, fmt.Errorf("database close: %w", err))
	}

	logger.Info("application stopped")
	return errors.Join(errs...)
}

func initTelemetry(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
) *core.Telemetry {
	if !cfg.Otel.Enabled {
		return nil
	}
	t, err := core.NewTelemetry(ctx, cfg.Otel, cfg.App)
	if err != nil {
		logger.Warn("telemetry init failed", "error", err)
		return nil
	}
	return t
}

func setupLogger(cfg config.LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

type registryAdapter struct{ r registry.Registry }

func (a registryAdapter) Get(t token.Type) (token.Generator, bool) {
	g, ok := a.r[t]
	return g, ok
}

type directEventRecorder struct {
	repo   *event.Repository
	tokens *token.Repository
	logger *slog.Logger
}

func (d *directEventRecorder) Record(
	ctx context.Context,
	t *token.Token,
	evt *event.Event,
) error {
	if err := d.repo.Insert(ctx, evt); err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	if err := d.tokens.IncrementTriggerCount(ctx, t.ID); err != nil {
		d.logger.WarnContext(ctx, "increment trigger count",
			"error", err, "token_id", t.ID)
	}
	return nil
}

type mysqlTokenLookup struct{ svc *token.Service }

func (m *mysqlTokenLookup) GetByID(
	ctx context.Context,
	id string,
) (*token.Token, error) {
	return m.svc.GetByID(ctx, id)
}

type mysqlEventRecorder struct {
	repo   *event.Repository
	tokens *token.Repository
	logger *slog.Logger
}

func (m *mysqlEventRecorder) Record(
	ctx context.Context,
	t *token.Token,
	evt *event.Event,
) error {
	if err := m.repo.Insert(ctx, evt); err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	if err := m.tokens.IncrementTriggerCount(ctx, t.ID); err != nil {
		m.logger.WarnContext(ctx, "mysql: increment trigger count",
			"error", err, "token_id", t.ID)
	}
	return nil
}
