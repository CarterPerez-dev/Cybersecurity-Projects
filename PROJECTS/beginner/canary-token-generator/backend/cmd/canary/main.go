// ©AngelaMos | 2026
// main.go

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
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
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/notify"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/notify/telegram"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/notify/webhook"
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

	notifySvc, eventSvc := buildEventStack(
		cfg, logger, eventRepo, tokenRepo, rdb,
	)
	tokenSvc, verifier, healthH, tokenH := buildHTTPDeps(
		cfg, logger, db, rdb, eventRepo, tokenRepo, eventSvc,
	)
	srv := mountRouter(cfg, logger, rdb, healthH, tokenH, verifier)

	var wg sync.WaitGroup
	spawnMySQLListener(ctx, cfg, logger, &wg, tokenSvc, eventSvc)
	spawnRetentionLoop(ctx, cfg, &wg, eventSvc)

	errChan := make(chan error, 1)
	go func() { errChan <- srv.Start() }()

	select {
	case startErr := <-errChan:
		return startErr
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownErr := gracefulShutdown(cfg, logger, srv, telemetry, rdb, db)
	logger.Info("waiting for in-flight notifications")
	notifySvc.Wait()
	wg.Wait()
	return shutdownErr
}

func buildHTTPDeps(
	cfg *config.Config,
	logger *slog.Logger,
	db *core.Database,
	rdb *core.Redis,
	eventRepo *event.Repository,
	tokenRepo *token.Repository,
	eventSvc *event.Service,
) (*token.Service, *turnstile.Verifier, *health.Handler, *token.Handler) {
	genRegistry := registry.Build(registry.Config{
		BaseURL:         cfg.Canary.BaseURL,
		MySQLPublicHost: cfg.MySQL.PublicHost,
		MySQLPublicPort: cfg.MySQL.PublicPort,
	})
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
		&eventRecorderAdapter{svc: eventSvc},
		&fingerprintRecorderAdapter{
			repo:   eventRepo,
			window: cfg.Notify.FingerprintWindow,
		},
		eventRepo,
		eventSvc,
		logger,
	)
	return tokenSvc, verifier, healthH, tokenH
}

func buildEventStack(
	cfg *config.Config,
	logger *slog.Logger,
	eventRepo *event.Repository,
	tokenRepo *token.Repository,
	rdb *core.Redis,
) (*notify.Service, *event.Service) {
	tgSender := telegram.NewSender(telegram.Config{
		APIBase:         cfg.Notify.TelegramAPIBase,
		ManageURL:       cfg.Canary.ManageURL,
		MaxTries:        cfg.Notify.MaxTries,
		MaxElapsed:      cfg.Notify.MaxElapsed,
		InitialInterval: cfg.Notify.InitialInterval,
	})
	whSender := webhook.NewSender(webhook.Config{
		ManageURL:       cfg.Canary.ManageURL,
		HMACSecret:      cfg.Notify.WebhookHMACSecret,
		MaxTries:        cfg.Notify.MaxTries,
		MaxElapsed:      cfg.Notify.MaxElapsed,
		InitialInterval: cfg.Notify.InitialInterval,
	})

	notifySvc := notify.NewService(eventRepo,
		notify.WithLogger(logger),
		notify.WithSendTimeout(cfg.Notify.SendTimeout),
	)
	notifySvc.Register(tgSender, whSender)

	eventSvc := event.NewService(
		eventRepo,
		tokenRepo,
		rdb.Client,
		notifySvc,
		event.ServiceConfig{
			DedupTTL: cfg.Notify.DedupTTL,
			Logger:   logger,
		},
	)
	return notifySvc, eventSvc
}

func spawnMySQLListener(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	wg *sync.WaitGroup,
	tokenSvc *token.Service,
	eventSvc *event.Service,
) {
	if !cfg.MySQL.Enabled {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		handler := mysql.NewHandler(
			&mysqlTokenLookup{svc: tokenSvc},
			&eventRecorderAdapter{svc: eventSvc},
		)
		if mErr := mysql.Run(ctx, cfg.MySQL.Addr, handler); mErr != nil {
			logger.Error("mysql server error", "error", mErr)
		}
	}()
}

func spawnRetentionLoop(
	ctx context.Context,
	cfg *config.Config,
	wg *sync.WaitGroup,
	eventSvc *event.Service,
) {
	if cfg.Notify.RetentionInterval <= 0 || cfg.Notify.RetentionLimit <= 0 {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		eventSvc.RunRetentionLoop(
			ctx,
			cfg.Notify.RetentionInterval,
			cfg.Notify.RetentionLimit,
		)
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

	createMin := middleware.NewRateLimiter(
		rdb.Client,
		middleware.RateLimitConfig{
			Limit: middleware.PerMinute(
				cfg.RateLimit.CreateMinRate,
				cfg.RateLimit.CreateMinBurst,
			),
			KeyFunc:  keyByCreateMin,
			FailOpen: true,
		},
	).Handler
	createHour := middleware.NewRateLimiter(
		rdb.Client,
		middleware.RateLimitConfig{
			Limit: middleware.PerHour(
				cfg.RateLimit.CreateHourRate,
				cfg.RateLimit.CreateHourBurst,
			),
			KeyFunc:  keyByCreateHour,
			FailOpen: true,
		},
	).Handler

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
		api.With(
			createMin,
			createHour,
			middleware.TurnstileVerify(verifier),
		).Post("/tokens", tokenH.CreateToken)
		tokenH.RegisterManageRoutes(api)
	})

	return srv
}

func keyByCreateMin(r *http.Request) string {
	return "ratelimit:create:min:" + middleware.ExtractFingerprint(r)
}

func keyByCreateHour(r *http.Request) string {
	return "ratelimit:create:hour:" + middleware.ExtractFingerprint(r)
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

type eventRecorderAdapter struct {
	svc *event.Service
}

func (a *eventRecorderAdapter) Record(
	ctx context.Context,
	t *token.Token,
	evt *event.Event,
) error {
	return a.svc.Record(ctx, t.NotifyInfo(), evt)
}

type fingerprintRecorderAdapter struct {
	repo   *event.Repository
	window time.Duration
}

func (f *fingerprintRecorderAdapter) AttachFingerprint(
	ctx context.Context,
	tokenID, sourceIP string,
	fingerprint json.RawMessage,
) error {
	return f.repo.AttachFingerprint(
		ctx,
		tokenID,
		sourceIP,
		fingerprint,
		f.window,
	)
}

type mysqlTokenLookup struct{ svc *token.Service }

func (m *mysqlTokenLookup) GetByID(
	ctx context.Context,
	id string,
) (*token.Token, error) {
	return m.svc.GetByID(ctx, id)
}
