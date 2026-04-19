/*
©AngelaMos | 2026
serve.go

The serve subcommand starts all honeypot services

Loads configuration, connects to PostgreSQL and Redis, creates the
event bus, instantiates each enabled honeypot service, wires them
into an errgroup, and blocks until signal or error. Every service
implements types.Service and runs in its own goroutine.
*/

package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/CarterPerez-dev/hive/internal/api"
	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ftpd"
	"github.com/CarterPerez-dev/hive/internal/geo"
	"github.com/CarterPerez-dev/hive/internal/httpd"
	"github.com/CarterPerez-dev/hive/internal/mitre"
	"github.com/CarterPerez-dev/hive/internal/mysqld"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/redisd"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/internal/smbd"
	"github.com/CarterPerez-dev/hive/internal/sshd"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/internal/ui"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start all honeypot services",
		Long: `Start the honeypot network with all enabled services. Each
protocol honeypot runs in its own goroutine, publishing events
to a shared event bus for processing and storage.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context())
		},
	}
}

func runServe(ctx context.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	logger := buildLogger(cfg)

	ui.PrintBanner()

	bus := event.NewBus()
	defer bus.Shutdown()

	tracker := session.NewTracker()
	limiter := ratelimit.NewIPLimiter(
		rate.Every(config.DefaultRateLimitInterval),
		config.DefaultRateLimitBurst,
	)
	defer limiter.Stop()

	detector := mitre.NewDetector()

	pgStore, err := store.NewPgxStore(ctx, cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pgStore.Close()

	if err := pgStore.EnsurePartitions(ctx); err != nil {
		return fmt.Errorf("creating table partitions: %w", err)
	}

	redisStreamer, err := store.NewRedisStreamer(
		cfg.Stream.URL, cfg.Stream.Password,
	)
	if err != nil {
		return fmt.Errorf("connecting to redis stream: %w", err)
	}
	defer func() { _ = redisStreamer.Close() }()

	geoLookup, err := geo.NewLookup(cfg.GeoIP.DBPath)
	if err != nil {
		return fmt.Errorf("loading geoip database: %w", err)
	}
	defer func() { _ = geoLookup.Close() }()

	tracker.SetOnStart(func(sess *types.Session) {
		if err := pgStore.InsertSession(ctx, sess); err != nil {
			logger.Error().Err(err).
				Str("session_id", sess.ID).
				Msg("failed to persist session start")
		}
	})

	tracker.SetOnEnd(func(sess *types.Session) {
		if err := pgStore.UpdateSession(ctx, sess); err != nil {
			logger.Error().Err(err).
				Str("session_id", sess.ID).
				Msg("failed to persist session end")
		}
	})

	proc := event.NewProcessor(
		config.DefaultProcessorWorkers,
		bus,
		pgStore,
		redisStreamer,
		geoLookup,
		detector,
		logger,
	)

	services := buildServices(
		cfg, bus, &logger, tracker, limiter,
	)

	apiSvc := api.New(
		pgStore, bus, detector.Index(),
		tracker, cfg, &logger,
	)
	services = append(services, apiSvc)

	logger.Info().
		Int("services", len(services)).
		Msg("starting honeypot network")

	for _, svc := range services {
		logger.Info().
			Str("service", svc.Name()).
			Msg("service enabled")
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return proc.Start(ctx)
	})

	for _, svc := range services {
		svc := svc
		g.Go(func() error {
			return svc.Start(ctx)
		})
	}

	return g.Wait()
}

func buildLogger(cfg *config.Config) zerolog.Logger {
	level := zerolog.InfoLevel
	if flagVerbose {
		level = zerolog.DebugLevel
	}

	switch cfg.Log.Level {
	case "debug":
		level = zerolog.DebugLevel
	case "warn":
		level = zerolog.WarnLevel
	case "error":
		level = zerolog.ErrorLevel
	}

	if cfg.Log.JSONFormat {
		return zerolog.New(os.Stdout).
			Level(level).
			With().
			Timestamp().
			Str("sensor", cfg.Sensor.ID).
			Logger()
	}

	return zerolog.New(
		zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.Kitchen,
		},
	).Level(level).
		With().
		Timestamp().
		Str("sensor", cfg.Sensor.ID).
		Logger()
}

func buildServices(
	cfg *config.Config,
	bus *event.Bus,
	logger *zerolog.Logger,
	tracker *session.Tracker,
	limiter *ratelimit.IPLimiter,
) []types.Service {
	var services []types.Service

	if cfg.SSH.Enabled {
		hostkey, err := sshd.LoadOrGenerateHostKey(
			cfg.SSH.HostKeyPath,
		)
		if err != nil {
			logger.Error().Err(err).
				Msg("ssh host key unavailable")
		} else {
			services = append(services,
				sshd.New(
					cfg, bus, logger,
					tracker, limiter, hostkey,
				),
			)
		}
	}

	if cfg.HTTP.Enabled {
		services = append(services,
			httpd.New(
				cfg, bus, logger, tracker, limiter,
			),
		)
	}

	if cfg.FTP.Enabled {
		services = append(services,
			ftpd.New(
				cfg, bus, logger, tracker, limiter,
			),
		)
	}

	if cfg.SMB.Enabled {
		services = append(services,
			smbd.New(
				cfg, bus, logger, tracker, limiter,
			),
		)
	}

	if cfg.MySQL.Enabled {
		services = append(services,
			mysqld.New(
				cfg, bus, logger, tracker, limiter,
			),
		)
	}

	if cfg.Redis.Enabled {
		services = append(services,
			redisd.New(
				cfg, bus, logger, tracker, limiter,
			),
		)
	}

	return services
}
