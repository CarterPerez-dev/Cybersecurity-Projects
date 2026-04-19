/*
©AngelaMos | 2026
router.go

Chi-based HTTP router for the hive dashboard API

Mounts all REST endpoints and the WebSocket handler behind a
middleware chain of panic recovery, CORS, and request logging.
Implements the types.Service interface so the API server
participates in the errgroup-managed lifecycle alongside the
honeypot services.
*/

package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/mitre"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	defaultPageLimit     = 50
	maxPageLimit         = 500
	defaultStatsDuration = 24 * time.Hour
	defaultCredentialTop = 20
	defaultAttackerTop   = 50
	corsMaxAgeSeconds    = "86400"
	wsEventBuffer        = 256
)

type Server struct {
	store     store.Store
	bus       *event.Bus
	mitreIdx  *mitre.Index
	tracker   *session.Tracker
	cfg       *config.Config
	logger    *zerolog.Logger
	router    *chi.Mux
	replayDir string
	startedAt time.Time
}

func New(
	db store.Store,
	bus *event.Bus,
	mitreIdx *mitre.Index,
	tracker *session.Tracker,
	cfg *config.Config,
	logger *zerolog.Logger,
) *Server {
	s := &Server{
		store:     db,
		bus:       bus,
		mitreIdx:  mitreIdx,
		tracker:   tracker,
		cfg:       cfg,
		logger:    logger,
		replayDir: cfg.Log.ReplayDir,
		startedAt: time.Now().UTC(),
	}

	s.router = s.buildRouter()
	return s
}

func (s *Server) Name() string {
	return "api"
}

func (s *Server) Start(ctx context.Context) error {
	addr := s.cfg.Addr(s.cfg.API.Port)

	srv := &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  s.cfg.API.ReadTimeout,
		WriteTimeout: s.cfg.API.WriteTimeout,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			config.DefaultShutdownTimeout,
		)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.logger.Info().
		Str("addr", addr).
		Msg("api server listening")

	if err := srv.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		return fmt.Errorf("api server: %w", err)
	}

	return nil
}

func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Use(recoverer(s.logger))
	r.Use(corsMiddleware(s.cfg.API.CORSOrigins))
	r.Use(requestLogger(s.logger))

	r.Route("/api", func(r chi.Router) {
		r.Get("/health", s.handleHealth)

		r.Route("/stats", func(r chi.Router) {
			r.Get("/overview", s.handleStatsOverview)
			r.Get("/countries", s.handleStatsCountries)
			r.Get(
				"/credentials",
				s.handleStatsCredentials,
			)
		})

		r.Route("/events", func(r chi.Router) {
			r.Get("/", s.handleEvents)
		})

		r.Route("/sessions", func(r chi.Router) {
			r.Get("/", s.handleSessions)
			r.Get("/{id}", s.handleSessionByID)
			r.Get(
				"/{id}/replay",
				s.handleSessionReplay,
			)
		})

		r.Route("/attackers", func(r chi.Router) {
			r.Get("/", s.handleAttackers)
			r.Get("/{id}", s.handleAttackerByID)
		})

		r.Route("/mitre", func(r chi.Router) {
			r.Get(
				"/techniques",
				s.handleMITRETechniques,
			)
			r.Get("/heatmap", s.handleMITREHeatmap)
		})

		r.Route("/iocs", func(r chi.Router) {
			r.Get("/", s.handleIOCs)
			r.Get(
				"/export/stix",
				s.handleIOCExportSTIX,
			)
			r.Get(
				"/export/blocklist",
				s.handleIOCExportBlocklist,
			)
		})

		r.Get("/sensors", s.handleSensors)
	})

	r.Get("/ws/events", s.handleWebSocket)

	return r
}

var _ types.Service = (*Server)(nil)
