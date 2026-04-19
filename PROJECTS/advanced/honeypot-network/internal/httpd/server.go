/*
©AngelaMos | 2026
server.go

HTTP honeypot service emulating a WordPress/phpMyAdmin web server

Routes requests to fake WordPress login pages, phpMyAdmin panels,
and common vulnerability probe paths like .env, .git/config, and
wp-config.php. The Server header is spoofed to match Apache on
Ubuntu. All requests pass through the capture middleware before
reaching route handlers.
*/

package httpd

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/session"
)

type HTTPService struct {
	cfg     *config.Config
	bus     *event.Bus
	logger  zerolog.Logger
	tracker *session.Tracker
	limiter *ratelimit.IPLimiter
}

func New(
	cfg *config.Config,
	bus *event.Bus,
	logger *zerolog.Logger,
	tracker *session.Tracker,
	limiter *ratelimit.IPLimiter,
) *HTTPService {
	return &HTTPService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "http").Logger(),
		tracker: tracker,
		limiter: limiter,
	}
}

func (s *HTTPService) Name() string { return "http" }

func (s *HTTPService) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	s.setupRoutes(mux)

	handler := requestLogger(
		s.bus, s.tracker, s.limiter, s.cfg, mux,
	)

	addr := s.cfg.Addr(s.cfg.HTTP.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  config.DefaultReadTimeout,
		WriteTimeout: config.DefaultWriteTimeout,
	}

	s.logger.Info().
		Str("addr", addr).
		Msg("http honeypot listening")

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *HTTPService) setupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/wp-login.php", handleWPLogin)
	mux.HandleFunc("/wp-admin/", handleWPAdmin)
	mux.HandleFunc("/xmlrpc.php", handleXMLRPC)

	mux.HandleFunc("/phpmyadmin/", handlePMA)
	mux.HandleFunc("/pma/", handlePMA)
	mux.HandleFunc("/phpMyAdmin/", handlePMA)

	mux.HandleFunc("/.env", handleSensitiveFile)
	mux.HandleFunc("/.git/config", handleGitConfig)
	mux.HandleFunc(
		"/.git/HEAD", handleGitHead,
	)
	mux.HandleFunc(
		"/config.php", handleSensitiveFile,
	)
	mux.HandleFunc(
		"/wp-config.php", handleSensitiveFile,
	)
	mux.HandleFunc(
		"/wp-config.php.bak", handleSensitiveFile,
	)
	mux.HandleFunc(
		"/.aws/credentials", handleSensitiveFile,
	)
	mux.HandleFunc(
		"/server-status", handleServerStatus,
	)
	mux.HandleFunc("/robots.txt", handleRobots)

	mux.HandleFunc("/", handleDefault)
}

func handleSensitiveFile(
	w http.ResponseWriter, r *http.Request,
) {
	http.Error(
		w, "403 Forbidden", http.StatusForbidden,
	)
}

func handleGitConfig(
	w http.ResponseWriter, _ *http.Request,
) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w,
		"[core]\n"+
			"\trepositoryformatversion = 0\n"+
			"\tfilemode = true\n"+
			"\tbare = false\n"+
			"[remote \"origin\"]\n"+
			"\turl = https://github.com/example/webapp.git\n"+
			"\tfetch = +refs/heads/*:refs/remotes/origin/*\n"+
			"[branch \"main\"]\n"+
			"\tremote = origin\n"+
			"\tmerge = refs/heads/main\n",
	)
}

func handleGitHead(
	w http.ResponseWriter, _ *http.Request,
) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "ref: refs/heads/main\n")
}

func handleServerStatus(
	w http.ResponseWriter, r *http.Request,
) {
	http.Error(
		w, "403 Forbidden", http.StatusForbidden,
	)
}

const robotsTxt = "User-agent: *\n" +
	"Disallow: /wp-admin/\n" +
	"Allow: /wp-admin/admin-ajax.php\n\n" +
	"Sitemap: /sitemap.xml\n"

func handleRobots(
	w http.ResponseWriter, _ *http.Request,
) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, robotsTxt)
}

const defaultHTML = `<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h1>Welcome</h1>
<p>This site is currently under maintenance. Please check back later.</p>
</body>
</html>`

func handleDefault(
	w http.ResponseWriter, r *http.Request,
) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set(
		"Content-Type", "text/html; charset=UTF-8",
	)
	fmt.Fprint(w, defaultHTML)
}
