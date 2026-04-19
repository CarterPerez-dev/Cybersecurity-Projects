/*
©AngelaMos | 2026
middleware.go

HTTP middleware chain for the dashboard REST API

Provides request logging with structured JSON output, panic
recovery that returns 500 without crashing the process, and CORS
handling for browser-based dashboard clients. Each middleware is
a standard func(http.Handler) http.Handler closure.
*/

package api

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

type statusWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	return n, err
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf(
		"underlying ResponseWriter does not implement http.Hijacker",
	)
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func requestLogger(
	logger *zerolog.Logger,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(
				w http.ResponseWriter,
				r *http.Request,
			) {
				start := time.Now()
				sw := &statusWriter{
					ResponseWriter: w,
					status:         http.StatusOK,
				}

				next.ServeHTTP(sw, r)

				logger.Info().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Int("status", sw.status).
					Int("bytes", sw.size).
					Dur("latency", time.Since(start)).
					Str("remote", r.RemoteAddr).
					Msg("api request")
			},
		)
	}
}

func recoverer(
	logger *zerolog.Logger,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(
				w http.ResponseWriter,
				r *http.Request,
			) {
				defer func() {
					if rec := recover(); rec != nil {
						logger.Error().
							Interface("panic", rec).
							Str("path", r.URL.Path).
							Str("method", r.Method).
							Msg("recovered from panic")
						http.Error(
							w,
							http.StatusText(
								http.StatusInternalServerError,
							),
							http.StatusInternalServerError,
						)
					}
				}()
				next.ServeHTTP(w, r)
			},
		)
	}
}

func corsMiddleware(
	origins []string,
) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		allowed[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(
				w http.ResponseWriter,
				r *http.Request,
			) {
				origin := r.Header.Get("Origin")
				if allowed[origin] || allowed["*"] {
					w.Header().Set(
						"Access-Control-Allow-Origin",
						origin,
					)
				}

				w.Header().Set(
					"Access-Control-Allow-Methods",
					"GET, POST, OPTIONS",
				)
				w.Header().Set(
					"Access-Control-Allow-Headers",
					"Content-Type, Authorization",
				)
				w.Header().Set(
					"Access-Control-Max-Age",
					corsMaxAgeSeconds,
				)

				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}

				next.ServeHTTP(w, r)
			},
		)
	}
}
