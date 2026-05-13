// ©AngelaMos | 2026
// recovery.go

package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

const (
	recoveryContentType = "application/json"
	recoveryBody        = `{"success":false,"error":{"code":"INTERNAL_ERROR","message":"internal server error"}}`
)

func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				requestID := ""
				if rid, ok := r.Context().Value(RequestIDKey).(string); ok {
					requestID = rid
				}
				logger.ErrorContext(r.Context(), "handler panic",
					"panic", rec,
					"request_id", requestID,
					"path", r.URL.Path,
					"method", r.Method,
					"stack", string(debug.Stack()),
				)
				w.Header().Set("Content-Type", recoveryContentType)
				w.WriteHeader(http.StatusInternalServerError)
				if _, err := w.Write([]byte(recoveryBody)); err != nil {
					logger.WarnContext(r.Context(), "recovery write",
						"error", err)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
