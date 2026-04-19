/*
©AngelaMos | 2026
middleware.go

Request capture middleware for the HTTP honeypot

Wraps every incoming HTTP request to capture the full method, path,
headers, and body. Publishes request events to the event bus and
runs user-agent scanner detection. Each request gets its own
session for tracking in the event pipeline.
*/

package httpd

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

const maxBodyCapture = 64 * 1024

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

func requestLogger(
	bus *event.Bus,
	tracker *session.Tracker,
	limiter *ratelimit.IPLimiter,
	cfg *config.Config,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			srcIP, srcPort := parseHTTPAddr(r)

			if !limiter.Allow(srcIP) {
				http.Error(
					w,
					"429 Too Many Requests",
					http.StatusTooManyRequests,
				)
				return
			}

			sess := tracker.Start(
				cfg.Sensor.ID, types.ServiceHTTP,
				srcIP, srcPort, cfg.HTTP.Port,
			)
			defer tracker.End(sess.ID)

			var body []byte
			if r.Body != nil {
				body, _ = io.ReadAll(
					io.LimitReader(r.Body, maxBodyCapture),
				)
				r.Body = io.NopCloser(bytes.NewReader(body))
			}

			w.Header().Set("Server", cfg.HTTP.ServerHeader)

			sw := &statusWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}
			next.ServeHTTP(sw, r)

			headers := make(
				map[string]string, len(r.Header),
			)
			for k, v := range r.Header {
				headers[k] = strings.Join(v, "; ")
			}

			serviceData, _ := json.Marshal(
				map[string]interface{}{
					"method":     r.Method,
					"path":       r.URL.Path,
					"query":      r.URL.RawQuery,
					"headers":    headers,
					"body":       string(body),
					"status":     sw.status,
					"user_agent": r.UserAgent(),
				},
			)

			bus.Publish(config.TopicCommand, &types.Event{
				ID:            uuid.Must(uuid.NewV7()).String(),
				SessionID:     sess.ID,
				SensorID:      cfg.Sensor.ID,
				Timestamp:     time.Now().UTC(),
				ServiceType:   types.ServiceHTTP,
				EventType:     types.EventRequest,
				SourceIP:      srcIP,
				SourcePort:    srcPort,
				DestPort:      cfg.HTTP.Port,
				Protocol:      types.ProtocolTCP,
				SchemaVersion: config.SchemaVersion,
				ServiceData:   serviceData,
			})

			scanner := DetectScanner(r.UserAgent())
			if scanner != "" {
				scanData, _ := json.Marshal(
					map[string]string{
						"scanner":    scanner,
						"user_agent": r.UserAgent(),
						"path":       r.URL.Path,
					},
				)
				bus.Publish(
					config.TopicScan,
					&types.Event{
						ID:            uuid.Must(uuid.NewV7()).String(),
						SessionID:     sess.ID,
						SensorID:      cfg.Sensor.ID,
						Timestamp:     time.Now().UTC(),
						ServiceType:   types.ServiceHTTP,
						EventType:     types.EventScan,
						SourceIP:      srcIP,
						Protocol:      types.ProtocolTCP,
						SchemaVersion: config.SchemaVersion,
						Tags: []string{
							"scanner:" + scanner,
							"mitre:T1595",
						},
						ServiceData: scanData,
					},
				)
			}
		},
	)
}

func parseHTTPAddr(
	r *http.Request,
) (string, int) {
	host, portStr, err := net.SplitHostPort(
		r.RemoteAddr,
	)
	if err != nil {
		return r.RemoteAddr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}
