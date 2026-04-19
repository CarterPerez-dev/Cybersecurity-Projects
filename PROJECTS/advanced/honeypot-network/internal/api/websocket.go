/*
©AngelaMos | 2026
websocket.go

Real-time event streaming over WebSocket

Clients connect to /ws/events and receive a JSON stream of honeypot
events as they occur. Each connection subscribes to the event bus
all-topic and forwards events as text frames until the client
disconnects or the server shuts down.
*/

package api

import (
	"encoding/json"
	"net/http"

	"nhooyr.io/websocket"

	"github.com/CarterPerez-dev/hive/internal/config"
)

func (s *Server) handleWebSocket(
	w http.ResponseWriter, r *http.Request,
) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: s.cfg.API.CORSOrigins,
	})
	if err != nil {
		s.logger.Error().Err(err).
			Msg("websocket accept failed")
		return
	}
	defer func() { _ = conn.CloseNow() }()

	ctx := r.Context()

	events := s.bus.Subscribe(
		wsEventBuffer, config.TopicAll,
	)
	defer s.bus.Unsubscribe(events)

	s.logger.Debug().
		Str("remote", r.RemoteAddr).
		Msg("websocket client connected")

	for {
		select {
		case <-ctx.Done():
			_ = conn.Close(
				websocket.StatusNormalClosure,
				"server shutting down",
			)
			return

		case ev, ok := <-events:
			if !ok {
				_ = conn.Close(
					websocket.StatusNormalClosure,
					"event bus closed",
				)
				return
			}

			data, marshalErr := json.Marshal(ev)
			if marshalErr != nil {
				s.logger.Error().Err(marshalErr).
					Msg("marshaling websocket event")
				continue
			}

			if writeErr := conn.Write(
				ctx, websocket.MessageText, data,
			); writeErr != nil {
				s.logger.Debug().
					Str("remote", r.RemoteAddr).
					Msg("websocket client disconnected")
				return
			}
		}
	}
}
