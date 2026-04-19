/*
©AngelaMos | 2026
server.go

MySQL honeypot service accepting database client connections

Emulates a MySQL 5.7 server using the raw wire protocol. Accepts
all authentication attempts, logs credentials and queries, and
returns realistic responses to common SQL commands. Automated tools
targeting exposed MySQL instances will interact long enough for
the honeypot to capture their full attack sequence.
*/

package mysqld

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type MySQLService struct {
	cfg     *config.Config
	bus     *event.Bus
	logger  zerolog.Logger
	tracker *session.Tracker
	limiter *ratelimit.IPLimiter
	connID  atomic.Uint32
}

func New(
	cfg *config.Config,
	bus *event.Bus,
	logger *zerolog.Logger,
	tracker *session.Tracker,
	limiter *ratelimit.IPLimiter,
) *MySQLService {
	return &MySQLService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "mysql").Logger(),
		tracker: tracker,
		limiter: limiter,
	}
}

func (s *MySQLService) Name() string { return "mysql" }

func (s *MySQLService) Start(
	ctx context.Context,
) error {
	addr := s.cfg.Addr(s.cfg.MySQL.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf(
			"mysql listen %s: %w", addr, err,
		)
	}

	s.logger.Info().
		Str("addr", addr).
		Msg("mysql honeypot listening")

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			s.logger.Debug().
				Err(err).Msg("accept failed")
			continue
		}

		go s.handleConnection(ctx, conn)
	}

	return nil
}

func (s *MySQLService) handleConnection(
	ctx context.Context, conn net.Conn,
) {
	defer func() { _ = conn.Close() }()

	srcIP, srcPort := types.RemoteAddr(conn)
	if !s.limiter.Allow(srcIP) {
		return
	}

	sess := s.tracker.Start(
		s.cfg.Sensor.ID, types.ServiceMySQL,
		srcIP, srcPort, s.cfg.MySQL.Port,
	)
	defer s.tracker.End(sess.ID)

	s.publishConnect(sess, srcIP, srcPort)
	defer s.publishDisconnect(sess, srcIP, srcPort)

	connID := s.connID.Add(1)

	greeting := buildGreeting(
		s.cfg.MySQL.ServerVersion, connID,
	)
	if err := writePacket(conn, 0, greeting); err != nil {
		return
	}

	seq, authData, err := readPacket(conn)
	if err != nil {
		return
	}

	username := parseAuthUsername(authData)
	s.publishAuth(sess.ID, srcIP, username)
	s.tracker.SetLogin(sess.ID, true, username, "")

	if err := writePacket(
		conn, seq+1, okPacket(),
	); err != nil {
		return
	}

	for {
		if ctx.Err() != nil {
			return
		}

		seq, data, err := readPacket(conn)
		if err != nil || len(data) == 0 {
			return
		}

		cmd := data[0]
		payload := ""
		if len(data) > 1 {
			payload = string(data[1:])
		}

		switch cmd {
		case comQuit:
			return

		case comPing:
			_ = writePacket(conn, seq+1, okPacket())

		case comInitDB:
			s.publishCommand(
				sess.ID, srcIP, "USE "+payload,
			)
			_ = writePacket(conn, seq+1, okPacket())

		case comQuery:
			s.publishCommand(
				sess.ID, srcIP, payload,
			)
			s.tracker.IncrCommandCount(sess.ID)

			result := handleQuery(payload)
			if result != nil {
				_ = writeResultSet(conn, seq, result)
			} else {
				_ = writePacket(
					conn, seq+1, okPacket(),
				)
			}

		default:
			_ = writePacket(
				conn, seq+1,
				errPacket(
					1047, "08S01",
					"Unknown command",
				),
			)
		}
	}
}

func (s *MySQLService) publishConnect(
	sess *types.Session,
	srcIP string,
	srcPort int,
) {
	s.bus.Publish(config.TopicConnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceMySQL,
		EventType:     types.EventConnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.MySQL.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *MySQLService) publishDisconnect(
	sess *types.Session,
	srcIP string,
	srcPort int,
) {
	s.bus.Publish(config.TopicDisconnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceMySQL,
		EventType:     types.EventDisconnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.MySQL.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *MySQLService) publishAuth(
	sessionID string,
	srcIP string,
	username string,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"username":    username,
		"auth_method": "mysql_native_password",
	})

	s.bus.Publish(config.TopicAuth, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceMySQL,
		EventType:     types.EventLoginSuccess,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

func (s *MySQLService) publishCommand(
	sessionID string,
	srcIP string,
	query string,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"query": query,
	})

	s.bus.Publish(config.TopicCommand, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceMySQL,
		EventType:     types.EventCommand,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}
