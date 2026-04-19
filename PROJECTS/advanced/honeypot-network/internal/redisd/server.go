/*
©AngelaMos | 2026
server.go

Redis RESP protocol honeypot using the redcon library

Listens for Redis client connections and dispatches commands through
the RESP handler. CONFIG SET and SLAVEOF commands are flagged as
exploit attempts commonly used for cryptominer deployment and
unauthorized replication attacks. Every connection and command is
published to the event bus for analysis.
*/

package redisd

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/tidwall/redcon"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	cmdConfigSet = "CONFIG SET"
	cmdSlaveOf   = "SLAVEOF"
	cmdReplicaOf = "REPLICAOF"
	cmdModule    = "MODULE"
)

type connState struct {
	sessionID string
	srcIP     string
	srcPort   int
	keys      *safeStore
}

type RedisService struct {
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
) *RedisService {
	return &RedisService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "redis").Logger(),
		tracker: tracker,
		limiter: limiter,
	}
}

func (s *RedisService) Name() string { return "redis" }

func (s *RedisService) Start(ctx context.Context) error {
	addr := s.cfg.Addr(s.cfg.Redis.Port)

	srv := redcon.NewServer(
		addr, s.handleCmd, s.handleAccept, s.handleClose,
	)

	s.logger.Info().
		Str("addr", addr).
		Msg("redis honeypot listening")

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	return srv.ListenAndServe()
}

func (s *RedisService) handleCmd(
	conn redcon.Conn, cmd redcon.Command,
) {
	state, ok := conn.Context().(*connState)
	if !ok {
		_ = conn.Close()
		return
	}

	cmdName := handleCommand(
		conn, cmd, s.cfg.Redis.ServerVersion,
		state.keys,
	)

	s.publishCommand(state, cmd, cmdName)

	if isExploitCommand(cmdName) {
		s.publishExploit(state, cmd, cmdName)
	}
}

func (s *RedisService) handleAccept(
	conn redcon.Conn,
) bool {
	srcIP, srcPort := parseRedconAddr(conn.RemoteAddr())

	if !s.limiter.Allow(srcIP) {
		return false
	}

	sess := s.tracker.Start(
		s.cfg.Sensor.ID, types.ServiceRedis,
		srcIP, srcPort, s.cfg.Redis.Port,
	)

	conn.SetContext(&connState{
		sessionID: sess.ID,
		srcIP:     srcIP,
		srcPort:   srcPort,
		keys:      newSafeStore(),
	})

	s.publishConnect(sess, srcIP, srcPort)
	return true
}

func (s *RedisService) handleClose(
	conn redcon.Conn, _ error,
) {
	state, ok := conn.Context().(*connState)
	if !ok {
		return
	}

	s.tracker.End(state.sessionID)
	s.publishDisconnect(state)
}

func (s *RedisService) publishConnect(
	sess *types.Session, srcIP string, srcPort int,
) {
	s.bus.Publish(config.TopicConnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceRedis,
		EventType:     types.EventConnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.Redis.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *RedisService) publishDisconnect(state *connState) {
	s.bus.Publish(config.TopicDisconnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     state.sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceRedis,
		EventType:     types.EventDisconnect,
		SourceIP:      state.srcIP,
		SourcePort:    state.srcPort,
		DestPort:      s.cfg.Redis.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *RedisService) publishCommand(
	state *connState,
	cmd redcon.Command,
	cmdName string,
) {
	raw := buildCommandArgs(cmd)

	serviceData, _ := json.Marshal(map[string]string{
		"command": cmdName,
		"raw":     raw,
	})

	s.bus.Publish(config.TopicCommand, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     state.sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceRedis,
		EventType:     types.EventCommand,
		SourceIP:      state.srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

func (s *RedisService) publishExploit(
	state *connState,
	cmd redcon.Command,
	cmdName string,
) {
	raw := buildCommandArgs(cmd)

	tags := []string{"redis-exploit"}
	switch {
	case cmdName == cmdConfigSet:
		tags = append(
			tags, "redis-rce", "mitre:T1059",
		)
	case cmdName == cmdSlaveOf || cmdName == cmdReplicaOf:
		tags = append(
			tags,
			"unauthorized-replication",
			"mitre:T1021",
		)
	case cmdName == cmdModule:
		tags = append(
			tags, "module-load", "mitre:T1059",
		)
	}

	serviceData, _ := json.Marshal(map[string]string{
		"command": cmdName,
		"raw":     raw,
	})

	s.bus.Publish(config.TopicExploit, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     state.sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceRedis,
		EventType:     types.EventExploit,
		SourceIP:      state.srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		Tags:          tags,
		ServiceData:   serviceData,
	})
}

func parseRedconAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func isExploitCommand(cmdName string) bool {
	switch cmdName {
	case cmdConfigSet, cmdSlaveOf, cmdReplicaOf, cmdModule:
		return true
	}
	return false
}

func buildCommandArgs(cmd redcon.Command) string {
	parts := make([]string, len(cmd.Args))
	for i, arg := range cmd.Args {
		parts[i] = string(arg)
	}
	return strings.Join(parts, " ")
}
