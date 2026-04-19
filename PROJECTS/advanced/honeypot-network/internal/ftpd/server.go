/*
©AngelaMos | 2026
server.go

FTP honeypot service accepting file transfer client connections

Emulates a ProFTPD 1.3.8b server with accept-all authentication.
Logs every credential attempt, command, and uploaded file to the
event bus. PASV mode data channels are opened on demand for
directory listings and upload capture.
*/

package ftpd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type FTPService struct {
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
) *FTPService {
	return &FTPService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "ftp").Logger(),
		tracker: tracker,
		limiter: limiter,
	}
}

func (s *FTPService) Name() string { return "ftp" }

func (s *FTPService) Start(
	ctx context.Context,
) error {
	addr := s.cfg.Addr(s.cfg.FTP.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf(
			"ftp listen %s: %w", addr, err,
		)
	}

	s.logger.Info().
		Str("addr", addr).
		Msg("ftp honeypot listening")

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

func (s *FTPService) handleConnection(
	ctx context.Context, conn net.Conn,
) {
	defer func() { _ = conn.Close() }()

	srcIP, srcPort := types.RemoteAddr(conn)
	if !s.limiter.Allow(srcIP) {
		return
	}

	sess := s.tracker.Start(
		s.cfg.Sensor.ID, types.ServiceFTP,
		srcIP, srcPort, s.cfg.FTP.Port,
	)
	defer s.tracker.End(sess.ID)

	s.publishConnect(sess, srcIP, srcPort)
	defer s.publishDisconnect(sess, srcIP, srcPort)

	fc := newFTPConn(conn)
	defer fc.close()

	fmt.Fprintf(
		fc.ctrl, "%s\r\n", s.cfg.FTP.Banner,
	)

	for {
		if ctx.Err() != nil {
			return
		}

		cmd, arg, err := fc.readLine()
		if err != nil {
			return
		}

		result := fc.dispatch(cmd, arg)

		s.publishCommand(
			sess.ID, srcIP, cmd, arg,
		)

		if result.password != "" {
			s.publishAuth(
				sess.ID, srcIP,
				fc.username, result.password,
			)
			s.tracker.SetLogin(
				sess.ID, true, fc.username, "",
			)
		}

		if result.upload != nil {
			s.publishUpload(
				sess.ID, srcIP,
				result.filename, result.upload,
			)
		}

		if result.quit {
			return
		}
	}
}

func (s *FTPService) publishConnect(
	sess *types.Session,
	srcIP string,
	srcPort int,
) {
	s.bus.Publish(config.TopicConnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceFTP,
		EventType:     types.EventConnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.FTP.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *FTPService) publishDisconnect(
	sess *types.Session,
	srcIP string,
	srcPort int,
) {
	s.bus.Publish(config.TopicDisconnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceFTP,
		EventType:     types.EventDisconnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.FTP.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *FTPService) publishAuth(
	sessionID string,
	srcIP string,
	username string,
	password string,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"username":    username,
		"password":    password,
		"auth_method": "password",
	})

	s.bus.Publish(config.TopicAuth, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceFTP,
		EventType:     types.EventLoginSuccess,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

func (s *FTPService) publishCommand(
	sessionID string,
	srcIP string,
	cmd string,
	arg string,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"command": cmd,
		"arg":     arg,
	})

	s.bus.Publish(config.TopicCommand, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceFTP,
		EventType:     types.EventCommand,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

func (s *FTPService) publishUpload(
	sessionID string,
	srcIP string,
	filename string,
	data []byte,
) {
	serviceData, _ := json.Marshal(
		map[string]interface{}{
			"filename": filename,
			"size":     len(data),
		},
	)

	s.bus.Publish(config.TopicFile, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceFTP,
		EventType:     types.EventFileUpload,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		Tags: []string{
			"file-upload", "mitre:T1105",
		},
		ServiceData: serviceData,
	})
}
