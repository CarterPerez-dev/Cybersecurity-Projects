/*
©AngelaMos | 2026
server.go

SSH honeypot service accepting all authentication attempts

Emulates an OpenSSH server with accept-all password and public key
callbacks. After authentication, provides an interactive shell with
a fake filesystem and command execution. Logs every connection,
credential attempt, and session to the event bus. Uses the SSH
server version banner from config to avoid honeypot fingerprinting.
*/

package sshd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type SSHService struct {
	cfg     *config.Config
	bus     *event.Bus
	logger  zerolog.Logger
	tracker *session.Tracker
	limiter *ratelimit.IPLimiter
	hostkey ssh.Signer
}

func New(
	cfg *config.Config,
	bus *event.Bus,
	logger *zerolog.Logger,
	tracker *session.Tracker,
	limiter *ratelimit.IPLimiter,
	hostkey ssh.Signer,
) *SSHService {
	return &SSHService{
		cfg:     cfg,
		bus:     bus,
		logger:  logger.With().Str("service", "ssh").Logger(),
		tracker: tracker,
		limiter: limiter,
		hostkey: hostkey,
	}
}

func (s *SSHService) Name() string { return "ssh" }

func (s *SSHService) Start(ctx context.Context) error {
	addr := s.cfg.Addr(s.cfg.SSH.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ssh listen %s: %w", addr, err)
	}

	s.logger.Info().
		Str("addr", addr).
		Msg("ssh honeypot listening")

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			s.logger.Debug().Err(err).Msg("accept failed")
			continue
		}

		go s.handleConnection(ctx, conn)
	}

	return nil
}

func (s *SSHService) handleConnection(
	ctx context.Context, conn net.Conn,
) {
	defer func() { _ = conn.Close() }()

	srcIP, srcPort := types.RemoteAddr(conn)

	if !s.limiter.Allow(srcIP) {
		return
	}

	sess := s.tracker.Start(
		s.cfg.Sensor.ID, types.ServiceSSH,
		srcIP, srcPort, s.cfg.SSH.Port,
	)
	defer s.tracker.End(sess.ID)

	s.publishConnect(sess, srcIP, srcPort)

	var lastUsername string

	sshCfg := &ssh.ServerConfig{
		ServerVersion: s.cfg.SSH.Banner,
		PasswordCallback: func(
			c ssh.ConnMetadata, pass []byte,
		) (*ssh.Permissions, error) {
			lastUsername = c.User()
			s.publishAuth(
				sess.ID, srcIP, c.User(),
				string(pass), "password",
				string(c.ClientVersion()),
			)
			return &ssh.Permissions{}, nil
		},
		PublicKeyCallback: func(
			c ssh.ConnMetadata, key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			lastUsername = c.User()
			s.publishAuth(
				sess.ID, srcIP, c.User(),
				"", "publickey",
				string(c.ClientVersion()),
			)
			return &ssh.Permissions{}, nil
		},
	}

	sshCfg.AddHostKey(s.hostkey)

	sshConn, chans, reqs, err := ssh.NewServerConn(
		conn, sshCfg,
	)
	if err != nil {
		s.publishDisconnect(sess, srcIP, srcPort)
		return
	}
	defer func() { _ = sshConn.Close() }()

	s.tracker.SetLogin(
		sess.ID, true, lastUsername,
		string(sshConn.ClientVersion()),
	)

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			go s.handleSession(
				ctx, newChan, sess, srcIP, lastUsername,
			)
		case "direct-tcpip":
			s.logLateralMovement(sess, srcIP, newChan)
			_ = newChan.Reject(
				ssh.Prohibited, "not allowed",
			)
		default:
			_ = newChan.Reject(
				ssh.UnknownChannelType, "unknown",
			)
		}
	}

	s.publishDisconnect(sess, srcIP, srcPort)
}

type sessionState struct {
	ch       ssh.Channel
	sess     *types.Session
	srcIP    string
	username string
	cols     int
	rows     int
	recorder *session.Recorder
}

func (s *SSHService) handleSession(
	ctx context.Context,
	newChan ssh.NewChannel,
	sess *types.Session,
	srcIP string,
	username string,
) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()

	st := &sessionState{
		ch:       ch,
		sess:     sess,
		srcIP:    srcIP,
		username: username,
		cols:     80,
		rows:     24,
	}

	st.recorder = session.NewRecorder(
		sess.ID, srcIP, s.cfg.Sensor.ID,
		st.cols, st.rows,
	)

	go s.dispatchRequests(reqs, st)

	<-ctx.Done()
}

func (s *SSHService) dispatchRequests(
	reqs <-chan *ssh.Request, st *sessionState,
) {
	for req := range reqs {
		if s.handleSessionRequest(req, st) {
			return
		}
	}
}

func (s *SSHService) handleSessionRequest(
	req *ssh.Request, st *sessionState,
) bool {
	switch req.Type {
	case "pty-req":
		if len(req.Payload) > 4 {
			st.cols, st.rows = parsePTYRequest(
				req.Payload,
			)
			st.recorder.Resize(st.cols, st.rows)
		}

	case "shell":
		replyOK(req)
		RunShell(
			st.ch, st.sess.ID, s.cfg.Sensor.ID,
			st.srcIP, st.username,
			s.cfg.SSH.Hostname,
			s.bus, st.recorder, st.cols, st.rows,
		)
		s.saveRecording(st)
		_ = st.ch.Close()
		return true

	case "exec":
		replyOK(req)
		cmd := parseExecPayload(req.Payload)
		s.handleExec(
			st.ch, st.sess, st.srcIP,
			st.username, cmd, st.recorder,
		)
		_ = st.ch.Close()
		return true

	case "window-change":
		if len(req.Payload) >= 8 {
			st.cols, st.rows = parseWindowChange(
				req.Payload,
			)
			st.recorder.Resize(st.cols, st.rows)
		}
	}

	replyOK(req)
	return false
}

func replyOK(req *ssh.Request) {
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

func (s *SSHService) saveRecording(st *sessionState) {
	if _, err := st.recorder.Save(s.cfg.Log.ReplayDir); err != nil {
		s.logger.Error().Err(err).
			Str("session_id", st.sess.ID).
			Msg("failed to save session recording")
	}
}

func (s *SSHService) handleExec(
	ch ssh.Channel,
	sess *types.Session,
	srcIP string,
	username string,
	cmd string,
	recorder *session.Recorder,
) {
	recorder.WriteInput([]byte(cmd + "\n"))

	publishCommand(
		s.bus, sess.ID, s.cfg.Sensor.ID, srcIP,
		cmd, s.cfg.SSH.Hostname,
	)

	fs := NewFakeFS(s.cfg.SSH.Hostname)
	cmdCtx := &CommandContext{
		FS:       fs,
		Hostname: s.cfg.SSH.Hostname,
		Username: username,
		CWD:      "/root",
	}

	output := DispatchCommand(cmd, cmdCtx)
	if output != "" {
		_, _ = ch.Write([]byte(output))
		recorder.WriteOutput([]byte(output))
	}

	_, _ = ch.SendRequest(
		"exit-status", false, []byte{0, 0, 0, 0},
	)
}

func (s *SSHService) logLateralMovement(
	sess *types.Session,
	srcIP string,
	newChan ssh.NewChannel,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"channel_type": newChan.ChannelType(),
		"extra_data":   string(newChan.ExtraData()),
	})

	s.bus.Publish(config.TopicCommand, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSSH,
		EventType:     types.EventExploit,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		Tags:          []string{"lateral-movement", "mitre:T1021.004"},
		ServiceData:   serviceData,
	})
}

func (s *SSHService) publishConnect(
	sess *types.Session, srcIP string, srcPort int,
) {
	s.bus.Publish(config.TopicConnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSSH,
		EventType:     types.EventConnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.SSH.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *SSHService) publishDisconnect(
	sess *types.Session, srcIP string, srcPort int,
) {
	s.bus.Publish(config.TopicDisconnect, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sess.ID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSSH,
		EventType:     types.EventDisconnect,
		SourceIP:      srcIP,
		SourcePort:    srcPort,
		DestPort:      s.cfg.SSH.Port,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
	})
}

func (s *SSHService) publishAuth(
	sessionID string,
	srcIP string,
	username string,
	password string,
	method string,
	clientVersion string,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"username":       username,
		"password":       password,
		"auth_method":    method,
		"client_version": clientVersion,
	})

	s.bus.Publish(config.TopicAuth, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      s.cfg.Sensor.ID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSSH,
		EventType:     types.EventLoginSuccess,
		SourceIP:      srcIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}

func parsePTYRequest(payload []byte) (int, int) {
	if len(payload) < 8 {
		return 80, 24
	}

	termLen := int(payload[3]) | int(payload[2])<<8 |
		int(payload[1])<<16 | int(payload[0])<<24
	offset := 4 + termLen

	if len(payload) < offset+8 {
		return 80, 24
	}

	cols := int(payload[offset+3]) | int(payload[offset+2])<<8 |
		int(payload[offset+1])<<16 | int(payload[offset])<<24
	rows := int(payload[offset+7]) | int(payload[offset+6])<<8 |
		int(payload[offset+5])<<16 | int(payload[offset+4])<<24

	return cols, rows
}

func parseWindowChange(payload []byte) (int, int) {
	if len(payload) < 8 {
		return 80, 24
	}

	cols := int(payload[3]) | int(payload[2])<<8 |
		int(payload[1])<<16 | int(payload[0])<<24
	rows := int(payload[7]) | int(payload[6])<<8 |
		int(payload[5])<<16 | int(payload[4])<<24

	return cols, rows
}

func parseExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}

	cmdLen := int(payload[3]) | int(payload[2])<<8 |
		int(payload[1])<<16 | int(payload[0])<<24

	if len(payload) < 4+cmdLen {
		return ""
	}

	return string(payload[4 : 4+cmdLen])
}
