/*
©AngelaMos | 2026
shell.go

Interactive shell emulation for the SSH honeypot

Provides a realistic bash-like terminal using golang.org/x/term
with a root prompt, Ubuntu MOTD banner on connect, and full
read-eval-print loop. All I/O is captured by the asciicast recorder
and every command is published to the event bus for analysis.
*/

package sshd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

func RunShell(
	ch ssh.Channel,
	sessionID string,
	sensorID string,
	sourceIP string,
	username string,
	hostname string,
	bus *event.Bus,
	recorder *session.Recorder,
	cols int,
	rows int,
) {
	now := time.Now().UTC()
	banner := fmt.Sprintf(
		config.SSHMOTDTemplate,
		now.Format("Mon Jan  2 15:04:05 UTC 2006"),
		now.Add(-24*time.Hour).Format(
			"Mon Jan  2 15:04:05 2006",
		),
	)

	writeAndRecord(ch, recorder, []byte(banner))

	fs := NewFakeFS(hostname)
	cmdCtx := &CommandContext{
		FS:       fs,
		Hostname: hostname,
		Username: username,
		CWD:      "/root",
	}

	prompt := fmt.Sprintf(
		"%s@%s:%s# ", username, hostname, cmdCtx.CWD,
	)

	terminal := term.NewTerminal(ch, prompt)
	_ = terminal.SetSize(cols, rows)

	for {
		line, err := terminal.ReadLine()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				break
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		recorder.WriteInput([]byte(line + "\n"))

		publishCommand(
			bus, sessionID, sensorID,
			sourceIP, line, hostname,
		)

		if line == "exit" || line == "logout" || line == "quit" {
			writeAndRecord(
				ch, recorder, []byte("logout\r\n"),
			)
			return
		}

		output := DispatchCommand(line, cmdCtx)
		if output != "" {
			crlf := strings.ReplaceAll(output, "\n", "\r\n")
			writeAndRecord(ch, recorder, []byte(crlf))
		}

		prompt = fmt.Sprintf(
			"%s@%s:%s# ",
			username, hostname, cmdCtx.CWD,
		)
		terminal.SetPrompt(prompt)
	}
}

func writeAndRecord(
	w io.Writer,
	recorder *session.Recorder,
	data []byte,
) {
	_, _ = w.Write(data)
	recorder.WriteOutput(data)
}

func publishCommand(
	bus *event.Bus,
	sessionID string,
	sensorID string,
	sourceIP string,
	command string,
	hostname string,
) {
	serviceData, _ := json.Marshal(map[string]string{
		"command":  command,
		"hostname": hostname,
	})

	bus.Publish(config.TopicCommand, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     sessionID,
		SensorID:      sensorID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   types.ServiceSSH,
		EventType:     types.EventCommand,
		SourceIP:      sourceIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		ServiceData:   serviceData,
	})
}
