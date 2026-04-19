/*
©AngelaMos | 2026
recorder.go

Terminal session recorder in asciicast v2 format

Captures SSH session I/O (input and output bytes) with precise
timestamps relative to session start. The resulting .cast file
can be replayed in the web dashboard using xterm.js or via the
asciinema CLI tool. Format specification: https://docs.asciinema.org/manual/asciicast/v2/
*/

package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type castHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env,omitempty"`
	Title     string            `json:"title,omitempty"`
}

type castEvent struct {
	Time float64
	Type string
	Data string
}

func (e *castEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal([]any{e.Time, e.Type, e.Data})
}

type Recorder struct {
	mu        sync.Mutex
	sessionID string
	sourceIP  string
	sensorID  string
	cols      int
	rows      int
	startTime time.Time
	header    castHeader
	events    []castEvent
}

func NewRecorder(
	sessionID string,
	sourceIP string,
	sensorID string,
	cols int,
	rows int,
) *Recorder {
	now := time.Now()

	return &Recorder{
		sessionID: sessionID,
		sourceIP:  sourceIP,
		sensorID:  sensorID,
		cols:      cols,
		rows:      rows,
		startTime: now,
		header: castHeader{
			Version:   2,
			Width:     cols,
			Height:    rows,
			Timestamp: now.Unix(),
			Env: map[string]string{
				"TERM":  "xterm-256color",
				"SHELL": "/bin/bash",
			},
			Title: fmt.Sprintf(
				"%s - %s", sourceIP, sessionID[:8],
			),
		},
	}
}

func (r *Recorder) WriteOutput(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, castEvent{
		Time: r.elapsed(),
		Type: "o",
		Data: string(data),
	})
}

func (r *Recorder) WriteInput(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, castEvent{
		Time: r.elapsed(),
		Type: "i",
		Data: string(data),
	})
}

func (r *Recorder) Resize(cols, rows int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, castEvent{
		Time: r.elapsed(),
		Type: "r",
		Data: fmt.Sprintf("%dx%d", cols, rows),
	})
}

func (r *Recorder) Save(dir string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating replay dir: %w", err)
	}

	filename := fmt.Sprintf("%s.cast", r.sessionID)
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("creating cast file: %w", err)
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)

	if err := enc.Encode(r.header); err != nil {
		return "", fmt.Errorf("writing header: %w", err)
	}

	for i := range r.events {
		if err := enc.Encode(&r.events[i]); err != nil {
			return "", fmt.Errorf("writing event: %w", err)
		}
	}

	return path, nil
}

func (r *Recorder) Bytes() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	headerBytes, err := json.Marshal(r.header)
	if err != nil {
		return nil, fmt.Errorf("marshaling header: %w", err)
	}

	result := make([]byte, 0, len(headerBytes)+1)
	result = append(result, headerBytes...)
	result = append(result, '\n')

	for i := range r.events {
		eventBytes, err := json.Marshal(&r.events[i])
		if err != nil {
			return nil, fmt.Errorf("marshaling event: %w", err)
		}
		result = append(result, eventBytes...)
		result = append(result, '\n')
	}

	return result, nil
}

func (r *Recorder) EventCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *Recorder) elapsed() float64 {
	return time.Since(r.startTime).Seconds()
}
