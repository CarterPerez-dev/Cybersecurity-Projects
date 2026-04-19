/*
©AngelaMos | 2026
recorder_test.go
*/

package session

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRecorderInitialState(t *testing.T) {
	rec := NewRecorder("sess-001", "10.0.0.1", "sensor-01", 80, 24)
	assert.Equal(t, 0, rec.EventCount())
}

func TestWriteOutputAndInput(t *testing.T) {
	rec := NewRecorder("sess-001", "10.0.0.1", "sensor-01", 80, 24)

	rec.WriteOutput([]byte("hello"))
	rec.WriteInput([]byte("ls\n"))

	assert.Equal(t, 2, rec.EventCount())
}

func TestBytesProducesValidAsciicast(t *testing.T) {
	rec := NewRecorder("sess-001", "10.0.0.1", "sensor-01", 80, 24)
	rec.WriteOutput([]byte("$ "))
	rec.WriteInput([]byte("whoami\n"))
	rec.WriteOutput([]byte("root\n"))

	data, err := rec.Bytes()
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.GreaterOrEqual(t, len(lines), 4)

	var header map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &header))
	assert.InDelta(t, float64(2), header["version"], 0)
	assert.InDelta(t, float64(80), header["width"], 0)
	assert.InDelta(t, float64(24), header["height"], 0)

	for _, line := range lines[1:] {
		var event []any
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		require.Len(t, event, 3)
	}
}

func TestSaveCreatesFile(t *testing.T) {
	dir := t.TempDir()
	rec := NewRecorder("sess-001", "10.0.0.1", "sensor-01", 80, 24)
	rec.WriteOutput([]byte("hello"))

	path, err := rec.Save(dir)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(path, ".cast"))

	content, err := os.ReadFile(path)
	require.NoError(t, err)

	var header map[string]any
	firstLine := strings.SplitN(string(content), "\n", 2)[0]
	require.NoError(t, json.Unmarshal([]byte(firstLine), &header))
	assert.InDelta(t, float64(2), header["version"], 0)
}

func TestResizeEvent(t *testing.T) {
	rec := NewRecorder("sess-001", "10.0.0.1", "sensor-01", 80, 24)
	rec.Resize(120, 40)

	data, err := rec.Bytes()
	require.NoError(t, err)

	assert.Contains(t, string(data), "120x40")
}

func TestEventOrdering(t *testing.T) {
	rec := NewRecorder("sess-001", "10.0.0.1", "sensor-01", 80, 24)
	rec.WriteOutput([]byte("one"))
	rec.WriteOutput([]byte("two"))
	rec.WriteOutput([]byte("three"))

	data, err := rec.Bytes()
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	var prevTime float64
	for _, line := range lines[1:] {
		var event []any
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		ts, ok := event[0].(float64)
		require.True(t, ok)
		assert.GreaterOrEqual(t, ts, prevTime)
		prevTime = ts
	}
}
