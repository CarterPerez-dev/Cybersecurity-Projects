/*
©AngelaMos | 2026
tracker_test.go
*/

package session

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

func TestStartAndGet(t *testing.T) {
	tr := NewTracker()

	sess := tr.Start("sensor-01", types.ServiceSSH, "10.0.0.1", 54321, 2222)
	require.NotNil(t, sess)
	assert.NotEmpty(t, sess.ID)
	assert.Equal(t, types.ServiceSSH, sess.ServiceType)
	assert.Equal(t, "10.0.0.1", sess.SourceIP)
	assert.Equal(t, 54321, sess.SourcePort)
	assert.Equal(t, 2222, sess.DestPort)

	got := tr.Get(sess.ID)
	assert.Equal(t, sess, got)
}

func TestEndReturnsSession(t *testing.T) {
	tr := NewTracker()

	sess := tr.Start("sensor-01", types.ServiceSSH, "10.0.0.1", 54321, 2222)
	ended := tr.End(sess.ID)

	require.NotNil(t, ended)
	require.NotNil(t, ended.EndedAt)

	assert.Nil(t, tr.Get(sess.ID))
}

func TestEndNonexistent(t *testing.T) {
	tr := NewTracker()
	assert.Nil(t, tr.End("nonexistent-id"))
}

func TestActive(t *testing.T) {
	tr := NewTracker()

	s1 := tr.Start("sensor-01", types.ServiceSSH, "10.0.0.1", 100, 22)
	tr.Start("sensor-01", types.ServiceHTTP, "10.0.0.2", 200, 80)
	tr.Start("sensor-01", types.ServiceRedis, "10.0.0.3", 300, 6379)

	assert.Len(t, tr.Active(), 3)

	tr.End(s1.ID)
	assert.Len(t, tr.Active(), 2)
}

func TestCount(t *testing.T) {
	tr := NewTracker()

	s1 := tr.Start("sensor-01", types.ServiceSSH, "10.0.0.1", 100, 22)
	tr.Start("sensor-01", types.ServiceHTTP, "10.0.0.2", 200, 80)
	assert.Equal(t, 2, tr.Count())

	tr.End(s1.ID)
	assert.Equal(t, 1, tr.Count())
}

func TestIncrCommandCount(t *testing.T) {
	tr := NewTracker()

	sess := tr.Start("sensor-01", types.ServiceSSH, "10.0.0.1", 100, 22)
	for range 5 {
		tr.IncrCommandCount(sess.ID)
	}

	got := tr.Get(sess.ID)
	assert.Equal(t, 5, got.CommandCount)
}

func TestSetLogin(t *testing.T) {
	tr := NewTracker()

	sess := tr.Start("sensor-01", types.ServiceSSH, "10.0.0.1", 100, 22)
	tr.SetLogin(sess.ID, true, "root", "SSH-2.0-paramiko_3.4.0")

	got := tr.Get(sess.ID)
	assert.True(t, got.LoginSuccess)
	assert.Equal(t, "root", got.Username)
	assert.Equal(t, "SSH-2.0-paramiko_3.4.0", got.ClientVersion)
}

func TestAddTechnique(t *testing.T) {
	tr := NewTracker()

	sess := tr.Start("sensor-01", types.ServiceSSH, "10.0.0.1", 100, 22)
	tr.AddTechnique(sess.ID, "T1078")
	tr.AddTechnique(sess.ID, "T1078")
	tr.AddTechnique(sess.ID, "T1059.004")

	got := tr.Get(sess.ID)
	assert.Equal(t, []string{"T1078", "T1059.004"}, got.MITRETechniques)
}

func TestOnStartCallback(t *testing.T) {
	tr := NewTracker()

	var captured *types.Session
	tr.SetOnStart(func(s *types.Session) {
		captured = s
	})

	sess := tr.Start("sensor-01", types.ServiceSSH, "10.0.0.1", 100, 22)
	require.NotNil(t, captured)
	assert.Equal(t, sess.ID, captured.ID)
}

func TestOnEndCallback(t *testing.T) {
	tr := NewTracker()

	var captured *types.Session
	tr.SetOnEnd(func(s *types.Session) {
		captured = s
	})

	sess := tr.Start("sensor-01", types.ServiceSSH, "10.0.0.1", 100, 22)
	tr.End(sess.ID)

	require.NotNil(t, captured)
	assert.Equal(t, sess.ID, captured.ID)
	assert.NotNil(t, captured.EndedAt)
}

func TestConcurrentAccess(t *testing.T) {
	tr := NewTracker()

	var wg sync.WaitGroup
	ids := make([]string, 50)

	for i := range 50 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sess := tr.Start(
				"sensor-01", types.ServiceSSH,
				"10.0.0.1", 10000+idx, 22,
			)
			ids[idx] = sess.ID
		}(i)
	}
	wg.Wait()

	assert.Equal(t, 50, tr.Count())

	for _, id := range ids {
		wg.Add(1)
		go func(sid string) {
			defer wg.Done()
			tr.End(sid)
		}(id)
	}
	wg.Wait()

	assert.Equal(t, 0, tr.Count())
}
