/*
©AngelaMos | 2026
bus_test.go

Tests for the event bus fan-out pub/sub system
*/

package event

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

func testEvent(_ string) *types.Event {
	return &types.Event{
		ID:          "test-001",
		SessionID:   "sess-001",
		SensorID:    "hive-01",
		Timestamp:   time.Now(),
		ServiceType: types.ServiceSSH,
		EventType:   types.EventConnect,
		SourceIP:    "192.168.1.100",
		SourcePort:  54321,
		DestPort:    2222,
		Protocol:    types.ProtocolTCP,
	}
}

func TestPublishSubscribe(t *testing.T) {
	bus := NewBus()
	defer bus.Shutdown()

	ch := bus.Subscribe(10, config.TopicAuth)

	ev := testEvent(config.TopicAuth)
	bus.Publish(config.TopicAuth, ev)

	select {
	case got := <-ch:
		assert.Equal(t, ev.ID, got.ID)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestFanOut(t *testing.T) {
	bus := NewBus()
	defer bus.Shutdown()

	ch1 := bus.Subscribe(10, config.TopicAuth)
	ch2 := bus.Subscribe(10, config.TopicAuth)

	ev := testEvent(config.TopicAuth)
	bus.Publish(config.TopicAuth, ev)

	for _, ch := range []<-chan *types.Event{ch1, ch2} {
		select {
		case got := <-ch:
			assert.Equal(t, ev.ID, got.ID)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
}

func TestWildcardSubscription(t *testing.T) {
	bus := NewBus()
	defer bus.Shutdown()

	allCh := bus.Subscribe(10, config.TopicAll)
	authCh := bus.Subscribe(10, config.TopicAuth)

	ev := testEvent(config.TopicCommand)
	bus.Publish(config.TopicCommand, ev)

	select {
	case got := <-allCh:
		assert.Equal(t, ev.ID, got.ID)
	case <-time.After(time.Second):
		t.Fatal("wildcard subscriber did not receive event")
	}

	select {
	case <-authCh:
		t.Fatal("auth subscriber should not receive command events")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSlowSubscriberDrop(t *testing.T) {
	bus := NewBus()
	defer bus.Shutdown()

	ch := bus.Subscribe(1, config.TopicAuth)

	bus.Publish(config.TopicAuth, testEvent(config.TopicAuth))
	bus.Publish(config.TopicAuth, testEvent(config.TopicAuth))
	bus.Publish(config.TopicAuth, testEvent(config.TopicAuth))

	got := <-ch
	require.NotNil(t, got)

	select {
	case <-ch:
		t.Fatal("expected channel to be empty after buffer")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestTopicIsolation(t *testing.T) {
	bus := NewBus()
	defer bus.Shutdown()

	authCh := bus.Subscribe(10, config.TopicAuth)
	cmdCh := bus.Subscribe(10, config.TopicCommand)

	bus.Publish(config.TopicAuth, testEvent(config.TopicAuth))

	select {
	case <-authCh:
	case <-time.After(time.Second):
		t.Fatal("auth subscriber did not receive event")
	}

	select {
	case <-cmdCh:
		t.Fatal("command subscriber should not receive auth events")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestShutdown(t *testing.T) {
	bus := NewBus()

	ch := bus.Subscribe(10, config.TopicAll)
	bus.Shutdown()

	_, open := <-ch
	assert.False(t, open)

	assert.Equal(t, 0, bus.SubscriberCount())
}

func TestPublishAfterShutdown(t *testing.T) {
	bus := NewBus()
	bus.Shutdown()

	assert.NotPanics(t, func() {
		bus.Publish(config.TopicAuth, testEvent(config.TopicAuth))
	})
}

func TestMultipleTopicSubscription(t *testing.T) {
	bus := NewBus()
	defer bus.Shutdown()

	ch := bus.Subscribe(10, config.TopicAuth, config.TopicCommand)

	bus.Publish(config.TopicAuth, testEvent(config.TopicAuth))
	bus.Publish(config.TopicCommand, testEvent(config.TopicCommand))
	bus.Publish(config.TopicConnect, testEvent(config.TopicConnect))

	count := 0
	for range 2 {
		select {
		case <-ch:
			count++
		case <-time.After(time.Second):
			t.Fatal("timed out")
		}
	}
	assert.Equal(t, 2, count)

	select {
	case <-ch:
		t.Fatal("should not receive connect events")
	case <-time.After(50 * time.Millisecond):
	}
}
