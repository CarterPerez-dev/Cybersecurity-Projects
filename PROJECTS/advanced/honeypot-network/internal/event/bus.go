/*
©AngelaMos | 2026
bus.go

In-process event bus with fan-out pub/sub for honeypot events

All honeypot services publish events to named topics. Subscribers
receive events on buffered channels. Publish is non-blocking: if a
subscriber channel is full the event is dropped to prevent a slow
consumer from back-pressuring producers. Supports wildcard
subscription via the "all" topic which receives every published event.
*/

package event

import (
	"sync"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type subscriber struct {
	ch     chan *types.Event
	topics map[string]bool
}

type Bus struct {
	mu          sync.RWMutex
	subscribers []*subscriber
	closed      bool
}

func NewBus() *Bus {
	return &Bus{}
}

func (b *Bus) Subscribe(
	bufSize int, topics ...string,
) <-chan *types.Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	topicSet := make(map[string]bool, len(topics))
	for _, t := range topics {
		topicSet[t] = true
	}

	sub := &subscriber{
		ch:     make(chan *types.Event, bufSize),
		topics: topicSet,
	}

	b.subscribers = append(b.subscribers, sub)
	return sub.ch
}

func (b *Bus) Publish(topic string, ev *types.Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return
	}

	for _, sub := range b.subscribers {
		if !sub.topics[topic] && !sub.topics[config.TopicAll] {
			continue
		}

		select {
		case sub.ch <- ev:
		default:
		}
	}
}

func (b *Bus) Unsubscribe(ch <-chan *types.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, sub := range b.subscribers {
		if sub.ch == ch {
			close(sub.ch)
			b.subscribers = append(
				b.subscribers[:i],
				b.subscribers[i+1:]...,
			)
			return
		}
	}
}

func (b *Bus) Shutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.closed = true
	for _, sub := range b.subscribers {
		close(sub.ch)
	}
	b.subscribers = nil
}

func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers)
}
