/*
©AngelaMos | 2026
redis.go

Redis Streams client for real-time event streaming

Publishes honeypot events to a capped Redis stream for consumption
by the WebSocket API. Also provides sliding window counters and
session caching for the dashboard stats endpoints.
*/

package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type RedisStreamer struct {
	client    *redis.Client
	streamKey string
	maxLen    int64
}

func NewRedisStreamer(
	url, password string,
) (*RedisStreamer, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parsing redis url: %w", err)
	}

	if password != "" {
		opts.Password = password
	}

	client := redis.NewClient(opts)

	return &RedisStreamer{
		client:    client,
		streamKey: config.DefaultRedisStreamKey,
		maxLen:    config.DefaultRedisMaxLen,
	}, nil
}

func (r *RedisStreamer) Close() error {
	return r.client.Close()
}

func (r *RedisStreamer) PublishEvent(
	ctx context.Context, ev *types.Event,
) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}

	return r.client.XAdd(ctx, &redis.XAddArgs{
		Stream: r.streamKey,
		MaxLen: r.maxLen,
		Approx: true,
		Values: map[string]any{
			"event_id":     ev.ID,
			"session_id":   ev.SessionID,
			"service_type": ev.ServiceType.String(),
			"event_type":   ev.EventType.String(),
			"source_ip":    ev.SourceIP,
			"data":         string(data),
		},
	}).Err()
}

func (r *RedisStreamer) SubscribeEvents(
	ctx context.Context,
) <-chan *types.Event {
	ch := make(
		chan *types.Event,
		config.DefaultEventBusBuffer,
	)

	go func() {
		defer close(ch)

		lastID := "$"
		for ctx.Err() == nil {
			streams, err := r.client.XRead(
				ctx, &redis.XReadArgs{
					Streams: []string{
						r.streamKey, lastID,
					},
					Count: 100,
					Block: 0,
				},
			).Result()
			if err != nil {
				continue
			}

			var done bool
			lastID, done = dispatchStreams(
				ctx, ch, streams, lastID,
			)
			if done {
				return
			}
		}
	}()

	return ch
}

func dispatchStreams(
	ctx context.Context,
	ch chan<- *types.Event,
	streams []redis.XStream,
	lastID string,
) (string, bool) {
	for _, stream := range streams {
		for _, msg := range stream.Messages {
			lastID = msg.ID

			ev := parseStreamMessage(msg)
			if ev == nil {
				continue
			}

			select {
			case ch <- ev:
			case <-ctx.Done():
				return lastID, true
			}
		}
	}

	return lastID, false
}

func parseStreamMessage(
	msg redis.XMessage,
) *types.Event {
	data, ok := msg.Values["data"].(string)
	if !ok {
		return nil
	}

	var ev types.Event
	if err := json.Unmarshal(
		[]byte(data), &ev,
	); err != nil {
		return nil
	}

	return &ev
}

func (r *RedisStreamer) IncrCounter(
	ctx context.Context, key string,
) error {
	pipe := r.client.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, config.DefaultRedisTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisStreamer) GetCounter(
	ctx context.Context, key string,
) (int64, error) {
	return r.client.Get(ctx, key).Int64()
}

func (r *RedisStreamer) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}
