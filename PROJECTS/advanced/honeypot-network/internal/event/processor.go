/*
©AngelaMos | 2026
processor.go

Event processing pipeline with bounded worker pool

Consumes events from the event bus and runs them through an enrichment
pipeline: GeoIP resolution, MITRE ATT&CK technique detection, IOC
extraction, and persistence to PostgreSQL and Redis streams. Workers
are managed via an errgroup and respect context cancellation for
graceful shutdown.
*/

package event

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type GeoResolver interface {
	Resolve(ip string) (*types.GeoInfo, error)
}

type TechniqueDetector interface {
	Detect(ev *types.Event) []*types.MITREDetection
}

type DataStore interface {
	InsertEvent(ctx context.Context, ev *types.Event) error
	InsertCredential(ctx context.Context, c *types.Credential) error
	InsertDetection(ctx context.Context, d *types.MITREDetection) error
	UpsertAttacker(ctx context.Context, a *types.Attacker) error
	UpsertIOC(ctx context.Context, ioc *types.IOC) error
}

type EventStreamer interface {
	PublishEvent(ctx context.Context, ev *types.Event) error
}

type Processor struct {
	workers  int
	bus      *Bus
	store    DataStore
	streamer EventStreamer
	geo      GeoResolver
	detector TechniqueDetector
	logger   zerolog.Logger
	eventCh  <-chan *types.Event
}

func NewProcessor(
	workers int,
	bus *Bus,
	store DataStore,
	streamer EventStreamer,
	geo GeoResolver,
	detector TechniqueDetector,
	logger zerolog.Logger,
) *Processor {
	ch := bus.Subscribe(
		config.DefaultEventBusBuffer,
		config.TopicAll,
	)

	return &Processor{
		workers:  workers,
		bus:      bus,
		store:    store,
		streamer: streamer,
		geo:      geo,
		detector: detector,
		logger:   logger,
		eventCh:  ch,
	}
}

func (p *Processor) Start(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	for range p.workers {
		g.Go(func() error {
			return p.work(ctx)
		})
	}

	return g.Wait()
}

func (p *Processor) work(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case ev, ok := <-p.eventCh:
			if !ok {
				return nil
			}
			p.process(ctx, ev)
		}
	}
}

func (p *Processor) process(
	ctx context.Context, ev *types.Event,
) {
	ev.ReceivedAt = time.Now().UTC()

	p.enrichGeo(ev)
	detections := p.detectTechniques(ev)
	p.persist(ctx, ev, detections)
	p.stream(ctx, ev)
}

func (p *Processor) enrichGeo(ev *types.Event) {
	if p.geo == nil {
		return
	}

	geo, err := p.geo.Resolve(ev.SourceIP)
	if err != nil {
		p.logger.Debug().
			Err(err).
			Str("ip", ev.SourceIP).
			Msg("geoip lookup failed")
		return
	}

	ev.Geo = geo
}

func (p *Processor) detectTechniques(
	ev *types.Event,
) []*types.MITREDetection {
	if p.detector == nil {
		return nil
	}

	detections := p.detector.Detect(ev)
	for _, d := range detections {
		ev.Tags = append(ev.Tags, d.TechniqueID)
	}
	return detections
}

func (p *Processor) persist(
	ctx context.Context,
	ev *types.Event,
	detections []*types.MITREDetection,
) {
	if p.store == nil {
		return
	}

	if err := p.store.InsertEvent(ctx, ev); err != nil {
		p.logger.Error().
			Err(err).
			Str("event_id", ev.ID).
			Msg("failed to persist event")
	}

	for _, d := range detections {
		if err := p.store.InsertDetection(ctx, d); err != nil {
			p.logger.Error().
				Err(err).
				Str("technique", d.TechniqueID).
				Msg("failed to persist detection")
		}
	}

	if ev.EventType == types.EventLoginSuccess ||
		ev.EventType == types.EventLoginFailed {
		if cred := extractCredential(ev); cred != nil {
			if err := p.store.InsertCredential(ctx, cred); err != nil {
				p.logger.Error().
					Err(err).
					Str("session_id", ev.SessionID).
					Msg("failed to persist credential")
			}
		}
	}

	attacker := buildAttacker(ev)
	if err := p.store.UpsertAttacker(ctx, attacker); err != nil {
		p.logger.Error().
			Err(err).
			Str("ip", ev.SourceIP).
			Msg("failed to upsert attacker")
	}

	if ioc := ipIOC(ev); ioc != nil {
		if err := p.store.UpsertIOC(ctx, ioc); err != nil {
			p.logger.Error().
				Err(err).
				Str("ip", ev.SourceIP).
				Msg("failed to upsert ip ioc")
		}
	}
}

func (p *Processor) stream(
	ctx context.Context, ev *types.Event,
) {
	if p.streamer == nil {
		return
	}

	if err := p.streamer.PublishEvent(ctx, ev); err != nil {
		p.logger.Error().
			Err(err).
			Str("event_id", ev.ID).
			Msg("failed to stream event")
	}
}

func extractCredential(ev *types.Event) *types.Credential {
	if len(ev.ServiceData) == 0 {
		return nil
	}
	var fields map[string]string
	if json.Unmarshal(ev.ServiceData, &fields) != nil {
		return nil
	}
	return &types.Credential{
		SessionID:   ev.SessionID,
		Timestamp:   ev.Timestamp,
		ServiceType: ev.ServiceType,
		SourceIP:    ev.SourceIP,
		Username:    fields["username"],
		Password:    fields["password"],
		PublicKey:   fields["public_key"],
		AuthMethod:  fields["auth_method"],
		Success:     ev.EventType == types.EventLoginSuccess,
	}
}

func buildAttacker(ev *types.Event) *types.Attacker {
	a := &types.Attacker{
		IP:          ev.SourceIP,
		FirstSeen:   ev.Timestamp,
		LastSeen:    ev.Timestamp,
		TotalEvents: 1,
	}
	if ev.EventType == types.EventConnect {
		a.TotalSessions = 1
	}
	if ev.Geo != nil {
		a.Geo = *ev.Geo
	}
	return a
}

func ipIOC(ev *types.Event) *types.IOC {
	ip := ev.SourceIP
	if ip == "" {
		return nil
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}

	if parsed.IsLoopback() || parsed.IsPrivate() {
		return nil
	}

	iocType := types.IOCIPv4
	if parsed.To4() == nil {
		iocType = types.IOCIPv6
	}

	return &types.IOC{
		Type:       iocType,
		Value:      ip,
		FirstSeen:  ev.Timestamp,
		LastSeen:   ev.Timestamp,
		SightCount: 1,
		Confidence: 50,
		Source:     ev.ServiceType.String() + "-honeypot",
	}
}
