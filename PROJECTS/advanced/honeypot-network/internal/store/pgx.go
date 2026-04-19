/*
©AngelaMos | 2026
pgx.go

PostgreSQL implementation of all repository interfaces using pgxpool

Manages a connection pool with tuned settings for high-throughput
event ingestion. Uses batch inserts for bulk operations and prepared
statements for frequent queries. Partition creation for time-ranged
tables is handled automatically on insert.
*/

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type PgxStore struct {
	pool *pgxpool.Pool
}

func NewPgxStore(
	ctx context.Context, dsn string,
) (*PgxStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing dsn: %w", err)
	}

	cfg.MinConns = int32(config.DefaultDBPoolMin)
	cfg.MaxConns = int32(config.DefaultDBPoolMax)
	cfg.MaxConnIdleTime = config.DefaultDBIdleTimeout

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return &PgxStore{pool: pool}, nil
}

func (s *PgxStore) Close() {
	s.pool.Close()
}

func (s *PgxStore) EnsurePartitions(
	ctx context.Context,
) error {
	now := time.Now().UTC()
	months := []time.Time{
		time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC),
		time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(now.Year(), now.Month()+2, 1, 0, 0, 0, 0, time.UTC),
	}

	for _, start := range months {
		end := time.Date(
			start.Year(), start.Month()+1, 1,
			0, 0, 0, 0, time.UTC,
		)
		suffix := start.Format("y2006m01")

		for _, table := range []string{"events", "sessions"} {
			query := fmt.Sprintf(
				`CREATE TABLE IF NOT EXISTS %s_%s
				PARTITION OF %s
				FOR VALUES FROM ('%s') TO ('%s')`,
				table, suffix, table,
				start.Format(time.DateOnly),
				end.Format(time.DateOnly),
			)
			if _, err := s.pool.Exec(ctx, query); err != nil {
				return fmt.Errorf(
					"creating partition %s_%s: %w",
					table, suffix, err,
				)
			}
		}
	}

	return nil
}

func (s *PgxStore) InsertEvent(
	ctx context.Context, ev *types.Event,
) error {
	tags := ev.Tags
	if tags == nil {
		tags = []string{}
	}

	var geoCountryCode, geoCountry, geoCity, geoOrg *string
	var geoLat, geoLon *float64
	var geoASN *int

	if ev.Geo != nil {
		geoCountryCode = &ev.Geo.CountryCode
		geoCountry = &ev.Geo.Country
		geoCity = &ev.Geo.City
		geoLat = &ev.Geo.Latitude
		geoLon = &ev.Geo.Longitude
		geoASN = &ev.Geo.ASN
		geoOrg = &ev.Geo.Org
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO events (
			id, session_id, sensor_id, timestamp, received_at,
			service_type, event_type, source_ip, source_port,
			dest_port, protocol, schema_version,
			country_code, country, city, latitude, longitude,
			asn, org, tags, service_data
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15, $16, $17,
			$18, $19, $20, $21
		)`,
		ev.ID, ev.SessionID, ev.SensorID,
		ev.Timestamp, ev.ReceivedAt,
		ev.ServiceType.String(), ev.EventType.String(),
		ev.SourceIP, ev.SourcePort,
		ev.DestPort, ev.Protocol.String(),
		ev.SchemaVersion,
		geoCountryCode, geoCountry, geoCity,
		geoLat, geoLon,
		geoASN, geoOrg,
		tags, ev.ServiceData,
	)
	if err != nil {
		return fmt.Errorf("inserting event: %w", err)
	}

	return nil
}

func (s *PgxStore) InsertBatch(
	ctx context.Context, evs []*types.Event,
) error {
	batch := &pgx.Batch{}
	for _, ev := range evs {
		var geoCountryCode, geoCountry, geoCity, geoOrg *string
		var geoLat, geoLon *float64
		var geoASN *int

		if ev.Geo != nil {
			geoCountryCode = &ev.Geo.CountryCode
			geoCountry = &ev.Geo.Country
			geoCity = &ev.Geo.City
			geoLat = &ev.Geo.Latitude
			geoLon = &ev.Geo.Longitude
			geoASN = &ev.Geo.ASN
			geoOrg = &ev.Geo.Org
		}

		batch.Queue(`
			INSERT INTO events (
				id, session_id, sensor_id, timestamp,
				received_at, service_type, event_type,
				source_ip, source_port, dest_port, protocol,
				schema_version,
				country_code, country, city,
				latitude, longitude, asn, org,
				tags, service_data
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7,
				$8, $9, $10, $11, $12,
				$13, $14, $15, $16, $17, $18, $19,
				$20, $21
			)`,
			ev.ID, ev.SessionID, ev.SensorID,
			ev.Timestamp, ev.ReceivedAt,
			ev.ServiceType.String(), ev.EventType.String(),
			ev.SourceIP, ev.SourcePort, ev.DestPort,
			ev.Protocol.String(), ev.SchemaVersion,
			geoCountryCode, geoCountry, geoCity,
			geoLat, geoLon, geoASN, geoOrg,
			ev.Tags, ev.ServiceData,
		)
	}

	br := s.pool.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()

	for range evs {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("batch insert: %w", err)
		}
	}

	return nil
}

func (s *PgxStore) FindByIP(
	ctx context.Context, ip string, limit, offset int,
) ([]*types.Event, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, session_id, sensor_id, timestamp,
			received_at, service_type, event_type,
			source_ip, source_port, dest_port,
			tags, service_data
		FROM events
		WHERE source_ip = $1
		ORDER BY timestamp DESC
		LIMIT $2 OFFSET $3`,
		ip, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("querying events by ip: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

func (s *PgxStore) FindBySession(
	ctx context.Context, sessionID string,
) ([]*types.Event, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, session_id, sensor_id, timestamp,
			received_at, service_type, event_type,
			source_ip, source_port, dest_port,
			tags, service_data
		FROM events
		WHERE session_id = $1
		ORDER BY timestamp ASC`,
		sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"querying events by session: %w", err,
		)
	}
	defer rows.Close()

	return scanEvents(rows)
}

func (s *PgxStore) RecentEvents(
	ctx context.Context, limit int,
) ([]*types.Event, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, session_id, sensor_id, timestamp,
			received_at, service_type, event_type,
			source_ip, source_port, dest_port,
			tags, service_data
		FROM events
		ORDER BY timestamp DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying recent events: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

func (s *PgxStore) CountByService(
	ctx context.Context, since time.Time,
) (map[types.ServiceType]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT service_type, COUNT(*)
		FROM events
		WHERE timestamp >= $1
		GROUP BY service_type`,
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("counting by service: %w", err)
	}
	defer rows.Close()

	result := make(map[types.ServiceType]int64)
	for rows.Next() {
		var svc string
		var count int64
		if err := rows.Scan(&svc, &count); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		st, _ := types.ParseServiceType(svc)
		result[st] = count
	}

	return result, rows.Err()
}

func (s *PgxStore) CountByCountry(
	ctx context.Context, since time.Time,
) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(country_code, 'unknown'), COUNT(*)
		FROM events
		WHERE timestamp >= $1
		GROUP BY country_code
		ORDER BY COUNT(*) DESC`,
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("counting by country: %w", err)
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var country string
		var count int64
		if err := rows.Scan(&country, &count); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		result[country] = count
	}

	return result, rows.Err()
}

func (s *PgxStore) TotalCount(
	ctx context.Context,
) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM events`,
	).Scan(&count)
	return count, err
}

func (s *PgxStore) InsertSession(
	ctx context.Context, sess *types.Session,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (
			id, sensor_id, started_at, service_type,
			source_ip, source_port, dest_port,
			client_version, login_success, username
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		sess.ID, sess.SensorID, sess.StartedAt,
		sess.ServiceType.String(),
		sess.SourceIP, sess.SourcePort, sess.DestPort,
		sess.ClientVersion, sess.LoginSuccess, sess.Username,
	)
	if err != nil {
		return fmt.Errorf("inserting session: %w", err)
	}
	return nil
}

func (s *PgxStore) UpdateSession(
	ctx context.Context, sess *types.Session,
) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions SET
			ended_at = $2,
			login_success = $3,
			username = $4,
			command_count = $5,
			mitre_techniques = $6,
			threat_score = $7,
			tags = $8
		WHERE id = $1`,
		sess.ID, sess.EndedAt, sess.LoginSuccess,
		sess.Username, sess.CommandCount,
		sess.MITRETechniques, sess.ThreatScore, sess.Tags,
	)
	if err != nil {
		return fmt.Errorf("updating session: %w", err)
	}
	return nil
}

func (s *PgxStore) GetSession(
	ctx context.Context, id string,
) (*types.Session, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, sensor_id, started_at, ended_at,
			service_type, source_ip, source_port, dest_port,
			client_version, login_success, username,
			command_count, mitre_techniques, threat_score, tags
		FROM sessions
		WHERE id = $1`,
		id,
	)

	return scanSession(row)
}

func (s *PgxStore) ListSessions(
	ctx context.Context,
	service string,
	limit, offset int,
) ([]*types.Session, int64, error) {
	var total int64
	countQuery := `SELECT COUNT(*) FROM sessions`
	listQuery := `
		SELECT id, sensor_id, started_at, ended_at,
			service_type, source_ip, source_port, dest_port,
			client_version, login_success, username,
			command_count, mitre_techniques, threat_score, tags
		FROM sessions`

	if service != "" {
		countQuery += ` WHERE service_type = $1`
		listQuery += ` WHERE service_type = $1
			ORDER BY started_at DESC LIMIT $2 OFFSET $3`

		if err := s.pool.QueryRow(
			ctx, countQuery, service,
		).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf(
				"counting sessions: %w", err,
			)
		}

		rows, err := s.pool.Query(
			ctx, listQuery, service, limit, offset,
		)
		if err != nil {
			return nil, 0, fmt.Errorf(
				"listing sessions: %w", err,
			)
		}
		defer rows.Close()
		sessions, err := scanSessions(rows)
		return sessions, total, err
	}

	listQuery += ` ORDER BY started_at DESC LIMIT $1 OFFSET $2`

	if err := s.pool.QueryRow(
		ctx, countQuery,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting sessions: %w", err)
	}

	rows, err := s.pool.Query(ctx, listQuery, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing sessions: %w", err)
	}
	defer rows.Close()
	sessions, err := scanSessions(rows)
	return sessions, total, err
}

func (s *PgxStore) ActiveSessions(
	ctx context.Context,
) ([]*types.Session, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, sensor_id, started_at, ended_at,
			service_type, source_ip, source_port, dest_port,
			client_version, login_success, username,
			command_count, mitre_techniques, threat_score, tags
		FROM sessions
		WHERE ended_at IS NULL
		ORDER BY started_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"querying active sessions: %w", err,
		)
	}
	defer rows.Close()

	return scanSessions(rows)
}

func (s *PgxStore) UpsertAttacker(
	ctx context.Context, a *types.Attacker,
) error {
	tags := a.Tags
	if tags == nil {
		tags = []string{}
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO attackers (
			ip, first_seen, last_seen, total_events,
			total_sessions, country_code, country, city,
			latitude, longitude, asn, org,
			threat_score, tool_family, tags
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15
		)
		ON CONFLICT (ip) DO UPDATE SET
			last_seen = EXCLUDED.last_seen,
			total_events = attackers.total_events + EXCLUDED.total_events,
			total_sessions = attackers.total_sessions + EXCLUDED.total_sessions,
			threat_score = GREATEST(attackers.threat_score, EXCLUDED.threat_score),
			tool_family = COALESCE(EXCLUDED.tool_family, attackers.tool_family),
			tags = EXCLUDED.tags`,
		a.IP, a.FirstSeen, a.LastSeen, a.TotalEvents,
		a.TotalSessions, a.Geo.CountryCode, a.Geo.Country,
		a.Geo.City, a.Geo.Latitude, a.Geo.Longitude,
		a.Geo.ASN, a.Geo.Org,
		a.ThreatScore, a.ToolFamily, tags,
	)
	if err != nil {
		return fmt.Errorf("upserting attacker: %w", err)
	}
	return nil
}

func (s *PgxStore) GetAttacker(
	ctx context.Context, id int64,
) (*types.Attacker, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, ip, first_seen, last_seen, total_events,
			total_sessions, country_code, country, city,
			latitude, longitude, asn, org,
			threat_score, tool_family, tags
		FROM attackers
		WHERE id = $1`,
		id,
	)
	return scanAttacker(row)
}

func (s *PgxStore) GetAttackerByIP(
	ctx context.Context, ip string,
) (*types.Attacker, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, ip, first_seen, last_seen, total_events,
			total_sessions, country_code, country, city,
			latitude, longitude, asn, org,
			threat_score, tool_family, tags
		FROM attackers
		WHERE ip = $1`,
		ip,
	)
	return scanAttacker(row)
}

func (s *PgxStore) TopAttackers(
	ctx context.Context, since time.Time, limit, offset int,
) ([]*types.Attacker, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, ip, first_seen, last_seen, total_events,
			total_sessions, country_code, country, city,
			latitude, longitude, asn, org,
			threat_score, tool_family, tags
		FROM attackers
		WHERE last_seen >= $1
		ORDER BY threat_score DESC, total_events DESC
		LIMIT $2 OFFSET $3`,
		since, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"querying top attackers: %w", err,
		)
	}
	defer rows.Close()

	var attackers []*types.Attacker
	for rows.Next() {
		a, err := scanAttackerRow(rows)
		if err != nil {
			return nil, err
		}
		attackers = append(attackers, a)
	}
	return attackers, rows.Err()
}

func (s *PgxStore) InsertCredential(
	ctx context.Context, c *types.Credential,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO credentials (
			session_id, timestamp, service_type, source_ip,
			username, password, public_key, auth_method, success
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.SessionID, c.Timestamp, c.ServiceType.String(),
		c.SourceIP, c.Username, c.Password,
		c.PublicKey, c.AuthMethod, c.Success,
	)
	if err != nil {
		return fmt.Errorf("inserting credential: %w", err)
	}
	return nil
}

func (s *PgxStore) TopUsernames(
	ctx context.Context, limit int,
) ([]CredentialCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT username, COUNT(*) as cnt
		FROM credentials
		GROUP BY username
		ORDER BY cnt DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying top usernames: %w", err)
	}
	defer rows.Close()
	return scanCredentialCounts(rows)
}

func (s *PgxStore) TopPasswords(
	ctx context.Context, limit int,
) ([]CredentialCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT password, COUNT(*) as cnt
		FROM credentials
		GROUP BY password
		ORDER BY cnt DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying top passwords: %w", err)
	}
	defer rows.Close()
	return scanCredentialCounts(rows)
}

func scanCredentialCounts(
	rows pgx.Rows,
) ([]CredentialCount, error) {
	var results []CredentialCount
	for rows.Next() {
		var cc CredentialCount
		if err := rows.Scan(&cc.Value, &cc.Count); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		results = append(results, cc)
	}
	return results, rows.Err()
}

func (s *PgxStore) TopPairs(
	ctx context.Context, limit int,
) ([]CredentialPairCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT username, password, COUNT(*) as cnt
		FROM credentials
		GROUP BY username, password
		ORDER BY cnt DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying top pairs: %w", err)
	}
	defer rows.Close()

	var results []CredentialPairCount
	for rows.Next() {
		var cp CredentialPairCount
		if err := rows.Scan(
			&cp.Username, &cp.Password, &cp.Count,
		); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		results = append(results, cp)
	}
	return results, rows.Err()
}

func (s *PgxStore) UpsertIOC(
	ctx context.Context, ioc *types.IOC,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO iocs (
			type, value, first_seen, last_seen,
			sight_count, confidence, source, tags
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (type, value) DO UPDATE SET
			last_seen = EXCLUDED.last_seen,
			sight_count = iocs.sight_count + 1,
			confidence = GREATEST(iocs.confidence, EXCLUDED.confidence)`,
		ioc.Type.String(), ioc.Value, ioc.FirstSeen,
		ioc.LastSeen, ioc.SightCount,
		ioc.Confidence, ioc.Source, ioc.Tags,
	)
	if err != nil {
		return fmt.Errorf("upserting ioc: %w", err)
	}
	return nil
}

func (s *PgxStore) ListIOCs(
	ctx context.Context, limit, offset int,
) ([]*types.IOC, int64, error) {
	var total int64
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM iocs`,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting iocs: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, type, value, first_seen, last_seen,
			sight_count, confidence, source, tags
		FROM iocs
		ORDER BY last_seen DESC
		LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("listing iocs: %w", err)
	}
	defer rows.Close()

	var iocs []*types.IOC
	for rows.Next() {
		var ioc types.IOC
		var iocType string
		if err := rows.Scan(
			&ioc.ID, &iocType, &ioc.Value,
			&ioc.FirstSeen, &ioc.LastSeen,
			&ioc.SightCount, &ioc.Confidence,
			&ioc.Source, &ioc.Tags,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning ioc: %w", err)
		}
		ioc.Type, _ = types.ParseIOCType(iocType)
		iocs = append(iocs, &ioc)
	}
	return iocs, total, rows.Err()
}

func (s *PgxStore) InsertDetection(
	ctx context.Context, d *types.MITREDetection,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO mitre_detections (
			session_id, technique_id, tactic, confidence,
			source_ip, service_type, evidence, detected_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		d.SessionID, d.TechniqueID, d.Tactic,
		d.Confidence, d.SourceIP,
		d.ServiceType.String(), d.Evidence, d.DetectedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting detection: %w", err)
	}
	return nil
}

func (s *PgxStore) TechniqueHeatmap(
	ctx context.Context, since time.Time,
) ([]TechniqueCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT technique_id, tactic, COUNT(*)
		FROM mitre_detections
		WHERE detected_at >= $1
		GROUP BY technique_id, tactic
		ORDER BY COUNT(*) DESC`,
		since,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"querying technique heatmap: %w", err,
		)
	}
	defer rows.Close()

	var results []TechniqueCount
	for rows.Next() {
		var tc TechniqueCount
		if err := rows.Scan(
			&tc.TechniqueID, &tc.Tactic, &tc.Count,
		); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		results = append(results, tc)
	}
	return results, rows.Err()
}

func (s *PgxStore) RecentDetections(
	ctx context.Context, limit int,
) ([]*types.MITREDetection, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, session_id, technique_id, tactic,
			confidence, source_ip, service_type,
			evidence, detected_at
		FROM mitre_detections
		ORDER BY detected_at DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"querying recent detections: %w", err,
		)
	}
	defer rows.Close()

	var detections []*types.MITREDetection
	for rows.Next() {
		var d types.MITREDetection
		var svc string
		if err := rows.Scan(
			&d.ID, &d.SessionID, &d.TechniqueID,
			&d.Tactic, &d.Confidence, &d.SourceIP,
			&svc, &d.Evidence, &d.DetectedAt,
		); err != nil {
			return nil, fmt.Errorf(
				"scanning detection: %w", err,
			)
		}
		d.ServiceType, _ = types.ParseServiceType(svc)
		detections = append(detections, &d)
	}
	return detections, rows.Err()
}

func scanEvents(rows pgx.Rows) ([]*types.Event, error) {
	var events []*types.Event
	for rows.Next() {
		var ev types.Event
		var svc, evt string
		if err := rows.Scan(
			&ev.ID, &ev.SessionID, &ev.SensorID,
			&ev.Timestamp, &ev.ReceivedAt,
			&svc, &evt,
			&ev.SourceIP, &ev.SourcePort, &ev.DestPort,
			&ev.Tags, &ev.ServiceData,
		); err != nil {
			return nil, fmt.Errorf("scanning event: %w", err)
		}
		ev.ServiceType, _ = types.ParseServiceType(svc)
		ev.EventType, _ = types.ParseEventType(evt)
		events = append(events, &ev)
	}
	return events, rows.Err()
}

func scanSession(row pgx.Row) (*types.Session, error) {
	var s types.Session
	var svc string
	err := row.Scan(
		&s.ID, &s.SensorID, &s.StartedAt, &s.EndedAt,
		&svc, &s.SourceIP, &s.SourcePort, &s.DestPort,
		&s.ClientVersion, &s.LoginSuccess, &s.Username,
		&s.CommandCount, &s.MITRETechniques,
		&s.ThreatScore, &s.Tags,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning session: %w", err)
	}
	s.ServiceType, _ = types.ParseServiceType(svc)
	return &s, nil
}

func scanSessions(rows pgx.Rows) ([]*types.Session, error) {
	var sessions []*types.Session
	for rows.Next() {
		var s types.Session
		var svc string
		if err := rows.Scan(
			&s.ID, &s.SensorID, &s.StartedAt, &s.EndedAt,
			&svc, &s.SourceIP, &s.SourcePort, &s.DestPort,
			&s.ClientVersion, &s.LoginSuccess, &s.Username,
			&s.CommandCount, &s.MITRETechniques,
			&s.ThreatScore, &s.Tags,
		); err != nil {
			return nil, fmt.Errorf("scanning session: %w", err)
		}
		s.ServiceType, _ = types.ParseServiceType(svc)
		sessions = append(sessions, &s)
	}
	return sessions, rows.Err()
}

func scanAttacker(row pgx.Row) (*types.Attacker, error) {
	var a types.Attacker
	err := row.Scan(
		&a.ID, &a.IP, &a.FirstSeen, &a.LastSeen,
		&a.TotalEvents, &a.TotalSessions,
		&a.Geo.CountryCode, &a.Geo.Country, &a.Geo.City,
		&a.Geo.Latitude, &a.Geo.Longitude,
		&a.Geo.ASN, &a.Geo.Org,
		&a.ThreatScore, &a.ToolFamily, &a.Tags,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning attacker: %w", err)
	}
	return &a, nil
}

func scanAttackerRow(
	rows pgx.Rows,
) (*types.Attacker, error) {
	var a types.Attacker
	err := rows.Scan(
		&a.ID, &a.IP, &a.FirstSeen, &a.LastSeen,
		&a.TotalEvents, &a.TotalSessions,
		&a.Geo.CountryCode, &a.Geo.Country, &a.Geo.City,
		&a.Geo.Latitude, &a.Geo.Longitude,
		&a.Geo.ASN, &a.Geo.Org,
		&a.ThreatScore, &a.ToolFamily, &a.Tags,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning attacker: %w", err)
	}
	return &a, nil
}

var _ json.Marshaler = (*types.ServiceType)(nil)
