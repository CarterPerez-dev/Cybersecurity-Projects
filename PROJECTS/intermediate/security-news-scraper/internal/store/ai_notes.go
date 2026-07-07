// ©AngelaMos | 2026
// ai_notes.go

package store

import (
	"database/sql"
	"errors"
	"fmt"
)

type AINote struct {
	ID         int64
	ClusterID  int64
	Provider   string
	Summary    string
	Why        string
	AnglesJSON string
	Format     string
	CreatedAt  int64
}

func (s *Store) InsertAINote(n AINote) error {
	_, err := s.db.Exec(`
		INSERT INTO ai_notes (cluster_id, provider, summary, why, angles_json, format, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, provider) DO UPDATE SET
			summary = excluded.summary,
			why = excluded.why,
			angles_json = excluded.angles_json,
			format = excluded.format,
			created_at = excluded.created_at`,
		n.ClusterID, n.Provider, n.Summary, n.Why, n.AnglesJSON, n.Format, n.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert ai_note cluster=%d provider=%q: %w", n.ClusterID, n.Provider, err)
	}
	return nil
}

func (s *Store) AINoteExists(clusterID int64, provider string) (bool, error) {
	var one int
	err := s.db.QueryRow(
		`SELECT 1 FROM ai_notes WHERE cluster_id = ? AND provider = ? LIMIT 1`,
		clusterID, provider,
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("ai_note exists cluster=%d provider=%q: %w", clusterID, provider, err)
	}
	return true, nil
}

func (s *Store) AINotesForCluster(clusterID int64) ([]AINote, error) {
	rows, err := s.db.Query(`
		SELECT id, cluster_id, provider, summary, why, angles_json, format, created_at
		FROM ai_notes WHERE cluster_id = ? ORDER BY provider`, clusterID)
	if err != nil {
		return nil, fmt.Errorf("ai_notes for cluster %d: %w", clusterID, err)
	}
	defer rows.Close()
	var out []AINote
	for rows.Next() {
		var n AINote
		if err := rows.Scan(&n.ID, &n.ClusterID, &n.Provider, &n.Summary, &n.Why, &n.AnglesJSON, &n.Format, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("ai_notes for cluster %d: scan: %w", clusterID, err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) LatestAINotes() (map[int64]AINote, error) {
	rows, err := s.db.Query(`
		SELECT id, cluster_id, provider, summary, why, angles_json, format, created_at
		FROM ai_notes ORDER BY cluster_id, created_at`)
	if err != nil {
		return nil, fmt.Errorf("latest ai_notes: %w", err)
	}
	defer rows.Close()
	out := make(map[int64]AINote)
	for rows.Next() {
		var n AINote
		if err := rows.Scan(&n.ID, &n.ClusterID, &n.Provider, &n.Summary, &n.Why, &n.AnglesJSON, &n.Format, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("latest ai_notes: scan: %w", err)
		}
		out[n.ClusterID] = n
	}
	return out, rows.Err()
}
