// ©AngelaMos | 2026
// store.go

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var ErrDuplicate = errors.New("store: article already exists")

const (
	EnrichStatusOK       = "ok"
	EnrichStatusNotFound = "not_found"
)

type Store struct {
	db      *sql.DB
	version int
}

type SourceInput struct {
	Name    string
	Title   string
	URL     string
	Type    string
	Weight  float64
	Tags    []string
	Enabled bool
}

type SourceRow struct {
	ID      int64
	Name    string
	Title   string
	URL     string
	Type    string
	Weight  float64
	Tags    []string
	Enabled bool
}

type Article struct {
	SourceID     int64
	CanonicalURL string
	ContentHash  string
	TitleHash    string
	Title        string
	Summary      string
	Body         string
	Author       string
	PublishedAt  int64
	FetchedAt    int64
}

type FetchState struct {
	ETag         string
	LastModified string
	LastFetched  int64
	LastStatus   int64
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite %s: %w", path, err)
	}
	version, err := migrate(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, version: version}, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Version() int { return s.version }
func (s *Store) DB() *sql.DB  { return s.db }

func (s *Store) UpsertSource(in SourceInput) (int64, error) {
	tags := strings.Join(in.Tags, ",")
	var id int64
	err := s.db.QueryRow(`
		INSERT INTO sources (name, title, url, type, weight, tags, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			title = excluded.title, url = excluded.url, type = excluded.type,
			weight = excluded.weight, tags = excluded.tags, enabled = excluded.enabled
		RETURNING id`,
		in.Name, in.Title, in.URL, in.Type, in.Weight, tags, boolToInt(in.Enabled),
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upsert source %q: %w", in.Name, err)
	}
	return id, nil
}

func (s *Store) GetSourceByName(name string) (SourceRow, error) {
	var r SourceRow
	var tags string
	var enabled int
	err := s.db.QueryRow(`
		SELECT id, name, title, url, type, weight, tags, enabled
		FROM sources WHERE name = ?`, name,
	).Scan(&r.ID, &r.Name, &r.Title, &r.URL, &r.Type, &r.Weight, &tags, &enabled)
	if err != nil {
		return SourceRow{}, fmt.Errorf("get source %q: %w", name, err)
	}
	if tags != "" {
		r.Tags = strings.Split(tags, ",")
	}
	r.Enabled = enabled != 0
	return r, nil
}

func (s *Store) InsertArticle(a Article) (int64, error) {
	res, err := s.db.Exec(`
		INSERT INTO articles
			(source_id, canonical_url, content_hash, title_hash, title, summary, body, author, published_at, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.SourceID, a.CanonicalURL, a.ContentHash, a.TitleHash, a.Title, a.Summary, a.Body,
		a.Author, a.PublishedAt, a.FetchedAt,
	)
	if err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return 0, ErrDuplicate
		}
		return 0, fmt.Errorf("insert article %q: %w", a.CanonicalURL, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("insert article %q: last insert id: %w", a.CanonicalURL, err)
	}
	return id, nil
}

func (s *Store) CountArticles() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM articles`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count articles: %w", err)
	}
	return n, nil
}

func (s *Store) GetFetchState(sourceID int64) (FetchState, bool, error) {
	var fs FetchState
	err := s.db.QueryRow(`
		SELECT etag, last_modified, last_fetched, last_status
		FROM fetch_state WHERE source_id = ?`, sourceID,
	).Scan(&fs.ETag, &fs.LastModified, &fs.LastFetched, &fs.LastStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return FetchState{}, false, nil
	}
	if err != nil {
		return FetchState{}, false, fmt.Errorf("get fetch_state %d: %w", sourceID, err)
	}
	return fs, true, nil
}

func (s *Store) UpsertFetchState(sourceID int64, fs FetchState) error {
	_, err := s.db.Exec(`
		INSERT INTO fetch_state (source_id, etag, last_modified, last_fetched, last_status)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(source_id) DO UPDATE SET
			etag = excluded.etag, last_modified = excluded.last_modified,
			last_fetched = excluded.last_fetched, last_status = excluded.last_status`,
		sourceID, fs.ETag, fs.LastModified, fs.LastFetched, fs.LastStatus,
	)
	if err != nil {
		return fmt.Errorf("upsert fetch_state %d: %w", sourceID, err)
	}
	return nil
}

type CVE struct {
	ID             string
	Description    string
	CVSSScore      *float64
	CVSSVersion    string
	CVSSSeverity   string
	CVSSVector     string
	CWE            string
	IsKEV          bool
	KEVDateAdded   string
	KEVRansomware  bool
	EPSS           *float64
	EPSSPercentile *float64
	NVDPublished   string
	NVDModified    string
	EnrichedAt     int64
	EnrichStatus   string
}

type ArticleSummary struct {
	ID           int64
	SourceName   string
	Title        string
	CanonicalURL string
	PublishedAt  int64
}

type ListFilter struct {
	Source  string
	Since   int64
	MinCVSS float64
	KEV     bool
	Keyword string
	Limit   int
}

func (s *Store) CVEsNeedingEnrichment(now, positiveTTL, negativeTTL int64) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT id FROM cves
		WHERE enriched_at = 0
		   OR (enrich_status = ? AND enriched_at < ?)
		   OR (enrich_status = ? AND enriched_at < ?)
		ORDER BY id`, EnrichStatusOK, now-positiveTTL, EnrichStatusNotFound, now-negativeTTL)
	if err != nil {
		return nil, fmt.Errorf("cves needing enrichment: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("cves needing enrichment: scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) UpdateCVEEnrichment(c CVE) error {
	_, err := s.db.Exec(`
		UPDATE cves SET
			description = ?, cvss_score = ?, cvss_version = ?, cvss_severity = ?, cvss_vector = ?,
			cwe = ?, is_kev = ?, kev_date_added = ?, kev_ransomware = ?,
			epss = ?, epss_percentile = ?, nvd_published = ?, nvd_modified = ?,
			enriched_at = ?, enrich_status = ?
		WHERE id = ?`,
		c.Description, c.CVSSScore, c.CVSSVersion, c.CVSSSeverity, c.CVSSVector,
		c.CWE, boolToInt(c.IsKEV), c.KEVDateAdded, boolToInt(c.KEVRansomware),
		c.EPSS, c.EPSSPercentile, c.NVDPublished, c.NVDModified,
		c.EnrichedAt, c.EnrichStatus, c.ID,
	)
	if err != nil {
		return fmt.Errorf("update cve enrichment %q: %w", c.ID, err)
	}
	return nil
}

func (s *Store) GetCVE(id string) (CVE, error) {
	var c CVE
	var isKEV, ransomware int
	err := s.db.QueryRow(`
		SELECT id, description, cvss_score, cvss_version, cvss_severity, cvss_vector,
			cwe, is_kev, kev_date_added, kev_ransomware, epss, epss_percentile,
			nvd_published, nvd_modified, enriched_at, enrich_status
		FROM cves WHERE id = ?`, id,
	).Scan(&c.ID, &c.Description, &c.CVSSScore, &c.CVSSVersion, &c.CVSSSeverity, &c.CVSSVector,
		&c.CWE, &isKEV, &c.KEVDateAdded, &ransomware, &c.EPSS, &c.EPSSPercentile,
		&c.NVDPublished, &c.NVDModified, &c.EnrichedAt, &c.EnrichStatus)
	if err != nil {
		return CVE{}, fmt.Errorf("get cve %q: %w", id, err)
	}
	c.IsKEV = isKEV != 0
	c.KEVRansomware = ransomware != 0
	return c, nil
}

func (s *Store) ArticlesForCVE(id string) ([]ArticleSummary, error) {
	rows, err := s.db.Query(`
		SELECT a.id, s.name, a.title, a.canonical_url, a.published_at
		FROM article_cves ac
		JOIN articles a ON a.id = ac.article_id
		JOIN sources s ON s.id = a.source_id
		WHERE ac.cve_id = ?
		ORDER BY a.published_at DESC`, id)
	if err != nil {
		return nil, fmt.Errorf("articles for cve %q: %w", id, err)
	}
	defer rows.Close()
	return scanArticleSummaries(rows)
}

func (s *Store) UpsertCVEStub(id string) error {
	_, err := s.db.Exec(`INSERT INTO cves (id) VALUES (?) ON CONFLICT(id) DO NOTHING`, id)
	if err != nil {
		return fmt.Errorf("upsert cve %q: %w", id, err)
	}
	return nil
}

func (s *Store) LinkArticleCVE(articleID int64, cveID string) error {
	_, err := s.db.Exec(`
		INSERT INTO article_cves (article_id, cve_id) VALUES (?, ?)
		ON CONFLICT(article_id, cve_id) DO NOTHING`, articleID, cveID)
	if err != nil {
		return fmt.Errorf("link article %d cve %q: %w", articleID, cveID, err)
	}
	return nil
}

type CandidateArticle struct {
	ID       int64
	SourceID int64
	Title    string
	Time     int64
}

type ClusterRow struct {
	Key       string
	Members   []int64
	FirstSeen int64
	LastSeen  int64
}

func (s *Store) ClusterCandidates(since int64) ([]CandidateArticle, error) {
	rows, err := s.db.Query(`
		SELECT id, source_id, title, COALESCE(NULLIF(published_at, 0), fetched_at) AS t
		FROM articles
		WHERE COALESCE(NULLIF(published_at, 0), fetched_at) >= ?
		ORDER BY id`, since)
	if err != nil {
		return nil, fmt.Errorf("cluster candidates: %w", err)
	}
	defer rows.Close()

	var out []CandidateArticle
	for rows.Next() {
		var c CandidateArticle
		if err := rows.Scan(&c.ID, &c.SourceID, &c.Title, &c.Time); err != nil {
			return nil, fmt.Errorf("cluster candidates: scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) ArticleCVEMap() (map[int64][]string, error) {
	rows, err := s.db.Query(`SELECT article_id, cve_id FROM article_cves`)
	if err != nil {
		return nil, fmt.Errorf("article cve map: %w", err)
	}
	defer rows.Close()

	out := make(map[int64][]string)
	for rows.Next() {
		var articleID int64
		var cveID string
		if err := rows.Scan(&articleID, &cveID); err != nil {
			return nil, fmt.Errorf("article cve map: scan: %w", err)
		}
		out[articleID] = append(out[articleID], cveID)
	}
	return out, rows.Err()
}

func (s *Store) ReplaceClusters(rows []ClusterRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("replace clusters: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM cluster_members`); err != nil {
		return fmt.Errorf("replace clusters: clear members: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM clusters`); err != nil {
		return fmt.Errorf("replace clusters: clear clusters: %w", err)
	}

	for _, r := range rows {
		var clusterID int64
		if err := tx.QueryRow(`
			INSERT INTO clusters (cluster_key, first_seen, last_seen, size)
			VALUES (?, ?, ?, ?) RETURNING id`,
			r.Key, r.FirstSeen, r.LastSeen, len(r.Members),
		).Scan(&clusterID); err != nil {
			return fmt.Errorf("replace clusters: insert cluster %q: %w", r.Key, err)
		}
		for _, articleID := range r.Members {
			if _, err := tx.Exec(`
				INSERT INTO cluster_members (cluster_id, article_id) VALUES (?, ?)`,
				clusterID, articleID,
			); err != nil {
				return fmt.Errorf("replace clusters: insert member %d: %w", articleID, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("replace clusters: commit: %w", err)
	}
	return nil
}

func (s *Store) ListArticles(f ListFilter) ([]ArticleSummary, error) {
	query := `
		SELECT a.id, s.name, a.title, a.canonical_url, a.published_at
		FROM articles a
		JOIN sources s ON s.id = a.source_id
		WHERE 1 = 1`
	var args []any

	if f.Source != "" {
		query += ` AND s.name = ?`
		args = append(args, f.Source)
	}
	if f.Since > 0 {
		query += ` AND a.published_at >= ?`
		args = append(args, f.Since)
	}
	if f.Keyword != "" {
		query += ` AND (a.title LIKE ? OR a.summary LIKE ?)`
		like := "%" + f.Keyword + "%"
		args = append(args, like, like)
	}
	if f.MinCVSS > 0 {
		query += ` AND EXISTS (
			SELECT 1 FROM article_cves ac JOIN cves c ON c.id = ac.cve_id
			WHERE ac.article_id = a.id AND c.cvss_score >= ?)`
		args = append(args, f.MinCVSS)
	}
	if f.KEV {
		query += ` AND EXISTS (
			SELECT 1 FROM article_cves ac JOIN cves c ON c.id = ac.cve_id
			WHERE ac.article_id = a.id AND c.is_kev = 1)`
	}
	query += ` ORDER BY a.published_at DESC`
	if f.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, f.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list articles: %w", err)
	}
	defer rows.Close()
	return scanArticleSummaries(rows)
}

func scanArticleSummaries(rows *sql.Rows) ([]ArticleSummary, error) {
	var out []ArticleSummary
	for rows.Next() {
		var a ArticleSummary
		if err := rows.Scan(&a.ID, &a.SourceName, &a.Title, &a.CanonicalURL, &a.PublishedAt); err != nil {
			return nil, fmt.Errorf("scan article summary: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
