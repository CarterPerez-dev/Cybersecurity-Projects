// ©AngelaMos | 2026
// dbgateway.go

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

const (
	routeReady = "/ready"

	// routeAlive is PROCESS liveness and nothing else. The container's own
	// healthcheck has to use it, because /health is the endpoint under test:
	// pointing a healthcheck at it makes the fixture unstartable until its
	// database credential exists, and the credential is seeded after the
	// stack is up.
	routeAlive = "/alive"

	// PoolUnbounded is the DEFAULT configuration of a Go service, not a
	// deliberately broken one: `database/sql` closes a connection for age only
	// when SetConnMaxLifetime is positive, and the zero value is zero. Every
	// connection authenticated before a rotation keeps working until the
	// process restarts.
	PoolUnbounded = "unbounded"

	// PoolBounded is the knob that converts a rotation into a revocation. A
	// background cleaner reaps idle connections past the lifetime with no reuse
	// attempt, so the pool redials and the stale secret surfaces.
	PoolBounded = "bounded"

	PoolHeld = "held"

	boundedLifetime = 2 * time.Second
	boundedIdle     = time.Second

	dbQuery       = "SELECT 1"
	dbTimeout     = 3 * time.Second
	readyPoolSize = 1

	headerReason = "X-Khaos-Reason"

	reasonNoCredential  = "no bearer credential was presented"
	reasonNotAuthorized = "the identity provider refused the credential"
	reasonDatabaseDown  = "the database refused or could not be reached"
	reasonPooled        = "answered on a pooled connection"
	reasonFresh         = "answered on a connection dialled for this request"
)

// dbGateway is the fixture the pooled-credential experiments measure. It holds
// a database credential of its own, which is the one khaos rotates, and it
// answers three questions that a real service usually conflates:
//
//   - /protected serves data, and needs both a caller credential and the
//     database;
//   - /health answers on a POOLED connection, which is what almost every
//     liveness probe does and what keeps reporting green through a total
//     credential failure;
//   - /ready forces a FRESH connection, which is what readiness should do and
//     almost none do.
type dbGateway struct {
	db   *sql.DB
	dsn  string
	mode string

	upstream string
	failMode string
	client   *http.Client

	mu   sync.Mutex
	held *sql.Conn
}

func newDBGateway(dsn, mode, upstream, failMode string) *dbGateway {
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		pool = nil
	}

	gateway := &dbGateway{
		db:       pool,
		dsn:      dsn,
		mode:     mode,
		upstream: upstream,
		failMode: failMode,
		client:   &http.Client{Timeout: upstreamTimeout},
	}

	gateway.configure()

	return gateway
}

// configure is where the fixture's whole behaviour lives, and every value is
// the real default rather than an exaggeration.
func (g *dbGateway) configure() {
	if g.db == nil {
		return
	}

	switch g.mode {
	case PoolBounded:
		g.db.SetConnMaxLifetime(boundedLifetime)
		g.db.SetConnMaxIdleTime(boundedIdle)

	case PoolHeld:
		// The SAME lifetime the bounded mode sets, which is the point: the
		// background cleaner only ever walks the idle list, so a connection
		// that is checked out rather than idle is not bounded by it at all.
		// Without the lifetime this mode would just be the unbounded one with
		// extra steps.
		//
		// The connection is acquired on first use rather than at startup,
		// because the engine may not hold the fixture's role yet when the
		// container starts and a checkout that failed once would leave this
		// mode measuring the unbounded one.
		g.db.SetConnMaxLifetime(boundedLifetime)
		g.db.SetConnMaxIdleTime(boundedIdle)

	default:
		// PoolUnbounded. Nothing is set, deliberately: this is the shape a
		// service has when nobody called SetConnMaxLifetime at all.
	}
}

func (g *dbGateway) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(routeAlive, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(routeHealth, g.health)
	mux.HandleFunc(routeReady, g.ready)
	mux.HandleFunc(routeProtected, g.protected)
	mux.HandleFunc(issuePath, g.forward(issuePath))
	mux.HandleFunc(revokePath, g.forward(revokePath))

	return mux
}

// health is the trap. It asks the database over whatever connection the pool
// hands it, which after a rotation is one that authenticated before the
// rotation, so it answers green while no new connection can be made at all.
func (g *dbGateway) health(w http.ResponseWriter, r *http.Request) {
	if err := g.queryPooled(r.Context()); err != nil {
		w.Header().Set(headerReason, reasonDatabaseDown)
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	w.Header().Set(headerReason, reasonPooled)
	w.WriteHeader(http.StatusOK)
}

// ready forces a connection of its own, which is the only way to answer the
// question readiness is asking.
func (g *dbGateway) ready(w http.ResponseWriter, r *http.Request) {
	if err := g.queryFresh(r.Context()); err != nil {
		w.Header().Set(headerReason, reasonDatabaseDown)
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	w.Header().Set(headerReason, reasonFresh)
	w.WriteHeader(http.StatusOK)
}

func (g *dbGateway) protected(w http.ResponseWriter, r *http.Request) {
	token, scheme := strings.CutPrefix(
		r.Header.Get(headerAuthorization),
		bearerPrefix,
	)

	if !scheme || token == "" {
		w.Header().Set(headerReason, reasonNoCredential)
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	active, reachable := g.introspect(token)

	if !reachable && g.failMode != FailOpen {
		w.Header().Set(headerReason, reasonNotAuthorized)
		w.WriteHeader(http.StatusForbidden)

		return
	}

	if reachable && !active {
		w.Header().Set(headerReason, reasonNotAuthorized)
		w.WriteHeader(http.StatusForbidden)

		return
	}

	// The credential is good, so whether this request is served is now purely
	// a question about the database.
	if err := g.queryPooled(r.Context()); err != nil {
		w.Header().Set(headerReason, reasonDatabaseDown)
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	w.Header().Set(headerReason, reasonPooled)
	w.WriteHeader(http.StatusOK)
}

// queryPooled prefers the held connection when there is one, because that is
// the configuration under test, and otherwise lets the pool decide.
func (g *dbGateway) queryPooled(ctx context.Context) error {
	if g.db == nil {
		return sql.ErrConnDone
	}

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	var one int

	if held := g.heldConn(ctx); held != nil {
		return held.QueryRowContext(ctx, dbQuery).Scan(&one)
	}

	return g.db.QueryRowContext(ctx, dbQuery).Scan(&one)
}

// heldConn is the checked-out connection this fixture keeps for the life of
// the process, acquired on first use. It is never returned to the pool, which
// is what makes it age-unbounded.
func (g *dbGateway) heldConn(ctx context.Context) *sql.Conn {
	if g.mode != PoolHeld {
		return nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.held != nil {
		return g.held
	}

	conn, err := g.db.Conn(ctx)
	if err != nil {
		return nil
	}

	g.held = conn

	return g.held
}

// queryFresh opens its own pool for one question so the dial cannot be
// satisfied from anything that authenticated earlier.
func (g *dbGateway) queryFresh(ctx context.Context) error {
	fresh, err := sql.Open("postgres", g.dsn)
	if err != nil {
		return err
	}
	defer func() { _ = fresh.Close() }()

	fresh.SetMaxIdleConns(0)
	fresh.SetMaxOpenConns(readyPoolSize)

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	var one int

	return fresh.QueryRowContext(ctx, dbQuery).Scan(&one)
}

func (g *dbGateway) introspect(token string) (bool, bool) {
	response, err := g.client.Get(g.upstream + introspectPath + token)
	if err != nil {
		return false, false
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode == http.StatusUnauthorized ||
		response.StatusCode == http.StatusForbidden {
		return false, true
	}

	if response.StatusCode != http.StatusOK {
		return false, false
	}

	var body introspection
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return false, false
	}

	return body.Active, true
}

func (g *dbGateway) forward(path string) http.HandlerFunc {
	plain := &gateway{upstream: g.upstream, client: g.client}

	return plain.forward(path)
}
