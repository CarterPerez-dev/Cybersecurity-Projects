// ©AngelaMos | 2026
// session.go

package dbx

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	errHoldFailed = "khaos could not establish the session it needs to hold across the fault: %w"

	detailAlreadyLost = "this session is still closed, and khaos's administrative connection still reaches the engine: %s"
)

// Try opens a connection of its own and asks the engine one question. It never
// reuses a pooled connection, because the whole measurement is what happens at
// authentication time and a reused connection skips it.
func (c *Client) Try(ctx context.Context, cred Credential) Result {
	pool, err := sql.Open(
		c.config.Engine.driver(),
		dsn(c.config.Engine, c.config.Address, c.config.Database, cred),
	)
	if err != nil {
		return Result{
			Answer: Misconfigured,
			Detail: fmt.Sprintf(detailKhaosFault, err),
			Err:    err,
		}
	}
	defer func() { _ = pool.Close() }()

	pool.SetMaxIdleConns(0)

	ctx, cancel := context.WithTimeout(ctx, dialTimeout+queryTimeout)
	defer cancel()

	var one int

	return classify(
		c.config.Engine,
		pool.QueryRowContext(ctx, probeQuery).Scan(&one),
	)
}

// Session is one connection, authenticated once and then held. It is pinned
// through sql.Conn rather than left in a pool on purpose: a checked-out
// connection is age-unbounded in database/sql, which is the shape a real
// service reproduces with an open transaction or a long poll.
type Session struct {
	client *Client
	pool   *sql.DB
	conn   *sql.Conn
	cred   Credential

	openedAt time.Time
	lost     bool
	lostWhy  string
}

// Hold authenticates now and proves the session works now, so a later refusal
// is the fault rather than a credential that was never accepted.
func (c *Client) Hold(
	ctx context.Context,
	cred Credential,
) (*Session, error) {
	pool, err := sql.Open(
		c.config.Engine.driver(),
		dsn(c.config.Engine, c.config.Address, c.config.Database, cred),
	)
	if err != nil {
		return nil, fmt.Errorf(errHoldFailed, err)
	}

	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout+queryTimeout)
	defer cancel()

	conn, err := pool.Conn(dialCtx)
	if err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf(errHoldFailed, err)
	}

	var one int
	if err := conn.QueryRowContext(
		dialCtx,
		probeQuery,
	).Scan(&one); err != nil {
		_ = conn.Close()
		_ = pool.Close()

		return nil, fmt.Errorf(errHoldFailed, err)
	}

	return &Session{
		client:   c,
		pool:     pool,
		conn:     conn,
		cred:     cred,
		openedAt: time.Now().UTC(),
	}, nil
}

func (s *Session) Credential() Credential {
	return s.cred
}

func (s *Session) OpenedAt() time.Time {
	return s.openedAt
}

// Query asks the held session one question. A connection-level failure is put
// to a liveness control before it is called a termination: khaos's own
// administrative connection must still reach the engine, or losing the session
// says nothing about the credential.
func (s *Session) Query(ctx context.Context) Result {
	if s.lost {
		return s.confirmStillLost(ctx)
	}

	queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var one int

	err := s.conn.QueryRowContext(queryCtx, probeQuery).Scan(&one)
	if err == nil {
		return served()
	}

	result := classify(s.client.config.Engine, err)

	if result.Answer == Terminated {
		s.markLost(result.Detail)
		return result
	}

	if result.Answer != Unreachable || !lostSession(err) {
		return result
	}

	if pingErr := s.client.Ping(ctx); pingErr != nil {
		return result
	}

	terminated := Result{
		Answer: Terminated,
		Detail: fmt.Sprintf(detailTerminated, err),
		Err:    err,
	}
	s.markLost(terminated.Detail)

	return terminated
}

// confirmStillLost re-runs the liveness control on every later sample rather
// than latching on the first one, so the claim stays measured for as long as
// it is reported.
func (s *Session) confirmStillLost(ctx context.Context) Result {
	if err := s.client.Ping(ctx); err != nil {
		return transport(err)
	}

	return Result{
		Answer: Terminated,
		Detail: fmt.Sprintf(detailAlreadyLost, s.lostWhy),
	}
}

func (s *Session) markLost(why string) {
	s.lost = true
	s.lostWhy = why
}

func (s *Session) Close() error {
	connErr := s.conn.Close()
	poolErr := s.pool.Close()
	if errors.Is(connErr, sql.ErrConnDone) {
		connErr = nil
	}
	return errors.Join(connErr, poolErr)
}
