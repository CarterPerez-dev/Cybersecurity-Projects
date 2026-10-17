// ©AngelaMos | 2026
// answer.go

package dbx

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

// Answer is what the engine said about one credential, not whether khaos's
// request succeeded. Terminated is never produced by classification: it needs
// a second observation proving the server is still up.
type Answer string

const (
	// Unknown is the zero value on purpose, so a half-built Result reads as
	// khaos not knowing rather than as the engine serving.
	Unknown Answer = "unknown"

	Served  Answer = "served"
	Refused Answer = "refused"
	Locked  Answer = "locked"

	// Expired and MustReset are the same operator action arriving at two
	// different points. MySQL 8.4 refuses an expired credential at connect;
	// MariaDB 11.4 authenticates it and then refuses to execute.
	Expired   Answer = "expired"
	MustReset Answer = "must-reset"

	// Terminated is a session the engine closed under khaos while remaining
	// reachable, which is the one control that revokes a live credential.
	Terminated Answer = "terminated"

	// Unreachable is the engine, not the credential.
	Unreachable Answer = "unreachable"

	// Misconfigured is khaos's own fault and is excluded from every rate.
	Misconfigured Answer = "misconfigured"
)

const (
	codeInvalidPassword = "28P01"
	codeNotPermitted    = "28000"
	codeAdminShutdown   = "57P01"
	codeBadCatalog      = "3D000"
	codeBadRole         = "42704"

	numberAccessDenied  = 1045
	numberLockedMySQL   = 3118
	numberLockedMariaDB = 4151
	numberMustReset     = 1820
	numberMustChange    = 1862
	numberNoSuchDB      = 1049
	numberDBAccess      = 1044

	detailServed = "the engine accepted the credential and answered a query"

	// PostgreSQL's three-way collision, stated in the detail rather than
	// resolved. Measured: a wrong password, a VALID UNTIL in the past and a
	// role that does not exist all produce this one message, and the
	// distinguishing DETAIL line exists only in the server log.
	detailRefusedPostgres = "%s; PostgreSQL returns this same message for a wrong password, for a credential whose validity has passed and for a role that does not exist, so khaos cannot resolve which from the client side"

	detailRefused    = "%s"
	detailTerminated = "the engine closed this session while remaining reachable to khaos's own administrative connection: %s"
	detailLocked     = "the account is locked or not permitted to log in: %s"
	detailMustReset  = "the credential authenticated and then refused to execute until it is reset: %s"

	// Which end of the connection an expiry lands on depends on a capability
	// the client advertises. khaos's driver does not advertise it, so MySQL
	// refuses at connect with 1862 where a CLI passing
	// --connect-expired-password is admitted and then fails at execute with
	// 1820, which is what MariaDB does to every client.
	detailExpired = "the engine refused the connection outright because the credential has expired: %s"

	detailUnreachable = "khaos could not reach the engine at all: %s"
	detailKhaosFault  = "khaos's own connection details are wrong rather than the credential: %s"
)

// Result is one observation of one credential against one engine.
type Result struct {
	Answer  Answer
	Detail  string
	Err     error
	Version string
}

// Decided reports whether the engine made a statement about the credential.
// An unreachable engine and khaos's own misconfiguration are not statements.
func (r Result) Decided() bool {
	switch r.Answer {
	case Served, Refused, Locked, Expired, MustReset, Terminated:
		return true
	default:
		return false
	}
}

func served() Result {
	return Result{Answer: Served, Detail: detailServed}
}

// classify reads the engine's own error code rather than its message text,
// except in the detail, which carries the message verbatim because a restated
// constant is not evidence.
func classify(engine Engine, err error) Result {
	if err == nil {
		return served()
	}

	if engine.MySQLFamily() {
		return classifyMySQL(err)
	}

	return classifyPostgres(err)
}

func classifyPostgres(err error) Result {
	var pgErr *pq.Error
	if errors.As(err, &pgErr) {
		switch string(pgErr.Code) {
		case codeInvalidPassword:
			return Result{
				Answer: Refused,
				Detail: fmt.Sprintf(detailRefusedPostgres, pgErr.Message),
				Err:    err,
			}
		case codeNotPermitted:
			return Result{
				Answer: Locked,
				Detail: fmt.Sprintf(detailLocked, pgErr.Message),
				Err:    err,
			}
		case codeAdminShutdown:
			return Result{
				Answer: Terminated,
				Detail: fmt.Sprintf(detailTerminated, pgErr.Message),
				Err:    err,
			}
		case codeBadCatalog, codeBadRole:
			return Result{
				Answer: Misconfigured,
				Detail: fmt.Sprintf(detailKhaosFault, pgErr.Message),
				Err:    err,
			}
		default:
			return Result{
				Answer: Refused,
				Detail: fmt.Sprintf(detailRefused, pgErr.Message),
				Err:    err,
			}
		}
	}

	return transport(err)
}

func classifyMySQL(err error) Result {
	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		switch myErr.Number {
		case numberAccessDenied:
			return Result{
				Answer: Refused,
				Detail: fmt.Sprintf(detailRefused, myErr.Message),
				Err:    err,
			}
		case numberLockedMySQL, numberLockedMariaDB:
			return Result{
				Answer: Locked,
				Detail: fmt.Sprintf(detailLocked, myErr.Message),
				Err:    err,
			}
		case numberMustChange:
			return Result{
				Answer: Expired,
				Detail: fmt.Sprintf(detailExpired, myErr.Message),
				Err:    err,
			}
		case numberMustReset:
			return Result{
				Answer: MustReset,
				Detail: fmt.Sprintf(detailMustReset, myErr.Message),
				Err:    err,
			}
		case numberNoSuchDB, numberDBAccess:
			return Result{
				Answer: Misconfigured,
				Detail: fmt.Sprintf(detailKhaosFault, myErr.Message),
				Err:    err,
			}
		default:
			return Result{
				Answer: Refused,
				Detail: fmt.Sprintf(detailRefused, myErr.Message),
				Err:    err,
			}
		}
	}

	return transport(err)
}

// transport is everything that is not the engine answering: a dead socket, a
// closed session, a timeout. It reads as Unreachable until a liveness control
// says otherwise, because a session khaos lost tells it nothing on its own.
func transport(err error) Result {
	return Result{
		Answer: Unreachable,
		Detail: fmt.Sprintf(detailUnreachable, err),
		Err:    err,
	}
}

// lostSession reports whether this error means the connection went away rather
// than the engine refusing something.
func lostSession(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, driver.ErrBadConn) ||
		errors.Is(err, mysql.ErrInvalidConn) ||
		errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error

	return errors.As(err, &netErr)
}
