// ©AngelaMos | 2026
// dbx.go

package dbx

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

type Engine string

const (
	Postgres Engine = "postgres"
	MySQL    Engine = "mysql"
	MariaDB  Engine = "mariadb"
)

const (
	driverPostgres = "postgres"
	driverMySQL    = "mysql"

	// sslmode is disabled deliberately. The credential tier measures what an
	// engine does with an authenticated session when its credential changes,
	// which is independent of the transport, and no engine in the range serves
	// TLS by default. MySQL needs no secure channel either: the driver performs
	// the caching_sha2_password RSA public-key exchange, which is what makes a
	// credential error observable over plaintext at all.
	postgresOptions = "sslmode=disable&connect_timeout=5"

	dialTimeout  = 5 * time.Second
	queryTimeout = 5 * time.Second

	probeQuery   = "SELECT 1"
	versionQuery = "SELECT version()"

	createRolePostgres = "CREATE ROLE %s LOGIN PASSWORD %s"
	createUserMySQL    = "CREATE USER %s@'%%' IDENTIFIED BY %s"
	dropRolePostgres   = "DROP ROLE IF EXISTS %s"
	dropUserMySQL      = "DROP USER IF EXISTS %s@'%%'"
	rotatePostgres     = "ALTER ROLE %s PASSWORD %s"
	rotateMySQL        = "ALTER USER %s@'%%' IDENTIFIED BY %s"
	lockPostgres       = "ALTER ROLE %s NOLOGIN"
	unlockPostgres     = "ALTER ROLE %s LOGIN"
	lockMySQL          = "ALTER USER %s@'%%' ACCOUNT LOCK"
	unlockMySQL        = "ALTER USER %s@'%%' ACCOUNT UNLOCK"
	expirePostgres     = "ALTER ROLE %s VALID UNTIL '1970-01-01'"
	unexpirePostgres   = "ALTER ROLE %s VALID UNTIL 'infinity'"
	expireMySQL        = "ALTER USER %s@'%%' PASSWORD EXPIRE"

	terminatePostgres = `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
WHERE usename = $1 AND pid <> pg_backend_pid()`
	listSessionsMySQL = `SELECT id FROM information_schema.processlist
WHERE user = ? AND id <> CONNECTION_ID()`
	killMySQL = "KILL %d"

	errUnknownEngine    = "%w: %q (known engines: %s)"
	errBadIdentifier    = "%w: %q"
	errNoAddress        = "%w: the credential tier needs an address for the engine it is faulting"
	errNoAdmin          = "%w: the credential tier needs an administrative role, read from the target container's own environment"
	errTerminateUnknown = "%w: khaos cannot terminate sessions on %s"
)

var (
	ErrUnknownEngine = errors.New(
		"no database engine is registered under that name",
	)

	// ErrBadIdentifier guards a role name that is interpolated into DDL. No
	// engine accepts a parameter in place of a role name or a password, so the
	// statement is built by hand and the input is constrained instead.
	ErrBadIdentifier = errors.New(
		"that role name is not one khaos is willing to put into a statement",
	)

	ErrIncomplete = errors.New(
		"this credential-tier client is missing something it cannot work without",
	)

	safeIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
)

func Engines() []string {
	return []string{string(MariaDB), string(MySQL), string(Postgres)}
}

func ParseEngine(name string) (Engine, error) {
	engine := Engine(strings.ToLower(strings.TrimSpace(name)))
	if !slices.Contains(Engines(), string(engine)) {
		return "", fmt.Errorf(
			errUnknownEngine,
			ErrUnknownEngine,
			name,
			strings.Join(Engines(), ", "),
		)
	}
	return engine, nil
}

// MySQLFamily reports whether this engine speaks the MySQL wire protocol. It
// does NOT imply a shared authentication path: MySQL 8.4 defaults to
// caching_sha2_password and MariaDB 11.4 to mysql_native_password.
func (e Engine) MySQLFamily() bool {
	return e == MySQL || e == MariaDB
}

func (e Engine) driver() string {
	if e.MySQLFamily() {
		return driverMySQL
	}
	return driverPostgres
}

func (e Engine) String() string {
	return string(e)
}

// Credential is a role and the password presented for it. khaos only ever
// rotates a credential it minted itself, except for the pooled-service
// experiment, where the role belongs to the target.
type Credential struct {
	Role string `json:"role"`

	// Never serialised, structurally. khaos journals where a credential is
	// READ FROM and never the credential, so the type it travels in refuses to
	// marshal it rather than relying on every call site to remember.
	Password string `json:"-"`
}

type Config struct {
	Engine   Engine
	Address  string
	Database string
	Admin    Credential
}

type Client struct {
	config Config
	admin  *sql.DB
}

// Open validates the configuration and opens the administrative pool. It does
// not dial: Ping is what proves the engine is reachable, and the caller wants
// that failure separately from a configuration error.
func Open(config Config) (*Client, error) {
	if _, err := ParseEngine(string(config.Engine)); err != nil {
		return nil, err
	}

	if config.Address == "" {
		return nil, fmt.Errorf(errNoAddress, ErrIncomplete)
	}

	if config.Admin.Role == "" || config.Admin.Password == "" {
		return nil, fmt.Errorf(errNoAdmin, ErrIncomplete)
	}

	pool, err := sql.Open(
		config.Engine.driver(),
		dsn(config.Engine, config.Address, config.Database, config.Admin),
	)
	if err != nil {
		return nil, err
	}

	pool.SetMaxOpenConns(2)
	pool.SetMaxIdleConns(1)

	return &Client{config: config, admin: pool}, nil
}

func (c *Client) Engine() Engine {
	return c.config.Engine
}

func (c *Client) Close() error {
	return c.admin.Close()
}

func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	return c.admin.PingContext(ctx)
}

// Version returns what the SERVER reports, never the image tag. On this host
// `postgres:18` resolved to two different patch releases hours apart, so a run
// record that names a tag names nothing.
func (c *Client) Version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var version string
	if err := c.admin.QueryRowContext(
		ctx,
		versionQuery,
	).Scan(&version); err != nil {
		return "", err
	}

	return version, nil
}

func (c *Client) CreateRole(ctx context.Context, cred Credential) error {
	statement := createRolePostgres
	if c.config.Engine.MySQLFamily() {
		statement = createUserMySQL
	}

	return c.alter(ctx, statement, cred)
}

func (c *Client) Rotate(ctx context.Context, cred Credential) error {
	statement := rotatePostgres
	if c.config.Engine.MySQLFamily() {
		statement = rotateMySQL
	}

	return c.alter(ctx, statement, cred)
}

func (c *Client) DropRole(ctx context.Context, role string) error {
	statement := dropRolePostgres
	if c.config.Engine.MySQLFamily() {
		statement = dropUserMySQL
	}

	return c.exec(ctx, statement, role)
}

func (c *Client) Lock(ctx context.Context, role string) error {
	statement := lockPostgres
	if c.config.Engine.MySQLFamily() {
		statement = lockMySQL
	}

	return c.exec(ctx, statement, role)
}

func (c *Client) Unlock(ctx context.Context, role string) error {
	statement := unlockPostgres
	if c.config.Engine.MySQLFamily() {
		statement = unlockMySQL
	}

	return c.exec(ctx, statement, role)
}

// Expire puts the credential's validity in the past. On the MySQL family this
// does not refuse a new connection: it authenticates and then fails at execute
// with 1820, which a connect-only liveness probe reads as healthy.
func (c *Client) Expire(ctx context.Context, role string) error {
	statement := expirePostgres
	if c.config.Engine.MySQLFamily() {
		statement = expireMySQL
	}

	return c.exec(ctx, statement, role)
}

// Unexpire restores validity. On the MySQL family the only way back is to set
// the password again, so the caller supplies the credential rather than a name.
func (c *Client) Unexpire(ctx context.Context, cred Credential) error {
	if c.config.Engine.MySQLFamily() {
		return c.Rotate(ctx, cred)
	}

	return c.exec(ctx, unexpirePostgres, cred.Role)
}

// Terminate is the only control in any of the three engines that revokes a
// LIVE session. It returns how many it closed, and it never closes khaos's own
// administrative connection.
func (c *Client) Terminate(ctx context.Context, role string) (int, error) {
	if err := validate(role); err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	switch {
	case c.config.Engine == Postgres:
		var killed int
		if err := c.admin.QueryRowContext(
			ctx,
			terminatePostgres,
			role,
		).Scan(&killed); err != nil {
			return 0, err
		}
		return killed, nil

	case c.config.Engine.MySQLFamily():
		return c.killMySQLSessions(ctx, role)

	default:
		return 0, fmt.Errorf(
			errTerminateUnknown,
			ErrUnknownEngine,
			c.config.Engine,
		)
	}
}

// killMySQLSessions reads the identifiers first and kills afterwards, because
// KILL closes the connection the result set is being read from when it lands on
// khaos's own.
func (c *Client) killMySQLSessions(
	ctx context.Context,
	role string,
) (int, error) {
	rows, err := c.admin.QueryContext(ctx, listSessionsMySQL, role)
	if err != nil {
		return 0, err
	}

	ids := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	killed := 0
	var failures []error

	for _, id := range ids {
		if _, err := c.admin.ExecContext(
			ctx,
			fmt.Sprintf(killMySQL, id),
		); err != nil {
			failures = append(failures, err)
			continue
		}
		killed++
	}

	return killed, errors.Join(failures...)
}

func (c *Client) alter(
	ctx context.Context,
	statement string,
	cred Credential,
) error {
	if err := validate(cred.Role); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	if c.config.Engine.MySQLFamily() {
		_, err := c.admin.ExecContext(
			ctx,
			fmt.Sprintf(
				statement, quoteIdentifier(c.config.Engine, cred.Role), "?",
			),
			cred.Password,
		)
		return err
	}
	if strings.ContainsRune(cred.Password, 0) {
		return errors.New("PostgreSQL passwords cannot contain a NUL byte")
	}

	_, err := c.admin.ExecContext(
		ctx,
		fmt.Sprintf(
			statement,
			quoteIdentifier(c.config.Engine, cred.Role),
			quoteLiteral(cred.Password),
		),
	)

	return err
}

func (c *Client) exec(
	ctx context.Context,
	statement string,
	role string,
) error {
	if err := validate(role); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	_, err := c.admin.ExecContext(
		ctx,
		fmt.Sprintf(statement, quoteIdentifier(c.config.Engine, role)),
	)

	return err
}

// validate is the guard that makes string-built DDL safe. Every role khaos
// creates is generated, so the constraint costs nothing and refuses anything
// that could carry a statement.
func validate(role string) error {
	if !safeIdentifier.MatchString(role) {
		return fmt.Errorf(errBadIdentifier, ErrBadIdentifier, role)
	}

	return nil
}

func quoteIdentifier(engine Engine, name string) string {
	if engine.MySQLFamily() {
		return "`" + name + "`"
	}

	return `"` + name + `"`
}

func quoteLiteral(value string) string {
	return pq.QuoteLiteral(value)
}

// dsn names no default database on the MySQL family, deliberately. khaos's
// probe asks only whether the engine ACCEPTS the credential, and a role with no
// grants can connect and run SELECT 1 with no schema selected — while naming a
// database it has no privilege on earns error 1044, which is khaos's own
// misconfiguration and not a statement about the credential. The alternative
// would be granting a khaos-minted role access to the operator's data, which is
// a larger blast radius for no measurement. PostgreSQL requires a database on
// every connection, so it keeps one.
func dsn(
	engine Engine,
	address, database string,
	cred Credential,
) string {
	if engine.MySQLFamily() {
		config := mysql.NewConfig()
		config.User = cred.Role
		config.Passwd = cred.Password
		config.Net = "tcp"
		config.Addr = address
		config.Timeout = dialTimeout
		config.ReadTimeout = queryTimeout
		config.WriteTimeout = queryTimeout
		config.InterpolateParams = true

		return config.FormatDSN()
	}

	target := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cred.Role, cred.Password),
		Host:     address,
		Path:     "/" + database,
		RawQuery: postgresOptions,
	}

	return target.String()
}
