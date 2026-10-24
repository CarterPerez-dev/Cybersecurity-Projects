// ©AngelaMos | 2026
// dbx_test.go

package dbx

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

const (
	testAddress  = "10.244.244.9:5432"
	testDatabase = "appdb"
)

// TestValidateRefusesAnythingThatCouldCarryAStatement is the control for the
// guard that makes string-built DDL safe. No engine accepts a parameter in
// place of a role name or a password, so the statement is interpolated and the
// input is constrained; this is the input set that must be refused.
func TestValidateRefusesAnythingThatCouldCarryAStatement(t *testing.T) {
	refused := []string{
		"",
		"robert'); DROP TABLE students;--",
		"khaos cred",
		"khaos-cred",
		"KhaosCred",
		"1khaos",
		`khaos"cred`,
		"khaos`cred",
		"khaos;cred",
		"khaos\ncred",
		"khaos%cred",
		strings.Repeat("k", 64),
	}

	for _, role := range refused {
		if err := validate(role); !errors.Is(err, ErrBadIdentifier) {
			t.Errorf(
				"validate(%q) = %v, want ErrBadIdentifier",
				role,
				err,
			)
		}
	}

	accepted := []string{
		"appuser",
		"khaos_cred_9f2c",
		"k",
		strings.Repeat("k", 63),
	}

	for _, role := range accepted {
		if err := validate(role); err != nil {
			t.Errorf("validate(%q) = %v, want nil", role, err)
		}
	}
}

func TestQuoteLiteralDoublesSingleQuotes(t *testing.T) {
	cases := map[string]string{
		"plain":       "'plain'",
		"it's":        "'it''s'",
		"''":          "''''''",
		"a'b'c":       "'a''b''c'",
		"back\\slash": " E'back\\\\slash'",
	}

	for in, want := range cases {
		if got := quoteLiteral(in); got != want {
			t.Errorf("quoteLiteral(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDSNCarriesTheCredentialAndNoTLS pins both halves of the transport
// decision: the credential reaches the driver intact even when it contains
// characters a URL would otherwise eat, and neither engine is asked for TLS.
func TestDSNCarriesTheCredentialAndNoTLS(t *testing.T) {
	awkward := Credential{Role: "appuser", Password: "p@ss:w/rd?&=#"}

	postgres := dsn(Postgres, testAddress, testDatabase, awkward)

	if !strings.Contains(postgres, "sslmode=disable") {
		t.Errorf("postgres dsn does not disable sslmode: %s", postgres)
	}
	if strings.Contains(postgres, awkward.Password) {
		t.Errorf("postgres dsn carries an unescaped password: %s", postgres)
	}

	parsed, err := pq.ParseURL(postgres)
	if err != nil {
		t.Fatalf("lib/pq cannot parse the dsn khaos built: %v", err)
	}
	if !strings.Contains(parsed, "password='p@ss:w/rd?&=#'") {
		t.Errorf("round-tripped postgres dsn lost the password: %s", parsed)
	}

	for _, engine := range []Engine{MySQL, MariaDB} {
		raw := dsn(engine, testAddress, testDatabase, awkward)

		config, err := mysql.ParseDSN(raw)
		if err != nil {
			t.Fatalf("%s: go-sql-driver cannot parse %q: %v", engine, raw, err)
		}
		if config.Passwd != awkward.Password {
			t.Errorf(
				"%s: dsn round-tripped the password as %q, want %q",
				engine,
				config.Passwd,
				awkward.Password,
			)
		}
		if config.TLS != nil {
			t.Errorf(
				"%s: dsn asks for TLS, which no range engine serves",
				engine,
			)
		}
		if !config.AllowNativePasswords {
			t.Errorf(
				"%s: native passwords are disabled, which MariaDB 11.4 needs",
				engine,
			)
		}
		if config.AllowCleartextPasswords {
			t.Errorf(
				"%s: cleartext passwords are enabled, and the RSA exchange is what khaos relies on",
				engine,
			)
		}
	}
}

func TestParseEngine(t *testing.T) {
	for _, name := range []string{"postgres", "MySQL", " mariadb "} {
		if _, err := ParseEngine(name); err != nil {
			t.Errorf("ParseEngine(%q) = %v, want nil", name, err)
		}
	}

	for _, name := range []string{"", "sqlite", "postgresql", "mysql8"} {
		if _, err := ParseEngine(name); !errors.Is(err, ErrUnknownEngine) {
			t.Errorf("ParseEngine(%q) = %v, want ErrUnknownEngine", name, err)
		}
	}
}

func TestOpenRefusesAnIncompleteClient(t *testing.T) {
	cases := []struct {
		name   string
		config Config
		want   error
	}{
		{
			name:   "no engine",
			config: Config{Address: testAddress},
			want:   ErrUnknownEngine,
		},
		{
			name:   "no address",
			config: Config{Engine: Postgres},
			want:   ErrIncomplete,
		},
		{
			name: "no administrative credential",
			config: Config{
				Engine:  Postgres,
				Address: testAddress,
			},
			want: ErrIncomplete,
		},
		{
			name: "an administrative role with no password",
			config: Config{
				Engine:  Postgres,
				Address: testAddress,
				Admin:   Credential{Role: "postgres"},
			},
			want: ErrIncomplete,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Open(test.config); !errors.Is(err, test.want) {
				t.Errorf("Open() = %v, want %v", err, test.want)
			}
		})
	}
}

// TestClassifyReadsTheCodeAndQuotesTheMessage pins the per-engine mapping. The
// live differential in live_test.go is what proves the engines actually emit
// these codes; this is the mapping, including the one case khaos must refuse to
// resolve.
func TestClassifyReadsTheCodeAndQuotesTheMessage(t *testing.T) {
	cases := []struct {
		name   string
		engine Engine
		err    error
		want   Answer
	}{
		{
			name:   "postgres refuses a password",
			engine: Postgres,
			err: &pq.Error{
				Code:    "28P01",
				Message: `password authentication failed for user "appuser"`,
			},
			want: Refused,
		},
		{
			name:   "postgres refuses a login",
			engine: Postgres,
			err: &pq.Error{
				Code:    "28000",
				Message: `role "appuser" is not permitted to log in`,
			},
			want: Locked,
		},
		{
			name:   "postgres closed the session",
			engine: Postgres,
			err: &pq.Error{
				Code:    "57P01",
				Message: "terminating connection due to administrator command",
			},
			want: Terminated,
		},
		{
			name:   "postgres has no such database",
			engine: Postgres,
			err: &pq.Error{
				Code:    "3D000",
				Message: `database "nope" does not exist`,
			},
			want: Misconfigured,
		},
		{
			name:   "mysql denies access",
			engine: MySQL,
			err: &mysql.MySQLError{
				Number:  1045,
				Message: "Access denied for user 'appuser'@'10.0.0.2'",
			},
			want: Refused,
		},
		{
			name:   "mysql reports a locked account",
			engine: MySQL,
			err: &mysql.MySQLError{
				Number:  3118,
				Message: "Access denied for user 'appuser'. Account is locked.",
			},
			want: Locked,
		},
		{
			name:   "mariadb reports a locked account",
			engine: MariaDB,
			err: &mysql.MySQLError{
				Number:  4151,
				Message: "Access denied, this account is locked",
			},
			want: Locked,
		},
		{
			name:   "the mysql family demands a reset",
			engine: MySQL,
			err: &mysql.MySQLError{
				Number:  1820,
				Message: "You must reset your password using ALTER USER",
			},
			want: MustReset,
		},
		{
			name:   "a dead socket is not a statement about the credential",
			engine: MySQL,
			err:    mysql.ErrInvalidConn,
			want:   Unreachable,
		},
		{
			name:   "nothing went wrong",
			engine: Postgres,
			err:    nil,
			want:   Served,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result := classify(test.engine, test.err)

			if result.Answer != test.want {
				t.Fatalf(
					"classify(%s, %v) = %q, want %q",
					test.engine,
					test.err,
					result.Answer,
					test.want,
				)
			}

			if test.err == nil {
				return
			}

			var (
				pgErr *pq.Error
				myErr *mysql.MySQLError
			)

			switch {
			case errors.As(test.err, &pgErr):
				if !strings.Contains(result.Detail, pgErr.Message) {
					t.Errorf(
						"detail %q does not quote the engine's own message %q",
						result.Detail,
						pgErr.Message,
					)
				}
			case errors.As(test.err, &myErr):
				if !strings.Contains(result.Detail, myErr.Message) {
					t.Errorf(
						"detail %q does not quote the engine's own message %q",
						result.Detail,
						myErr.Message,
					)
				}
			}
		})
	}
}

// TestPostgresRefusalRefusesToNameACause is the control for the one collision
// khaos must not resolve. A wrong password, a credential whose validity has
// passed and a role that does not exist all produce 28P01, so a detail that
// named any single cause would be confidently wrong a third of the time.
func TestPostgresRefusalRefusesToNameACause(t *testing.T) {
	result := classify(Postgres, &pq.Error{
		Code:    "28P01",
		Message: `password authentication failed for user "appuser"`,
	})

	for _, phrase := range []string{
		"validity has passed",
		"does not exist",
		"cannot resolve",
	} {
		if !strings.Contains(result.Detail, phrase) {
			t.Errorf(
				"a 28P01 detail must say %q, got %q",
				phrase,
				result.Detail,
			)
		}
	}
}

func TestDecidedExcludesWhatTheEngineNeverSaid(t *testing.T) {
	decided := []Answer{Served, Refused, Locked, MustReset, Terminated}
	silent := []Answer{Unknown, Unreachable, Misconfigured, ""}

	for _, answer := range decided {
		if !(Result{Answer: answer}).Decided() {
			t.Errorf("%q should count as the engine deciding", answer)
		}
	}

	for _, answer := range silent {
		if (Result{Answer: answer}).Decided() {
			t.Errorf("%q is not the engine deciding anything", answer)
		}
	}
}

// TestWrongMintsAFreshPasswordPerSample is the control for the negative
// control. A fixed invalid credential keeps a target's decision cache warm, so
// the catalogue census requires freshness and this is where it is observable:
// the engine cannot tell khaos whether the password it refused was new.
func TestWrongMintsAFreshPasswordPerSample(t *testing.T) {
	tier := NewTier(Trap{Kind: Rotate, Role: "khaos_cred_abcdef", Minted: true})

	const rounds = 8

	seen := map[string]bool{}

	for range rounds {
		cred := tier.wrong()

		if cred.Role != "khaos_cred_abcdef" {
			t.Fatalf(
				"the control changed the ROLE to %q; it must vary the password of the role under test, or it is measuring a different account",
				cred.Role,
			)
		}

		seen[cred.Password] = true
	}

	if len(seen) != rounds {
		t.Fatalf(
			"%d calls produced %d distinct passwords; a repeated control credential can be answered from a cache",
			rounds,
			len(seen),
		)
	}
}

// TestACredentialCannotBeSerialisedWithItsSecret is the structural control for
// the rule that khaos journals where a credential is read from and never the
// credential. Enforcing it in the type beats enforcing it at every call site.
func TestACredentialCannotBeSerialisedWithItsSecret(t *testing.T) {
	encoded, err := json.Marshal(Credential{
		Role:     "appuser",
		Password: "hunter2-should-never-appear",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if strings.Contains(string(encoded), "hunter2") {
		t.Fatalf(
			"a Credential serialised its password: %s",
			encoded,
		)
	}

	if !strings.Contains(string(encoded), "appuser") {
		t.Fatalf(
			"a Credential dropped the role as well, which the journal does need: %s",
			encoded,
		)
	}
}
