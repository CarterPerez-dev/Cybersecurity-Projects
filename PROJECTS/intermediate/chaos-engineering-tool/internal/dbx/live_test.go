// ©AngelaMos | 2026
// live_test.go

package dbx

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"
)

// Every assertion in this file is a differential against a real engine. The
// mapping tests in dbx_test.go prove khaos reads a code correctly; only these
// prove the engines emit the codes khaos reads, and a self-consistent client
// agrees with its own mistake.
//
// Skipped unless the engine's address is in the environment, so `go test ./...`
// stays hermetic. scripts/credential.sh supplies them from the range.
//
//	KHAOS_DBX_LIVE_POSTGRES=host:port,database,adminrole,adminpassword
//	KHAOS_DBX_LIVE_MYSQL=...
//	KHAOS_DBX_LIVE_MARIADB=...
const (
	liveEnvPrefix = "KHAOS_DBX_LIVE_"
	liveFields    = 4
	liveTimeout   = 30 * time.Second
)

func liveConfig(t *testing.T, engine Engine) Config {
	t.Helper()

	name := liveEnvPrefix + strings.ToUpper(string(engine))

	raw := os.Getenv(name)
	if raw == "" {
		t.Skipf(
			"%s is not set, so there is no live %s to measure against",
			name,
			engine,
		)
	}

	parts := strings.Split(raw, ",")
	if len(parts) != liveFields {
		t.Fatalf(
			"%s has %d fields, want host:port,database,adminrole,adminpassword",
			name,
			len(parts),
		)
	}

	return Config{
		Engine:   engine,
		Address:  parts[0],
		Database: parts[1],
		Admin:    Credential{Role: parts[2], Password: parts[3]},
	}
}

func TestRotationIsNotRevocation(t *testing.T) {
	for _, engine := range []Engine{Postgres, MySQL, MariaDB} {
		t.Run(string(engine), func(t *testing.T) {
			config := liveConfig(t, engine)

			ctx, cancel := context.WithTimeout(
				context.Background(),
				liveTimeout,
			)
			defer cancel()

			client, role := liveRole(t, ctx, config)

			first := Credential{Role: role, Password: "khaos" + rand.Text()}
			second := Credential{Role: role, Password: "khaos" + rand.Text()}

			if err := client.Rotate(ctx, first); err != nil {
				t.Fatalf("setting the first password: %v", err)
			}

			wantAnswer(t, "the first password", client.Try(ctx, first), Served)

			wrong := Credential{Role: role, Password: "khaos" + rand.Text()}
			wantAnswer(
				t,
				"a password that was never correct",
				client.Try(ctx, wrong),
				Refused,
			)

			session, err := client.Hold(ctx, first)
			if err != nil {
				t.Fatalf("holding a session on the first password: %v", err)
			}
			defer func() { _ = session.Close() }()

			wantAnswer(
				t,
				"the held session before the rotation",
				session.Query(ctx),
				Served,
			)

			if err := client.Rotate(ctx, second); err != nil {
				t.Fatalf("rotating: %v", err)
			}

			wantAnswer(
				t,
				"THE FINDING: the held session after the rotation",
				session.Query(ctx),
				Served,
			)

			wantAnswer(
				t,
				"a NEW connection on the rotated-away password",
				client.Try(ctx, first),
				Refused,
			)

			wantAnswer(
				t,
				"a NEW connection on the rotated-to password",
				client.Try(ctx, second),
				Served,
			)

			killed, err := client.Terminate(ctx, role)
			if err != nil {
				t.Fatalf("terminating: %v", err)
			}
			if killed < 1 {
				t.Fatalf(
					"terminate closed %d sessions, want at least 1",
					killed,
				)
			}

			wantAnswer(
				t,
				"THE CONTRAST: the held session after termination",
				session.Query(ctx),
				Terminated,
			)
			wantClosedSession(t, session)
		})
	}
}

func wantClosedSession(t *testing.T, session *Session) {
	t.Helper()
	if err := session.Close(); err != nil {
		t.Fatalf("closing an already terminated session: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("repeating session close: %v", err)
	}
}

// TestAccountLockDoesNotRevokeALiveSession and the expiry test below are the
// two other controls an operator reaches for believing they revoke. Neither
// does, on any engine.
func TestAccountLockDoesNotRevokeALiveSession(t *testing.T) {
	for _, engine := range []Engine{Postgres, MySQL, MariaDB} {
		t.Run(string(engine), func(t *testing.T) {
			config := liveConfig(t, engine)

			ctx, cancel := context.WithTimeout(
				context.Background(),
				liveTimeout,
			)
			defer cancel()

			client, role := liveRole(t, ctx, config)

			cred := Credential{Role: role, Password: "khaos" + rand.Text()}
			if err := client.Rotate(ctx, cred); err != nil {
				t.Fatalf("setting the password: %v", err)
			}

			session, err := client.Hold(ctx, cred)
			if err != nil {
				t.Fatalf("holding a session: %v", err)
			}
			defer func() { _ = session.Close() }()

			if err := client.Lock(ctx, role); err != nil {
				t.Fatalf("locking: %v", err)
			}

			wantAnswer(
				t,
				"THE FINDING: the held session after the lock",
				session.Query(ctx),
				Served,
			)

			wantAnswer(
				t,
				"a NEW connection against a locked account",
				client.Try(ctx, cred),
				Locked,
			)

			// A locked account presented with a WRONG password reports the
			// wrong-password error on both MySQL-family engines, so lock state
			// is not observable without a valid credential. Measured, and it
			// bounds what khaos can claim.
			wrong := Credential{Role: role, Password: "khaos" + rand.Text()}
			locked := client.Try(ctx, wrong)
			if locked.Answer != Locked && locked.Answer != Refused {
				t.Errorf(
					"a locked account with a wrong password answered %q, want locked or refused",
					locked.Answer,
				)
			}

			if err := client.Unlock(ctx, role); err != nil {
				t.Fatalf("unlocking: %v", err)
			}

			wantAnswer(
				t,
				"a NEW connection after the unlock",
				client.Try(ctx, cred),
				Served,
			)
		})
	}
}

func TestExpiryDoesNotRevokeALiveSession(t *testing.T) {
	for _, engine := range []Engine{Postgres, MySQL, MariaDB} {
		t.Run(string(engine), func(t *testing.T) {
			config := liveConfig(t, engine)

			ctx, cancel := context.WithTimeout(
				context.Background(),
				liveTimeout,
			)
			defer cancel()

			client, role := liveRole(t, ctx, config)

			cred := Credential{Role: role, Password: "khaos" + rand.Text()}
			if err := client.Rotate(ctx, cred); err != nil {
				t.Fatalf("setting the password: %v", err)
			}

			session, err := client.Hold(ctx, cred)
			if err != nil {
				t.Fatalf("holding a session: %v", err)
			}
			defer func() { _ = session.Close() }()

			if err := client.Expire(ctx, role); err != nil {
				t.Fatalf("expiring: %v", err)
			}

			wantAnswer(
				t,
				"THE FINDING: the held session after the credential expired",
				session.Query(ctx),
				Served,
			)

			// Three engines, three answers, measured. PostgreSQL refuses an
			// expired credential with the same message it uses for a wrong
			// password. MySQL 8.4 refuses it at connect with 1862, because
			// khaos's client does not advertise the expired-password
			// capability. MariaDB 11.4 admits it and then refuses to execute
			// with 1820, which is a state a connect-only liveness probe reads
			// as healthy.
			want := map[Engine]Answer{
				Postgres: Refused,
				MySQL:    Expired,
				MariaDB:  MustReset,
			}[config.Engine]

			wantAnswer(
				t,
				"a NEW connection on an expired credential",
				client.Try(ctx, cred),
				want,
			)

			if err := client.Unexpire(ctx, cred); err != nil {
				t.Fatalf("restoring validity: %v", err)
			}

			wantAnswer(
				t,
				"a NEW connection after validity was restored",
				client.Try(ctx, cred),
				Served,
			)
		})
	}
}

// TestRotatingToTheSamePasswordChangesNothing is the inert control for the
// tier's confirmation oracle, and it needs no test-only flag: a rotation that
// changes nothing leaves the old password working, so a confirmation that
// requires the old password to be refused MUST say no.
func TestRotatingToTheSamePasswordChangesNothing(t *testing.T) {
	for _, engine := range []Engine{Postgres, MySQL, MariaDB} {
		t.Run(string(engine), func(t *testing.T) {
			config := liveConfig(t, engine)

			ctx, cancel := context.WithTimeout(
				context.Background(),
				liveTimeout,
			)
			defer cancel()

			client, role := liveRole(t, ctx, config)

			cred := Credential{Role: role, Password: "khaos" + rand.Text()}
			if err := client.Rotate(ctx, cred); err != nil {
				t.Fatalf("setting the password: %v", err)
			}

			if err := client.Rotate(ctx, cred); err != nil {
				t.Fatalf("rotating to the same password: %v", err)
			}

			wantAnswer(
				t,
				"the unchanged password after an inert rotation",
				client.Try(ctx, cred),
				Served,
			)
		})
	}
}

// TestVersionComesFromTheServer pins the rule that a tag is not a version.
func TestVersionComesFromTheServer(t *testing.T) {
	for _, engine := range []Engine{Postgres, MySQL, MariaDB} {
		t.Run(string(engine), func(t *testing.T) {
			config := liveConfig(t, engine)

			ctx, cancel := context.WithTimeout(
				context.Background(),
				liveTimeout,
			)
			defer cancel()

			client, err := Open(config)
			if err != nil {
				t.Fatalf("opening: %v", err)
			}
			defer func() { _ = client.Close() }()

			version, err := client.Version(ctx)
			if err != nil {
				t.Fatalf("reading the version: %v", err)
			}

			if version == "" {
				t.Fatal("the engine reported an empty version")
			}

			t.Logf("%s reports %q", engine, version)
		})
	}
}

// liveRole opens a client and mints a role that only exists for this test, so
// nothing belonging to the operator is ever mutated.
func liveRole(
	t *testing.T,
	ctx context.Context,
	config Config,
) (*Client, string) {
	t.Helper()

	client, err := Open(config)
	if err != nil {
		t.Fatalf("opening a client: %v", err)
	}

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("the engine at %s is not reachable: %v", config.Address, err)
	}

	role := "khaos_live_" + strings.ToLower(rand.Text()[:10])

	if err := client.CreateRole(
		ctx,
		Credential{Role: role, Password: "khaos" + rand.Text()},
	); err != nil {
		t.Fatalf("creating %s: %v", role, err)
	}

	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(
			context.Background(),
			liveTimeout,
		)
		defer cancel()

		if _, err := client.Terminate(cleanup, role); err != nil {
			t.Errorf("terminating %s during cleanup: %v", role, err)
		}
		if err := client.DropRole(cleanup, role); err != nil {
			t.Errorf("dropping %s: %v", role, err)
		}
		if err := client.Close(); err != nil {
			t.Errorf("closing the client: %v", err)
		}
	})

	return client, role
}

func wantAnswer(t *testing.T, what string, got Result, want Answer) {
	t.Helper()

	if got.Answer != want {
		t.Fatalf(
			"%s answered %q, want %q (detail: %s)",
			what,
			got.Answer,
			want,
			got.Detail,
		)
	}
}

func TestAwkwardPasswordsRoundTripAcrossSQLModes(t *testing.T) {
	for _, engine := range []Engine{Postgres, MySQL, MariaDB} {
		t.Run(string(engine), func(t *testing.T) {
			config := liveConfig(t, engine)
			ctx, cancel := context.WithTimeout(t.Context(), liveTimeout)
			defer cancel()
			client, role := liveRole(t, ctx, config)
			client.admin.SetMaxOpenConns(1)
			modes := []string{""}
			if engine.MySQLFamily() {
				modes = append(modes, "NO_BACKSLASH_ESCAPES")
			}
			for _, mode := range modes {
				if engine.MySQLFamily() {
					if _, err := client.admin.ExecContext(
						ctx, "SET SESSION sql_mode = ?", mode,
					); err != nil {
						t.Fatal(err)
					}
				}
				for _, password := range []string{`slash\value`, `quote'and\slash`, `trailing\`, "tab\tand\nnewline"} {
					cred := Credential{Role: role, Password: password}
					if err := client.Rotate(ctx, cred); err != nil {
						t.Fatalf("rotate in mode %q: %v", mode, err)
					}
					wantAnswer(
						t, "password round trip", client.Try(ctx, cred), Served,
					)
					wrong := Credential{
						Role: role, Password: password + "wrong",
					}
					wantAnswer(
						t,
						"wrong-password control",
						client.Try(ctx, wrong),
						Refused,
					)
				}
			}
		})
	}
}

// TestAnInertArmIsRefusedByTheConfirmation is the oracle's negative control,
// and it is the one assertion that cannot be satisfied by a confirmation gutted
// to `return true`. Arm prepares everything and never tells the engine, so the
// old password still works and a read-back MUST say no.
//
// Every kind is driven, because each one reads a different thing back and a
// control on one arm alibis the others.
func TestAnInertArmIsRefusedByTheConfirmation(t *testing.T) {
	for _, kind := range []Kind{Rotate, RotateTerminate, Lock, Expire} {
		t.Run(string(kind), func(t *testing.T) {
			config := liveConfig(t, Postgres)

			ctx, cancel := context.WithTimeout(
				context.Background(),
				liveTimeout,
			)
			defer cancel()

			tier := NewTier(Trap{
				Kind:   kind,
				Role:   MintedRole(),
				Minted: true,
				Inert:  true,
			})

			if err := tier.Open(ctx, config, Credential{}); err != nil {
				t.Fatalf("opening the tier: %v", err)
			}

			t.Cleanup(func() {
				closing, stop := context.WithTimeout(
					context.Background(),
					liveTimeout,
				)
				defer stop()

				if err := tier.Close(closing); err != nil {
					t.Errorf("closing the tier: %v", err)
				}
			})

			if err := tier.Arm(ctx); err != nil {
				t.Fatalf("arming inert: %v", err)
			}

			observable, confirmed, err := tier.Observe(ctx)
			if err != nil {
				t.Fatalf("observing: %v", err)
			}

			if confirmed {
				t.Fatalf(
					"an inert %s arm was CONFIRMED, so the oracle is not reading the engine back: %s",
					kind,
					observable,
				)
			}
		})
	}
}

// TestAnArmedFaultIsConfirmed is the other end of the same control: the same
// kinds, armed for real, must all confirm. Without this the inert control above
// is satisfied by an oracle that always says no.
func TestAnArmedFaultIsConfirmed(t *testing.T) {
	for _, kind := range []Kind{Rotate, RotateTerminate, Lock, Expire} {
		t.Run(string(kind), func(t *testing.T) {
			config := liveConfig(t, Postgres)

			ctx, cancel := context.WithTimeout(
				context.Background(),
				liveTimeout,
			)
			defer cancel()

			tier := NewTier(Trap{
				Kind:   kind,
				Role:   MintedRole(),
				Minted: true,
			})

			if err := tier.Open(ctx, config, Credential{}); err != nil {
				t.Fatalf("opening the tier: %v", err)
			}

			t.Cleanup(func() {
				closing, stop := context.WithTimeout(
					context.Background(),
					liveTimeout,
				)
				defer stop()

				if err := tier.Close(closing); err != nil {
					t.Errorf("closing the tier: %v", err)
				}
			})

			if err := tier.Arm(ctx); err != nil {
				t.Fatalf("arming: %v", err)
			}

			observable, confirmed, err := tier.Observe(ctx)
			if err != nil {
				t.Fatalf("observing: %v", err)
			}

			if !confirmed {
				t.Fatalf("an armed %s arm was not confirmed", kind)
			}

			if observable == "" {
				t.Fatal("confirmed with no observable, which is not evidence")
			}
		})
	}
}
