// ©AngelaMos | 2026
// tier.go

package dbx

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	rolePrefix    = "khaos_cred_"
	roleNonceLen  = 12
	passwordLabel = "khaos"

	errNotOpen = "%w: the credential tier was never opened, so khaos has no engine to ask"

	errAlreadyOpen = "%w: this credential tier is already open"

	errMintRole = "minting %s on the %s: %w"

	errNoOriginal = "%w: khaos has no original credential to restore for %s, so it will not guess one"

	confirmRotated = "a new connection on the rotated-away password is refused by the engine (%s) while the rotated-to password is accepted"

	confirmLocked = "a new connection presenting the correct password is refused because the account is locked (%s)"

	confirmExpired = "a new connection presenting the correct password is refused because the credential's validity has passed (%s)"

	detailNotOpen = "khaos's own credential tier is not open, so this probe measured nothing"
)

var ErrNotOpen = errors.New(
	"this credential tier has no open client",
)

var ErrAlreadyOpen = errors.New(
	"this credential tier is already open",
)

var ErrNoOriginal = errors.New(
	"khaos cannot restore a credential it never held",
)

// Tier is the per-run state of the credential tier: built by the experiment so
// the probe streams can close over it, and opened by the run, which is the only
// place that has a daemon to read an administrative credential out of.
//
// Every method is safe for the concurrent probe streams the engine fires.
type Tier struct {
	mu sync.Mutex

	trap   Trap
	client *Client

	session *Session

	// current is the credential that should work right now, original is what
	// the revert restores, and previous is what the fault rotated away from.
	current  Credential
	original Credential
	previous Credential

	version string
	armed   bool
}

func NewTier(trap Trap) *Tier {
	return &Tier{trap: trap}
}

func (t *Tier) Trap() Trap {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.trap
}

func (t *Tier) Engine() Engine {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client == nil {
		return ""
	}

	return t.client.Engine()
}

func (t *Tier) Version() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.version
}

func (t *Tier) Role() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.trap.Role
}

// Open dials the engine, records the version the SERVER reports, mints the role
// when the fault is one khaos owns, and holds a session that must work now so a
// later refusal is the fault rather than a credential that never worked.
//
// subject is the credential a pooled-service fault acts on, read out of the
// target's own environment by the caller; it is ignored for a minted role.
func (t *Tier) Open(
	ctx context.Context,
	config Config,
	subject Credential,
) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client != nil {
		return fmt.Errorf(errAlreadyOpen, ErrAlreadyOpen)
	}

	client, err := Open(config)
	if err != nil {
		return err
	}

	if err := client.Ping(ctx); err != nil {
		_ = client.Close()
		return err
	}

	version, err := client.Version(ctx)
	if err != nil {
		_ = client.Close()
		return err
	}

	t.client = client
	t.version = version

	if t.trap.Minted {
		minted := Credential{
			Role:     t.trap.Role,
			Password: newPassword(),
		}

		if err := client.CreateRole(ctx, minted); err != nil {
			_ = client.Close()
			t.client = nil

			return fmt.Errorf(errMintRole, minted.Role, config.Engine, err)
		}

		t.original = minted
	} else {
		if subject.Role == "" || subject.Password == "" {
			_ = client.Close()
			t.client = nil

			return fmt.Errorf(errNoOriginal, ErrNoOriginal, t.trap.Role)
		}

		t.original = subject
	}

	t.current = t.original

	session, err := client.Hold(ctx, t.current)
	if err != nil {
		return errors.Join(err, t.closeLocked(ctx))
	}

	t.session = session

	return nil
}

// MintedRole is the role name khaos will create for a fault it owns, generated
// rather than fixed so two runs cannot collide on one engine.
func MintedRole() string {
	return rolePrefix + strings.ToLower(rand.Text()[:roleNonceLen])
}

func newPassword() string {
	return passwordLabel + rand.Text()
}

// Arm performs the mutation. It prepares everything first and tells the engine
// only when the trap is not inert, so an inert arm leaves a state the
// confirmation has to reject.
func (t *Tier) Arm(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client == nil {
		return fmt.Errorf(errNotOpen, ErrNotOpen)
	}

	replacement := Credential{
		Role:     t.trap.Role,
		Password: newPassword(),
	}

	if t.trap.Inert {
		replacement = t.current
	}

	t.previous = t.current

	switch t.trap.Kind {
	case Rotate, PoolRotate, RotateTerminate:
		if err := t.client.Rotate(ctx, replacement); err != nil {
			return err
		}

		t.current = replacement

		if t.trap.Kind != RotateTerminate || t.trap.Inert {
			break
		}

		if _, err := t.client.Terminate(ctx, t.trap.Role); err != nil {
			return err
		}

	case Lock:
		if t.trap.Inert {
			break
		}
		if err := t.client.Lock(ctx, t.trap.Role); err != nil {
			return err
		}

	case Expire:
		if t.trap.Inert {
			break
		}
		if err := t.client.Expire(ctx, t.trap.Role); err != nil {
			return err
		}

	default:
		return t.trap.Validate()
	}

	t.armed = true

	return nil
}

// Observe is the two-sided confirmation. It never reads khaos's own armed
// state: ALTER ROLE succeeds when it changes nothing, which is the same class
// of answer as a pause the daemon acknowledges.
func (t *Tier) Observe(ctx context.Context) (string, bool, error) {
	t.mu.Lock()
	client := t.client
	trap := t.trap
	previous := t.previous
	current := t.current
	t.mu.Unlock()

	if client == nil {
		return "", false, fmt.Errorf(errNotOpen, ErrNotOpen)
	}

	if trap.RotatesPassword() {
		away := client.Try(ctx, previous)
		if away.Answer != Refused {
			return "", false, nil
		}

		if live := client.Try(ctx, current); live.Answer != Served {
			return "", false, nil
		}

		return fmt.Sprintf(confirmRotated, away.Detail), true, nil
	}

	answer := client.Try(ctx, current)

	switch trap.Kind {
	case Lock:
		if answer.Answer != Locked {
			return "", false, nil
		}

		return fmt.Sprintf(confirmLocked, answer.Detail), true, nil

	case Expire:
		// PostgreSQL refuses an expired credential with the string it also uses
		// for a wrong password, so the proof is that THIS password was served
		// during the baseline and is refused now.
		switch answer.Answer {
		case Expired, MustReset, Refused:
			return fmt.Sprintf(confirmExpired, answer.Detail), true, nil
		default:
			return "", false, nil
		}

	default:
		return "", false, nil
	}
}

// Disarm RESTORES and never removes, including for a role khaos minted. The
// recovery window measures the engine serving the credential again, so dropping
// the role here would make khaos's own cleanup read as a target that never came
// back — measured, and it reported a degraded recovery on a run where nothing
// about the engine had degraded. Removal belongs to Close, which runs after the
// recovery window, and to the cold-start revert, where there is no window to
// measure.
func (t *Tier) Disarm(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client == nil {
		return fmt.Errorf(errNotOpen, ErrNotOpen)
	}

	var failures []error

	if t.original.Password == "" {
		return fmt.Errorf(errNoOriginal, ErrNoOriginal, t.trap.Role)
	}

	switch t.trap.Kind {
	case Lock:
		if err := t.client.Unlock(ctx, t.trap.Role); err != nil {
			failures = append(failures, err)
		}
	case Expire:
		if err := t.client.Unexpire(ctx, t.original); err != nil {
			failures = append(failures, err)
		}
	default:
		if err := t.client.Rotate(ctx, t.original); err != nil {
			failures = append(failures, err)
		}
	}

	if len(failures) == 0 {
		t.current = t.original
		t.armed = false
	}

	return errors.Join(failures...)
}

// Current is the valid probe stream: a fresh connection presenting whatever
// credential should work right now.
func (t *Tier) Current(ctx context.Context) Result {
	t.mu.Lock()
	client := t.client
	cred := t.current
	t.mu.Unlock()

	if client == nil {
		return notOpen()
	}

	return client.Try(ctx, cred)
}

func (t *Tier) Wrong(ctx context.Context) Result {
	t.mu.Lock()
	client := t.client
	t.mu.Unlock()

	if client == nil {
		return notOpen()
	}

	return client.Try(ctx, t.wrong())
}

// wrong is separate so the freshness property has a control. The engine cannot
// tell khaos whether the password it refused was a new one, so the only place
// this is observable is here.
func (t *Tier) wrong() Credential {
	t.mu.Lock()
	defer t.mu.Unlock()

	return Credential{Role: t.trap.Role, Password: newPassword()}
}

// Held is the revoked stream: the session that authenticated before the fault
// and was never asked again.
func (t *Tier) Held(ctx context.Context) Result {
	t.mu.Lock()
	session := t.session
	t.mu.Unlock()

	if session == nil {
		return notOpen()
	}

	return session.Query(ctx)
}

func notOpen() Result {
	return Result{Answer: Misconfigured, Detail: detailNotOpen}
}

func (t *Tier) Close(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.closeLocked(ctx)
}

func (t *Tier) closeLocked(ctx context.Context) error {
	var failures []error

	if t.session != nil {
		if err := t.session.Close(); err != nil {
			failures = append(failures, err)
		}
		t.session = nil
	}

	if t.client == nil {
		return errors.Join(failures...)
	}

	// A minted role must not outlive the run even when the revert already ran,
	// because the lease exists to make that true without khaos's cooperation.
	if t.trap.Minted {
		if _, err := t.client.Terminate(ctx, t.trap.Role); err != nil {
			failures = append(failures, err)
		}
		if err := t.client.DropRole(ctx, t.trap.Role); err != nil {
			failures = append(failures, err)
		}
	}

	if err := t.client.Close(); err != nil {
		failures = append(failures, err)
	}

	t.client = nil

	return errors.Join(failures...)
}
