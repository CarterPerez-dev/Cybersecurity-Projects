// ©AngelaMos | 2026
// trap.go

package dbx

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

type Kind string

const (
	// Rotate is the headline: change the password and leave every live session
	// alone, which is what an operator believes revokes access.
	Rotate Kind = "rotate"

	// RotateTerminate is the contrast that makes the pair worth running. One
	// statement more, and the same fault inverts.
	RotateTerminate Kind = "rotate_terminate"

	Lock   Kind = "lock"
	Expire Kind = "expire"

	// PoolRotate acts on a role the TARGET is using, so the finding is a
	// property of the target's connection pool rather than of the engine.
	PoolRotate Kind = "pool_rotate"
)

const (
	errUnknownTrap = "%w: %q (known credential faults: %s)"
	errNoRole      = "%w: a credential fault needs the role it acts on"

	describeRotate = "rotate %s's password at the %s it authenticates against, and leave every established session alone"

	describeRotateTerminate = "rotate %s's password at the %s it authenticates against and then terminate its sessions, which is the only control of the three that reaches a live connection"

	describeLock = "lock %s's account at the %s it authenticates against, which is what an incident runbook reaches for when a credential leaks"

	describeExpire = "put %s's credential validity in the past at the %s it authenticates against"

	describePoolRotate = "rotate the password %s's own connection pool authenticated with, without telling %s"
)

var ErrUnknownTrap = errors.New(
	"no credential fault is registered under that name",
)

var ErrNoRole = errors.New(
	"this credential fault has no role to act on",
)

// Trap is one credential fault. Minted records whether khaos created the role,
// which decides whether the revert restores a password or drops the role
// outright.
type Trap struct {
	Kind   Kind   `json:"kind"`
	Role   string `json:"role"`
	Minted bool   `json:"minted"`

	// Inert is the negative control. Arm still prepares everything, including
	// the replacement credential, and simply never tells the engine, so a
	// confirmation that reads the engine back MUST say no.
	Inert bool `json:"inert,omitempty"`
}

func Kinds() []string {
	return []string{
		string(Expire),
		string(Lock),
		string(PoolRotate),
		string(Rotate),
		string(RotateTerminate),
	}
}

func (t Trap) Validate() error {
	if !slices.Contains(Kinds(), string(t.Kind)) {
		return fmt.Errorf(
			errUnknownTrap,
			ErrUnknownTrap,
			t.Kind,
			strings.Join(Kinds(), ", "),
		)
	}

	if t.Role == "" {
		return fmt.Errorf(errNoRole, ErrNoRole)
	}

	return validate(t.Role)
}

// Describe names the engine as well as the role, because the same fault means
// something different against an engine that re-authenticates and none of the
// three do.
func (t Trap) Describe(target string, engine Engine) string {
	switch t.Kind {
	case Rotate:
		return fmt.Sprintf(describeRotate, t.Role, engine)
	case RotateTerminate:
		return fmt.Sprintf(describeRotateTerminate, t.Role, engine)
	case Lock:
		return fmt.Sprintf(describeLock, t.Role, engine)
	case Expire:
		return fmt.Sprintf(describeExpire, t.Role, engine)
	case PoolRotate:
		return fmt.Sprintf(describePoolRotate, target, target)
	default:
		return string(t.Kind)
	}
}

// RotatesPassword reports whether this fault replaces the credential, which is
// what the two-sided confirmation reads back.
func (t Trap) RotatesPassword() bool {
	switch t.Kind {
	case Rotate, RotateTerminate, PoolRotate:
		return true
	default:
		return false
	}
}
