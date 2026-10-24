// ©AngelaMos | 2026
// trap.go

package authz

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

type Kind string

const (
	// Deny is a DEFINITIVE answer about one credential, and the whole point of
	// the tier: the dependency said no, loudly and correctly, with full
	// reachability and a 403. No network fault can produce it, because every
	// network fault only ever makes a dependency unreachable.
	Deny Kind = "deny"

	Outage Kind = "outage"
)

const (
	errUnknownTrap = "%w: %q (known authorization faults: %s)"

	errNoCredential = "%w: a deny needs the credential it is a verdict about"

	describeDeny = "have khaos's own authorization dependency answer a definitive 403 for one credential the target is honouring, while it keeps answering 200 for every other credential; khaos stands in for that dependency for the length of the run, so it allows everything it has not been told to deny"

	describeOutage = "then stop answering at all, with a 503, which is the only answer a fallback policy may act on"
)

var ErrUnknownTrap = errors.New(
	"no authorization fault is registered under that name",
)

var ErrNoCredential = errors.New(
	"this authorization fault has no credential to be a verdict about",
)

// Trap is one authorization fault. The credential is a value khaos was given
// rather than one it minted, because the dependency is a stand-in for the
// operator's own and the credential belongs to their target.
type Trap struct {
	Kind       Kind   `json:"kind"`
	Credential string `json:"-"`

	// Inert is the negative control. Arm prepares everything and never tells
	// the dependency, so a confirmation that reads the dependency back through
	// its own surface MUST say no.
	Inert bool `json:"inert,omitempty"`
}

func Kinds() []string {
	return []string{string(Deny), string(Outage)}
}

// Injectable is the subset khaos registers as a fault an operator can ask for.
// An outage is NOT one of them: every other tier already makes a dependency
// unreachable, and this one exists for the answer that no network fault can
// produce. It is reachable only as the second phase of a deny, where its whole
// value is the comparison with the first.
func Injectable() []string {
	return []string{string(Deny)}
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

	if t.Kind == Deny && t.Credential == "" {
		return fmt.Errorf(errNoCredential, ErrNoCredential)
	}

	return nil
}

func (t Trap) Describe() string {
	if t.Kind == Outage {
		return describeOutage
	}

	return describeDeny
}
