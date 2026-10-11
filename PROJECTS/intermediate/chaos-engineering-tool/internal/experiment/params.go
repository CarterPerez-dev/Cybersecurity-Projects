// ©AngelaMos | 2026
// params.go

package experiment

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	ParamTarget       = "target"
	ParamURL          = "url"
	ParamToken        = "token"
	ParamInvalidToken = "invalid-token"

	errUndeclared  = "%w: --%s (this experiment accepts: %s)"
	errNoParams    = "%w: --%s (this experiment takes no parameters)"
	errMissing     = "this experiment needs --%s, %s"
	errNotDuration = "--%s was given as %q, which is not a duration; write it like 2s, 500ms or 1m30s"
	errNotCount    = "--%s was given as %q, which is not a whole number"
	errNotPositive = "--%s was given as %q, and a fault with no magnitude is indistinguishable from no fault at all"
	errBelowFloor  = "--%s was given as %s, and khaos needs at least %s: %s"
)

var ErrUndeclaredParam = errors.New(
	"that is not a parameter of this experiment",
)

// Param declares one input an experiment needs. The declaration is the single
// place the CLI registers flags from, the range fills defaults into, and Bind
// validates against, so an experiment can neither be handed an input it never
// asked for nor be given one it silently ignores.
type Param struct {
	Name     string
	Usage    string
	Required bool
	Default  string
}

// Params is the bound, validated parameter set for one build. Get records every
// read so Build can reject a builder reaching for a name nobody declared, which
// is otherwise an empty string with no symptom.
type Params struct {
	values map[string]string
	read   map[string]bool
	stray  map[string]bool
}

func Bind(declared []Param, supplied map[string]string) (*Params, error) {
	names := make([]string, 0, len(declared))
	for _, param := range declared {
		names = append(names, param.Name)
	}

	for _, name := range sorted(supplied) {
		if slices.Contains(names, name) {
			continue
		}
		if len(names) == 0 {
			return nil, fmt.Errorf(errNoParams, ErrUndeclaredParam, name)
		}
		return nil, fmt.Errorf(
			errUndeclared,
			ErrUndeclaredParam,
			name,
			strings.Join(names, nameSep),
		)
	}

	bound := &Params{
		values: make(map[string]string, len(declared)),
		read:   map[string]bool{},
		stray:  map[string]bool{},
	}

	// Presence decides whether the default applies, not emptiness. An operator who
	// explicitly asked for an empty value has asked for something meaningful: an
	// empty credential is sent as no Authorization header, which is the
	// unauthenticated negative control. Overwriting it with the default makes that
	// control impossible to express.
	for _, param := range declared {
		value, given := supplied[param.Name]
		if !given {
			value = param.Default
		}
		if value == "" && param.Required {
			return nil, fmt.Errorf(errMissing, param.Name, param.Usage)
		}
		bound.values[param.Name] = value
	}

	return bound, nil
}

func (p *Params) Get(name string) string {
	value, declared := p.values[name]
	if !declared {
		p.stray[name] = true
		return ""
	}

	p.read[name] = true

	return value
}

func (p *Params) strayReads() []string {
	return sorted(p.stray)
}

func (p *Params) unread() []string {
	out := []string{}
	for name := range p.values {
		if !p.read[name] {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func sorted[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}

// Duration and Count parse a declared parameter and refuse a value the fault
// cannot use. The refusal names the flag and what was typed, because a fault
// whose magnitude failed to parse would otherwise fall back to zero, and a zero
// delay or a zero byte budget is indistinguishable from no fault at all.
func (p *Params) Duration(name string) (time.Duration, error) {
	raw := p.Get(name)

	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf(errNotDuration, name, raw)
	}

	if value <= 0 {
		return 0, fmt.Errorf(errNotPositive, name, raw)
	}

	return value, nil
}

// AtLeast is Duration with a floor, for the magnitudes where a value the target
// is ALLOWED to tolerate is not a smaller fault but a different and false
// finding.
//
// Measured: `identity.claim_expired --delay 30s` against a textbook verifier
// that allows 60 seconds of clock skew, which RFC 7519 section 4.1.4 explicitly
// permits, produced `deviated / PERMITTED`, defect, exit 2. khaos confirmed the
// trap honestly — the token really was expired — and then reported a correct
// target as broken, because an expiry inside the skew allowance is one a correct
// verifier is supposed to accept.
//
// The refusal names the floor AND why it exists, because an operator's first
// instinct on seeing it will be that khaos is being fussy about a magnitude.
func (p *Params) AtLeast(
	name string,
	floor time.Duration,
	because string,
) (time.Duration, error) {
	value, err := p.Duration(name)
	if err != nil {
		return 0, err
	}

	if value < floor {
		return 0, fmt.Errorf(errBelowFloor, name, value, floor, because)
	}

	return value, nil
}

func (p *Params) Count(name string) (int, error) {
	raw := p.Get(name)

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf(errNotCount, name, raw)
	}

	if value <= 0 {
		return 0, fmt.Errorf(errNotPositive, name, raw)
	}

	return value, nil
}
