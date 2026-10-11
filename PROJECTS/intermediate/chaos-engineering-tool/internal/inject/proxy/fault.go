// ©AngelaMos | 2026
// fault.go

package proxy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type Kind string

const (
	// PassThrough is not a fault. It is what the proxy does when nothing is
	// armed, and it has to be a real mode rather than the absence of one,
	// because the baseline is measured through the proxy and a baseline
	// measured through a different code path than the fault window proves
	// nothing about the difference between them.
	PassThrough Kind = "pass-through"

	// Hang accepts the connection and never answers. The research found this
	// and Reset to be the two shapes that most reliably separate a fail-closed
	// implementation from a fail-open one, because a refused connection and a
	// hung one hit different branches in almost every HTTP client, and the hang
	// branch is the one carrying the badly-chosen default timeout.
	Hang Kind = "hang"

	// Reset answers with RST rather than FIN. Reaching this needs SO_LINGER 0,
	// because an ordinary close with an empty receive queue sends FIN.
	Reset Kind = "reset"

	// EOF accepts and closes cleanly, which is what a stopped or killed
	// dependency looks like to its peer. Measured in research 06 section 6.1:
	// even SIGKILL produces an orderly FIN.
	EOF Kind = "eof"

	// Latency delays both directions. It is the graduated fault, for finding a
	// timeout that is too generous rather than one that is missing.
	Latency Kind = "latency"

	// Partial forwards a prefix of the dependency's answer and then closes, so
	// the target receives a truncated body with a valid status line. This is the
	// shape that finds a parser treating a short read as an empty-but-successful
	// response, which an outage-shaped fault never reaches.
	Partial Kind = "partial"

	// SlowClose forwards the whole answer and then holds the connection open.
	// A client that waits for close rather than for Content-Length stalls.
	SlowClose Kind = "slow-close"
)

const (
	errUnknownKind = "%w: %q (known proxy faults: %s)"
	errNeedDelay   = "%w: %s needs a positive delay"
	errNeedBytes   = "%w: %s needs a positive byte count"

	kindSep = ", "

	describePassThrough = "forward every byte between %s and its dependency, unchanged"
	describeHang        = "accept the target's connections to its dependency and never answer them"
	describeReset       = "answer the target's connections to its dependency with an immediate RST"
	describeEOF         = "accept the target's connections to its dependency and close them cleanly"
	describeLatency     = "delay every byte between %s and its dependency by %s in each direction"
	describePartial     = "forward only the first %d bytes of the dependency's answer, then close"
	describeSlowClose   = "forward the dependency's answer, then hold the connection open for %s"
)

var ErrUnknownKind = errors.New("no proxy fault is registered under that name")

var ErrFaultIncomplete = errors.New(
	"that proxy fault needs a parameter it was not given",
)

// Fault is the whole mutable state of an armed proxy. Reverting is assigning
// PassThrough over it, which is why the tier rolls back by freeing a struct
// rather than by undoing anything.
type Fault struct {
	Kind  Kind
	Delay time.Duration
	Bytes int
}

func Kinds() []string {
	kinds := []string{
		string(Hang), string(Reset), string(EOF),
		string(Latency), string(Partial), string(SlowClose),
	}
	slices.Sort(kinds)
	return kinds
}

func ParseKind(name string) (Kind, error) {
	kind := Kind(name)
	if kind == PassThrough || !slices.Contains(Kinds(), name) {
		return "", fmt.Errorf(
			errUnknownKind,
			ErrUnknownKind,
			name,
			strings.Join(Kinds(), kindSep),
		)
	}
	return kind, nil
}

// Validate refuses a fault that cannot express itself. A latency fault with no
// delay and a partial fault with no byte count are both indistinguishable from
// pass-through at runtime, which is a run that measures nothing and reports a
// clean survival.
func (f Fault) Validate() error {
	switch f.Kind {
	case Latency, SlowClose:
		if f.Delay <= 0 {
			return fmt.Errorf(errNeedDelay, ErrFaultIncomplete, f.Kind)
		}
	case Partial:
		if f.Bytes <= 0 {
			return fmt.Errorf(errNeedBytes, ErrFaultIncomplete, f.Kind)
		}
	case Hang, Reset, EOF:
	default:
		// The whitelist is the point. A switch that only names the parameterised
		// kinds accepts the zero Fault, a misspelling and a trailing space, all of
		// which forward every byte untouched while reporting as armed. An
		// unmarshalled journal payload reaches this with no other guard.
		return fmt.Errorf(
			errUnknownKind,
			ErrUnknownKind,
			f.Kind,
			strings.Join(Kinds(), kindSep),
		)
	}

	return nil
}

func (f Fault) Describe(target string) string {
	switch f.Kind {
	case Hang:
		return describeHang
	case Reset:
		return describeReset
	case EOF:
		return describeEOF
	case Latency:
		return fmt.Sprintf(describeLatency, target, f.Delay)
	case Partial:
		return fmt.Sprintf(describePartial, f.Bytes)
	case SlowClose:
		return fmt.Sprintf(describeSlowClose, f.Delay)
	default:
		return fmt.Sprintf(describePassThrough, target)
	}
}

// Severs reports whether the fault prevents the dependency from being reached at
// all. khaos confirms a severing fault by proving the dependency is unreachable
// THROUGH the proxy, and a forwarding fault by proving the proxy altered the
// stream, because those are different observations and one cannot stand in for
// the other.
func (f Fault) Severs() bool {
	return f.Kind == Hang || f.Kind == Reset || f.Kind == EOF
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
