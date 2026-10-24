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
	// A real mode rather than the absence of one, because the baseline is
	// measured through the proxy as well.
	PassThrough Kind = "pass-through"

	// Accepts and never answers. A refused connection and a hung one hit
	// different client branches, and the hang branch carries the bad default.
	Hang Kind = "hang"

	// RST rather than FIN, which needs SO_LINGER 0.
	Reset Kind = "reset"

	// Closes cleanly, as a stopped dependency does; even SIGKILL sends FIN.
	EOF Kind = "eof"

	// Delays both directions, for a timeout too generous rather than missing.
	Latency Kind = "latency"

	// Forwards a prefix then closes, which finds a parser treating a short read
	// as empty-but-successful.
	Partial Kind = "partial"

	// Forwards everything, then holds the connection open, stalling a client
	// that waits for close rather than for Content-Length.
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

// Fault is the whole mutable state of an armed proxy, so reverting is
// assigning PassThrough over it rather than undoing anything.
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

// Validate refuses a fault that cannot express itself: a latency with no delay
// or a partial with no byte count is pass-through that reports as armed.
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
		// The whitelist is the point: naming only the parameterised kinds
		// accepts the zero Fault and a misspelling, and an unmarshalled journal
		// payload reaches here with no other guard.
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

// Severs separates the two confirmations: unreachability THROUGH the proxy, or
// an altered stream. Neither observation can stand in for the other.
func (f Fault) Severs() bool {
	return f.Kind == Hang || f.Kind == Reset || f.Kind == EOF
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
