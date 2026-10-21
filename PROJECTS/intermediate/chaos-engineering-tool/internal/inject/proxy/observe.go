// ©AngelaMos | 2026
// observe.go

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
)

const (
	observeGrace  = 2 * time.Second
	observeBuffer = 64 * 1024

	observeDelayFactor = 4

	// Slack on the measured magnitude: the thresholds are lower bounds, and CPU
	// contention routinely shaves a few percent off a sleep.
	observeSlackNumerator   = 9
	observeSlackDenominator = 10

	errNoControl = "%w: %v"
)

var ErrNothingArmed = errors.New(
	"nothing is armed on the fault proxy, so there is nothing to confirm",
)

var ErrDependencyUnreachable = errors.New(
	"khaos cannot reach the dependency directly, so it cannot attribute what it sees through the proxy to its own fault",
)

var ErrFaultNotObserved = errors.New(
	"the armed fault did not produce its own observable",
)

// reading is what khaos's confirmation probe measured on one path.
type reading struct {
	firstByte time.Duration
	total     int64
	closed    time.Duration
}

// armedFor checks closed FIRST, because close reverts to pass-through: reading
// the fault before that would report "nothing armed" for a proxy that is gone,
// and a dial to a dead listener is ECONNREFUSED, which reset must not accept.
func (p *Proxy) armedFor(expected Kind) (Fault, error) {
	select {
	case <-p.closed:
		return Fault{}, ErrClosed
	default:
	}

	fault := p.Fault()

	if fault.Kind == PassThrough {
		return Fault{}, ErrNothingArmed
	}

	if expected != "" && fault.Kind != expected {
		return Fault{}, fmt.Errorf(
			errWrongArmed,
			ErrFaultNotObserved,
			fault.Kind,
			expected,
		)
	}

	return fault, nil
}

// Observe measures the dependency on TWO paths and requires them to disagree:
// once directly, bypassing the proxy, and once through it. The differential is
// what separates khaos's fault from a merely slow dependency.
func (p *Proxy) Observe(
	ctx context.Context,
	expected Kind,
) (string, bool, error) {
	fault, err := p.armedFor(expected)
	if err != nil {
		return "", false, err
	}

	p.probes.Add(1)

	budget := observeGrace + fault.Delay*observeDelayFactor

	// The control first: if the dependency is unreachable without the proxy,
	// nothing seen through it is khaos's fault. The test is the absence of
	// BYTES, not an error, because a complete answer always ends in one.
	direct, directErr := p.measure(ctx, p.upstream, observeGrace)
	if direct.total == 0 {
		return "", false, fmt.Errorf(
			errNoControl,
			ErrDependencyUnreachable,
			directErr,
		)
	}

	through, throughErr := p.measure(ctx, p.Addr(), budget)

	switch fault.Kind {
	case Hang:
		// The dependency answered on the control path and answered nothing here.
		if through.total == 0 && isTimeout(throughErr) {
			return observedHang, true, nil
		}
	case Reset:
		// ECONNREFUSED is deliberately NOT accepted; see isReset.
		if isReset(throughErr) {
			return observedReset, true, nil
		}
	case EOF:
		if through.total == 0 && errors.Is(throughErr, io.EOF) {
			return observedEOF, true, nil
		}
	case Latency:
		added := through.firstByte - direct.firstByte
		if added >= slack(fault.Delay) {
			return sprintf(
				observedLatency,
				added.Round(time.Millisecond),
			), true, nil
		}
	case Partial:
		// Both halves: a count that merely MATCHES the budget is what
		// pass-through delivers when the answer happens to be that long.
		if through.total == int64(fault.Bytes) && direct.total > through.total {
			return sprintf(
				observedPartial,
				through.total,
				direct.total,
			), true, nil
		}
	case SlowClose:
		held := through.closed - through.firstByte
		reference := direct.closed - direct.firstByte
		if held-reference >= slack(fault.Delay) {
			return sprintf(
				observedSlowClose,
				held.Round(time.Millisecond),
			), true, nil
		}

	default:
		// PassThrough has no observable, so it falls to the unconfirmed return.
	}

	return "", false, nil
}

func slack(delay time.Duration) time.Duration {
	return delay * observeSlackNumerator / observeSlackDenominator
}

// measure records when the first byte arrived, how much arrived, and when the
// peer closed.
func (p *Proxy) measure(
	ctx context.Context,
	addr string,
	budget time.Duration,
) (reading, error) {
	dialer := net.Dialer{Timeout: budget}

	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return reading{}, err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(budget)); err != nil {
		return reading{}, err
	}

	started := time.Now()

	if _, err := io.WriteString(conn, p.probe); err != nil {
		return reading{}, err
	}

	out := reading{}
	buffer := make([]byte, observeBuffer)

	for {
		read, err := conn.Read(buffer)
		if read > 0 {
			if out.total == 0 {
				out.firstByte = time.Since(started)
			}
			out.total += int64(read)
			out.closed = time.Since(started)
		}
		if err != nil {
			out.closed = time.Since(started)
			return out, err
		}
	}
}

// isReset accepts ECONNRESET and NOT ECONNREFUSED: a gone listener produces
// refused, which would let a CLOSED proxy confirm the fault it died holding.
func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}

func isTimeout(err error) bool {
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}
