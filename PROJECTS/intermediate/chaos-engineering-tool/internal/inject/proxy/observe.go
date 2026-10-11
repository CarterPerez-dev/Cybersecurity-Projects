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

	// Slack on the measured magnitude. The thresholds are lower bounds with no
	// tolerance otherwise, and on a host that also serves real traffic CPU
	// contention routinely shaves a few percent off a sleep. Measured: under
	// 64-goroutine load a 250ms slow-close refused 6 of 25 times, voiding a
	// quarter of its runs.
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

// Observe confirms the armed fault by measuring the dependency on TWO paths and
// requiring them to disagree: once directly, bypassing the proxy, and once
// through it. It never consults an internal flag or a branch counter, because a
// counter incremented by the dispatcher records which code path was chosen rather
// than what reached the wire.
//
// The differential is what makes the oracle sound. An absolute threshold cannot
// tell khaos's fault from a slow dependency: measured, a dependency answering in
// four seconds confirmed a `hang` that was not applied at all, with the target
// served in full, and a dependency taking one second confirmed a `latency` whose
// delay had been removed. The direct path is the control, and the design contract
// calls for read-back rather than an API return value.
// armedFor resolves the fault this call is allowed to confirm, or says why the
// proxy cannot be asked at all.
//
// Closed is checked FIRST. Close reverts to pass-through, so reading the fault
// before this would report "nothing armed" for a proxy that is gone, and a dial
// to a listener that no longer exists is ECONNREFUSED, which a reset oracle
// must not accept as its own observable.
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

	// The control first. If the dependency cannot be reached without the proxy in
	// the way, nothing seen through the proxy can be attributed to khaos's fault,
	// and saying so voids the run instead of crediting khaos for someone else's
	// outage.
	//
	// The test is the absence of BYTES, not the presence of an error: a complete
	// answer always ends in one, because that is what the peer closing looks
	// like to a reader.
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
		// ECONNREFUSED is deliberately NOT accepted. Dialling a listener that is
		// gone produces exactly that, so accepting it let a CLOSED proxy confirm
		// its own fault.
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
		// Both halves. A byte count that merely MATCHES the budget is also what
		// pass-through delivers when the answer happens to be that long, so the
		// control's answer has to be longer than what came through.
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
		// PassThrough is the absence of a fault and has no observable to
		// confirm, so it reaches the unconfirmed return below.
	}

	return "", false, nil
}

func slack(delay time.Duration) time.Duration {
	return delay * observeSlackNumerator / observeSlackDenominator
}

// measure sends one probe to an address and records when the first byte arrived,
// how much arrived in total, and when the peer closed.
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

	if _, err := io.WriteString(conn, probePayload); err != nil {
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

// isReset accepts ECONNRESET and deliberately NOT ECONNREFUSED. Dialling a
// listener that is gone produces refused, and accepting it let a CLOSED proxy
// confirm the fault it was holding when it died.
func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}

func isTimeout(err error) bool {
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}
