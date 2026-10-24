// ©AngelaMos | 2026
// race_test.go

package proxy

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

const (
	raceAttempts = 2000
	raceWindow   = 150 * time.Millisecond
)

// An armed fault must arrive as ITSELF. Storing the fault and advancing the
// generation as two steps let a handler read the new fault with the old
// generation, which track refused, so hold closed the client instead of holding
// it: an armed hang came out as a reset. Measured before the fix at 116 of 2000
// attempts, and hang and reset are the two faults the design doc exists to keep
// distinguishable because they hit different branches in almost every client.
func TestAnArmedHangNeverArrivesAsAReset(t *testing.T) {
	p := through(t)

	resets := 0

	for range raceAttempts {
		p.Disarm()

		conn, err := net.DialTimeout(network, p.Addr(), probeWait)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}

		if err := p.Arm(Fault{Kind: Hang}); err != nil {
			t.Fatalf("arm: %v", err)
		}

		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(raceWindow))

		_, readErr := conn.Read(make([]byte, 64))
		_ = conn.Close()

		if errors.Is(readErr, syscall.ECONNRESET) {
			resets++
		}
	}

	if resets > 0 {
		t.Fatalf(
			"%d of %d armed hangs arrived as a reset. A handler read the new fault with a "+
				"stale generation, so the connection was refused and closed rather than held, and "+
				"the operator measured the other fault in the catalogue",
			resets,
			raceAttempts,
		)
	}
}

// The mirror of the above, for the property the generation counter exists to
// provide: a connection accepted just before a revert must not be left held by
// nothing once the revert has run.
func TestNoConnectionOutlivesTheRevertThatShouldHaveFreedIt(t *testing.T) {
	p := through(t)

	for attempt := range raceAttempts {
		if err := p.Arm(Fault{Kind: Hang}); err != nil {
			t.Fatalf("arm: %v", err)
		}

		conn, err := net.DialTimeout(network, p.Addr(), probeWait)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}

		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		p.Disarm()

		_ = conn.SetReadDeadline(time.Now().Add(raceWindow))
		_, readErr := conn.Read(make([]byte, 64))
		_ = conn.Close()

		var timeout net.Error
		if errors.As(readErr, &timeout) && timeout.Timeout() {
			t.Fatalf(
				"attempt %d: a connection was still held %s after the revert. The ceiling "+
					"is %s against a five second recovery window, so the target reads as one that "+
					"never came back and khaos manufactures that verdict itself",
				attempt,
				raceWindow,
				hangCeiling,
			)
		}
	}
}
