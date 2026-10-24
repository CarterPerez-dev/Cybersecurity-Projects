// ©AngelaMos | 2026
// delivery_test.go

package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestDeliveryCountsOnlyTheWatchedTarget(t *testing.T) {
	p := through(t)
	if err := p.WatchSources([]string{"127.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Arm(Fault{Kind: EOF}); err != nil {
		t.Fatal(err)
	}
	_, confirmed, err := p.Observe(t.Context(), EOF)
	if err != nil || !confirmed {
		t.Fatalf("confirmation: %v, %v", confirmed, err)
	}
	if count, _ := p.FaultConnections(); count != 0 {
		t.Fatal("confirmation was attributed to the target")
	}
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")},
		Timeout:   time.Second,
	}
	conn, err := dialer.DialContext(t.Context(), "tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(conn)
	_ = conn.Close()
	if count, _ := p.FaultConnections(); count != 1 {
		t.Fatalf("target count = %d, want 1", count)
	}
	p.Disarm()
	if count, _ := p.FaultConnections(); count != 0 {
		t.Fatal("fault delivery survived disarm")
	}
	if count, _ := p.TargetConnections(); count != 1 {
		t.Fatal("baseline counter was reset with the fault")
	}
}
