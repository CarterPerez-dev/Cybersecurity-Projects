package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestCloseDoesNotDeadlockAgainstAWedgedDependency(t *testing.T) {
	wedged, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = wedged.Close() }()

	go func() {
		for {
			conn, err := wedged.Accept()
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	p, err := Open("127.0.0.1:0", wedged.Addr().String(), "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	client, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	time.Sleep(300 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- p.Close() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(
			"Close() did not return within 5s against a dependency that accepts and never " +
				"answers. khaos run defers this Close, so the whole command hangs with a fault's " +
				"listener still bound, and the operator reaches for kill -9",
		)
	}
}
