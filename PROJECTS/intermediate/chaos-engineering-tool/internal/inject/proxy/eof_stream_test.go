// ©AngelaMos | 2026
// eof_stream_test.go

package proxy

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestEOFAcceptsWritesBeyondTheOldDrainWindow(t *testing.T) {
	p := through(t)
	if err := p.Arm(Fault{Kind: EOF}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", p.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if _, err := io.WriteString(
			conn, "request body continues\n",
		); err != nil {
			t.Fatalf("clean EOF reset a continuing request: %v", err)
		}
		time.Sleep(150 * time.Millisecond)
	}
	var body [1]byte
	if _, err := conn.Read(body[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("clean close = %v, want EOF", err)
	}
}
