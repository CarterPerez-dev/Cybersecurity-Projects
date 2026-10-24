// ©AngelaMos | 2026
// authority_cleanup_test.go

package cli

import (
	"io"
	"net"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/pki"
)

func TestAuthorityPartialStartupReleasesItsFirstListener(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	authority, err := pki.New(pki.Config{Host: "dependency.khaos.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	err = startAuthority(io.Discard, experiment.Experiment{
		Authority:       authority,
		AuthorityListen: "127.0.0.1:0",
		AuthorityTLS:    occupied.Addr().String(),
	})
	if err == nil {
		t.Fatal("occupied TLS listener unexpectedly bound")
	}
	if addr, err := authority.Addr(); err == nil {
		t.Fatalf("partial startup leaked the revocation listener at %s", addr)
	}
}
