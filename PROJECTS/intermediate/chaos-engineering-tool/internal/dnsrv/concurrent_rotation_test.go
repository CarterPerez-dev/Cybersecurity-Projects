// ©AngelaMos | 2026
// concurrent_rotation_test.go

package dnsrv

import (
	"sync"
	"testing"
)

func TestRotationAndLiveQueriesShareConsistentZoneState(t *testing.T) {
	resolver, client := startResolver(t)
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 200 {
			if err := resolver.Arm(trapFor(AddressRotated)); err != nil {
				t.Error(err)
				return
			}
			resolver.Disarm()
		}
	})
	workers.Go(func() {
		for range 200 {
			zone := resolver.Zone()
			if address := zone[testHost]; address != testAddress &&
				address != testRotatedAddress {
				t.Errorf("unexpected zone address %q", address)
			}
			_ = client.ask(testHost, udpNet)
			_ = client.ask(testHost, tcpNet)
		}
	})
	workers.Wait()
	if resolver.Zone()[testHost] != testAddress {
		t.Fatal("disarm lost the original zone")
	}
}
