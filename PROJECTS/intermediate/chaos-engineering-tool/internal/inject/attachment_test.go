// ©AngelaMos | 2026
// attachment_test.go

package inject

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/network"
)

func TestAttachedNetworkMustMatchTheRecordedEndpoint(t *testing.T) {
	before := attachment{
		Network: "fixture", Aliases: []string{"api", "worker"},
		EndpointID: "original", MacAddress: "02:42:ac:16:00:08",
		Address: netip.MustParseAddr("172.22.0.8"), GwPriority: 5,
		DriverOpts: map[string]string{"test": "original"},
	}
	if before.settings().IPAMConfig != nil {
		t.Fatal("a dynamically allocated address became an explicit IP request")
	}
	original := func() *network.EndpointSettings {
		current := before.settings()
		current.EndpointID = before.EndpointID
		current.IPAddress = before.Address
		return current
	}
	for _, test := range []struct {
		field  string
		change func(*network.EndpointSettings)
	}{
		{"aliases", func(e *network.EndpointSettings) { e.Aliases = []string{"other"} }},
		{"IPv4 address", func(e *network.EndpointSettings) { e.IPAddress = netip.MustParseAddr("172.22.0.9") }},
		{"gateway priority", func(e *network.EndpointSettings) { e.GwPriority = 0 }},
		{"driver options", func(e *network.EndpointSettings) { e.DriverOpts = nil }},
		{"MAC address", func(e *network.EndpointSettings) { e.MacAddress = network.HardwareAddr{} }},
	} {
		t.Run(test.field, func(t *testing.T) {
			current := original()
			test.change(current)
			err := before.verify(current)
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("endpoint drift was not named: %v", err)
			}
		})
	}
	current := original()
	current.Aliases = []string{"worker", "api"}
	if err := before.verify(current); err != nil {
		t.Fatalf("matching endpoint refused: %v", err)
	}
	current.EndpointID = "recreated"
	if err := current.MacAddress.UnmarshalText(
		[]byte("02:42:ac:16:00:09"),
	); err != nil {
		t.Fatal(err)
	}
	if err := before.verify(current); err != nil {
		t.Fatalf("allocated MAC on a recreated endpoint refused: %v", err)
	}
}
