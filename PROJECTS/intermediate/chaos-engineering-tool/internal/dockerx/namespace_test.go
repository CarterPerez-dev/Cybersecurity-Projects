// ©AngelaMos | 2026
// namespace_test.go

package dockerx

import (
	"testing"

	"github.com/moby/moby/api/types/container"
)

func TestNamespacePeersRequireRunningUnconsentingSharers(t *testing.T) {
	owner := container.Summary{ID: acceptableID, Names: []string{"/owner"}}
	for _, reference := range []string{"owner", acceptableID, acceptableID[:12]} {
		for _, consent := range []string{"", "false", "true"} {
			for _, running := range []bool{false, true} {
				peer := container.Summary{
					ID: peerID, Names: []string{"/sidecar"},
					Labels: map[string]string{LabelConsent: consent},
					State:  container.StateExited,
				}
				if running {
					peer.State = container.StateRunning
				}
				peer.HostConfig.NetworkMode = NetworkModeContainerPfx + reference
				got := namespacePeersOf([]container.Summary{owner, peer})
				want := running && consent != ConsentValue
				if (len(got[acceptableID]) == 1) != want {
					t.Fatalf(
						"reference=%s consent=%s running=%v: peers=%v",
						reference, consent, running, got,
					)
				}
			}
		}
	}
}
